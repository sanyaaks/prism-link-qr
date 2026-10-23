import {
  DANGEROUS_SCHEMES,
  DEFAULT_OPTIONS,
  MAX_INPUT_LENGTH,
  RULE_NAME,
  SEVERITY_WEIGHT,
  URL_SHORTENERS,
  WEB_SCHEMES,
} from './config';
import {
  describeChars,
  describeIPv4,
  diffMiddle,
  editDistance,
  foldConfusables,
  isIPv4,
  isSameOrSubdomain,
  registrableDomain,
  skeleton,
  toUnicodeHost,
} from './domain';
import type {
  Analysis,
  AnalysisResult,
  AnalyzerOptions,
  Check,
  Finding,
  HostType,
  ReadsLike,
  RuleId,
  Segment,
  Severity,
  UrlParts,
  Verdict,
} from './types';

// ---------------------------------------------------------------------------
// Input preparation
// ---------------------------------------------------------------------------

const SCHEME_RE = /^([a-zA-Z][a-zA-Z0-9+.-]*):/;
// Zero-width, bidi-control and other invisible formatting characters.
const INVISIBLE_RE = /[­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;
// eslint-disable-next-line no-control-regex
const CONTROL_RE = /[\u0000-\u001F\u007F]/g;

interface PreparedInput {
  normalized: string;
  assumedScheme: boolean;
  invisible: string[];
  hasBackslash: boolean;
}

function hasExplicitScheme(s: string): boolean {
  const m = SCHEME_RE.exec(s);
  if (!m) return false;
  const rest = s.slice(m[0].length);
  // "campus.example:8443/x" or "localhost:3000" is host:port, not a scheme.
  const looksLikePort = /^\d+(?:[/?#\\]|$)/.test(rest);
  if (looksLikePort && (m[1].includes('.') || m[1].toLowerCase() === 'localhost')) return false;
  return true;
}

export function prepareInput(input: string): PreparedInput {
  const trimmed = input.trim();
  const invisible = [...(trimmed.match(INVISIBLE_RE) ?? []), ...(trimmed.match(CONTROL_RE) ?? [])];
  let normalized = trimmed;
  let assumedScheme = false;
  if (normalized.startsWith('//')) {
    normalized = 'https:' + normalized;
    assumedScheme = true;
  } else if (!hasExplicitScheme(normalized)) {
    normalized = 'https://' + normalized;
    assumedScheme = true;
  }
  return { normalized, assumedScheme, invisible, hasBackslash: trimmed.includes('\\') };
}

/** Host exactly as typed in the authority (before WHATWG normalization). */
function rawHostOf(s: string): string | null {
  const m = /^[a-zA-Z][a-zA-Z0-9+.-]*:[/\\]*/.exec(s);
  if (!m) return null;
  const rest = s.slice(m[0].length);
  const end = rest.search(/[/?#\\]/);
  let authority = end === -1 ? rest : rest.slice(0, end);
  const at = authority.lastIndexOf('@');
  if (at !== -1) authority = authority.slice(at + 1);
  if (authority.startsWith('[')) {
    const close = authority.indexOf(']');
    return close === -1 ? authority : authority.slice(0, close + 1);
  }
  return authority.replace(/:\d*$/, '').toLowerCase();
}

function safeDecode(s: string): string {
  try {
    return decodeURIComponent(s);
  } catch {
    return s;
  }
}

function normalizeReferences(refs: string[]): string[] {
  const out = new Set<string>();
  for (const r of refs) {
    const cleaned = r
      .trim()
      .toLowerCase()
      .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
      .replace(/[/?#].*$/, '')
      .replace(/\.$/, '');
    if (cleaned.includes('.') && !/\s/.test(cleaned)) out.add(cleaned);
  }
  return [...out];
}

// ---------------------------------------------------------------------------
// Rule context
// ---------------------------------------------------------------------------

interface RuleContext {
  input: string;
  prep: PreparedInput;
  url: URL;
  parts: UrlParts;
  rawHost: string | null;
  refs: string[];
}

interface RuleOutput {
  findings: Finding[];
  readsLike?: ReadsLike;
  matchedReference?: string;
}

function finding(ruleId: RuleId, severity: Severity, title: string, explanation: string, evidence?: string): Finding {
  return { ruleId, ruleName: RULE_NAME[ruleId], severity, title, explanation, evidence };
}

function tail(parts: UrlParts): string {
  const t = parts.path + parts.query + parts.fragment;
  return t === '/' ? '' : t;
}

function prefixSegs(parts: UrlParts): Segment[] {
  return [{ text: parts.scheme + '://', tone: 'muted' }];
}

function portSeg(parts: UrlParts): Segment[] {
  return parts.port ? [{ text: ':' + parts.port, tone: 'plain' }] : [];
}

function tailSegs(parts: UrlParts): Segment[] {
  const t = tail(parts);
  return t ? [{ text: t, tone: 'plain' }] : [];
}

// ---------------------------------------------------------------------------
// Rules (max 10)
// ---------------------------------------------------------------------------

type Rule = (ctx: RuleContext) => RuleOutput;

const userinfoRule: Rule = ({ parts, url }) => {
  if (!parts.username && !parts.hasPassword) return { findings: [] };
  const user = parts.username;
  const looksLikeDomain = /\.[a-z]{2,}/i.test(user);
  const userinfoText = safeDecode(url.username) + (url.password ? ':' + '•'.repeat(4) : '');
  const f = looksLikeDomain
    ? finding(
        'PR-01',
        'critical',
        `“${user}” is a username, not the destination`,
        `Everything before the “@” in a link's authority is treated as login credentials and ignored for routing. The link reads like it goes to ${user}, but the browser connects to ${parts.displayHost}.`,
        `${userinfoText}@${parts.displayHost}`,
      )
    : finding(
        'PR-01',
        'high',
        'Link embeds credentials before an “@”',
        `This link carries userinfo (“${userinfoText}”) before the host. Legitimate links almost never include this; it is commonly used to push the real host out of view.`,
        `${userinfoText}@${parts.displayHost}`,
      );
  const readsLike: ReadsLike | undefined = looksLikeDomain
    ? {
        ruleId: 'PR-01',
        appears: user,
        appearsLabel: 'Reads like',
        actual: parts.displayHost,
        actualLabel: 'Actually goes to',
        segments: [
          ...prefixSegs(parts),
          { text: userinfoText + '@', tone: 'deceptive' },
          { text: parts.displayHost, tone: 'actual' },
          ...portSeg(parts),
          ...tailSegs(parts),
        ],
        note: 'The text before “@” is discarded as a username. Only the part after it is the destination.',
      }
    : undefined;
  return { findings: [f], readsLike };
};

const schemeRule: Rule = ({ parts }) => {
  if (WEB_SCHEMES.includes(parts.scheme)) return { findings: [] };
  if (DANGEROUS_SCHEMES.includes(parts.scheme)) {
    return {
      findings: [
        finding(
          'PR-02',
          'critical',
          `“${parts.scheme}:” link can run or embed content directly`,
          `A ${parts.scheme}: link does not point to a website. Opening it can execute script, render attacker-supplied content, or read local resources, so no hostname can be verified.`,
          parts.href.length > 80 ? parts.href.slice(0, 80) + '…' : parts.href,
        ),
      ],
    };
  }
  return {
    findings: [
      finding(
        'PR-02',
        'medium',
        `Opens a “${parts.scheme}:” handler, not a web page`,
        `This link hands off to another application (${parts.scheme}:). It may be legitimate, but it skips the usual browser address bar and PRISM cannot screen a web destination for it.`,
        parts.href,
      ),
    ],
  };
};

const ipHostRule: Rule = ({ parts, rawHost }) => {
  if (parts.hostType !== 'ipv4' && parts.hostType !== 'ipv6') return { findings: [] };
  const raw = (rawHost ?? '').replace(/\.$/, '');
  const obfuscated = parts.hostType === 'ipv4' && raw !== '' && raw !== parts.hostname;
  const range = describeIPv4(parts.hostname);
  const rangeNote = range ? ` It resolves to ${range}.` : '';
  if (obfuscated) {
    return {
      findings: [
        finding(
          'PR-03',
          'high',
          `Encoded IP address “${raw}” hides the destination`,
          `The host is written as an encoded number that browsers silently convert to the IP address ${parts.hostname}. This format is used almost exclusively to disguise where a link goes.${rangeNote}`,
          `${raw} → ${parts.hostname}`,
        ),
      ],
      readsLike: {
        ruleId: 'PR-03',
        appears: raw,
        appearsLabel: 'Written as',
        actual: parts.hostname,
        actualLabel: 'Browser decodes to',
        segments: [...prefixSegs(parts), { text: raw, tone: 'deceptive' }, ...portSeg(parts), ...tailSegs(parts)],
        note: 'Decimal, hex and octal host numbers are legal in browsers but unreadable to people.',
      },
    };
  }
  return {
    findings: [
      finding(
        'PR-03',
        'medium',
        'Host is a raw IP address',
        `The link points at ${parts.hostname} directly instead of a named domain, so there is no domain owner to recognise or verify.${rangeNote}`,
        parts.hostname,
      ),
    ],
  };
};

/** The configured shortener service a hostname belongs to, if any. Single source for PR-04. */
export function matchShortener(hostname: string): string | null {
  return URL_SHORTENERS.find((s) => isSameOrSubdomain(hostname, s)) ?? null;
}

const shortenerRule: Rule = ({ parts }) => {
  const match = matchShortener(parts.hostname);
  if (!match) return { findings: [] };
  return {
    findings: [
      finding(
        'PR-04',
        'medium',
        `${match} is a URL shortener`,
        `Short links redirect somewhere else. PRISM screens locally and does not follow redirects, so the final destination is unknown. Expand the link with a trusted preview tool before opening.`,
        parts.hostname,
      ),
    ],
  };
};

const lookalikeRule: Rule = ({ parts, refs }) => {
  if (parts.hostType !== 'domain') return { findings: [] };
  if (refs.some((ref) => isSameOrSubdomain(parts.hostname, ref))) return { findings: [] };
  const regDisplay = registrableDomain(parts.displayHost);
  const regAscii = parts.registrable;
  for (const ref of refs) {
    const homoglyph = skeleton(regDisplay) === skeleton(ref);
    const distance = editDistance(foldConfusables(regDisplay), ref);
    const typo = !homoglyph && distance === 1 && ref.length >= 8;
    if (!homoglyph && !typo) continue;

    const d = diffMiddle(regDisplay, ref);
    const swap = d.a || d.b ? `${d.a ? describeChars(d.a) : 'nothing'} in place of ${d.b ? describeChars(d.b) : 'nothing'}` : '';
    const sub = parts.displayHost.slice(0, parts.displayHost.length - regDisplay.length);
    const readsLike: ReadsLike = {
      ruleId: 'PR-05',
      appears: sub + ref,
      appearsLabel: 'Reads like',
      actual: parts.displayHost,
      actualLabel: 'Actually goes to',
      segments: [
        ...prefixSegs(parts),
        ...(sub ? [{ text: sub, tone: 'actual' as const }] : []),
        { text: d.prefix, tone: 'actual' },
        { text: d.a || '·', tone: 'deceptive' },
        { text: d.suffix, tone: 'actual' },
        ...portSeg(parts),
        ...tailSegs(parts),
      ],
      note:
        regDisplay !== regAscii
          ? `The browser actually requests ${parts.hostname} (punycode).`
          : `Compared against reference domain ${ref}.`,
    };
    const f = homoglyph
      ? finding(
          'PR-05',
          'high',
          `${regDisplay} imitates reference domain ${ref}`,
          `${regDisplay} uses ${swap}, which renders almost identically to ${ref} at a glance. It is a different domain with a different owner.`,
          `${regAscii} vs ${ref}`,
        )
      : finding(
          'PR-05',
          'medium',
          `${regDisplay} is one edit away from ${ref}`,
          `${regDisplay} differs from the reference domain ${ref} by a single character (${swap}). This may be a typo-squat; it is not the reference domain.`,
          `${regAscii} vs ${ref}`,
        );
    return { findings: [f], readsLike, matchedReference: ref };
  }
  return { findings: [] };
};

const brandInHostRule: Rule = ({ parts, refs }) => {
  if (parts.hostType !== 'domain') return { findings: [] };
  if (refs.some((ref) => isSameOrSubdomain(parts.hostname, ref))) return { findings: [] };
  const hostLabels = parts.hostname.split('.');
  for (const ref of refs) {
    const refLabels = ref.split('.');
    // Full reference domain embedded as a subdomain: campus.example.evil.example
    for (let i = 0; i + refLabels.length < hostLabels.length; i++) {
      if (refLabels.every((l, k) => hostLabels[i + k] === l)) {
        const deceptive = hostLabels.slice(0, i + refLabels.length).join('.') + '.';
        const owner = parts.registrable;
        return {
          findings: [
            finding(
              'PR-06',
              'high',
              `${ref} is only a subdomain of ${owner}`,
              `The host starts with “${ref}”, but domains are read right-to-left: this host belongs to ${owner}, which can name its subdomains anything.`,
              parts.hostname,
            ),
          ],
          readsLike: {
            ruleId: 'PR-06',
            appears: ref,
            appearsLabel: 'Reads like',
            actual: owner,
            actualLabel: 'Actually controlled by',
            segments: [
              ...prefixSegs(parts),
              { text: deceptive, tone: 'deceptive' },
              { text: parts.hostname.slice(deceptive.length), tone: 'actual' },
              ...portSeg(parts),
              ...tailSegs(parts),
            ],
            note: 'The registrable domain is the last labels of the host; everything to its left is chosen by its owner.',
          },
          matchedReference: ref,
        };
      }
    }
    // Reference name reused as a hyphenated token or under another TLD: campus-login.example
    const brand = refLabels[0];
    const regLabel = parts.registrable.split('.')[0];
    if (brand.length >= 4 && regLabel.split('-').includes(brand)) {
      return {
        findings: [
          finding(
            'PR-06',
            'medium',
            `Uses the name “${brand}” outside ${ref}`,
            `${parts.registrable} contains the reference name “${brand}” but is not ${ref}. It may be unrelated or may be borrowing the name; verify who owns it.`,
            parts.registrable,
          ),
        ],
        matchedReference: ref,
      };
    }
  }
  return { findings: [] };
};

const punycodeRule: Rule = ({ parts }) => {
  if (!parts.hostname.split('.').some((l) => l.startsWith('xn--'))) return { findings: [] };
  const nonAscii = Array.from(parts.displayHost).filter((c) => (c.codePointAt(0) ?? 0) > 0x7e);
  const unique = [...new Set(nonAscii)];
  const segments: Segment[] = [...prefixSegs(parts)];
  for (const ch of Array.from(parts.displayHost)) {
    const tone = (ch.codePointAt(0) ?? 0) > 0x7e ? 'deceptive' : 'actual';
    const last = segments[segments.length - 1];
    if (last && last.tone === tone) last.text += ch;
    else segments.push({ text: ch, tone });
  }
  segments.push(...portSeg(parts), ...tailSegs(parts));
  return {
    findings: [
      finding(
        'PR-07',
        'medium',
        'Host contains non-ASCII characters',
        `The host is displayed as “${parts.displayHost}” but is registered as ${parts.hostname}. Characters such as ${describeChars(unique.slice(0, 3).join(''))} can imitate Latin letters.`,
        `${parts.displayHost} = ${parts.hostname}`,
      ),
    ],
    readsLike: {
      ruleId: 'PR-07',
      appears: parts.displayHost,
      appearsLabel: 'Displays as',
      actual: parts.hostname,
      actualLabel: 'Registered as',
      segments,
      note: 'Highlighted characters are outside basic Latin.',
    },
  };
};

const httpRule: Rule = ({ parts }) => {
  if (parts.scheme !== 'http') return { findings: [] };
  return {
    findings: [
      finding(
        'PR-08',
        'low',
        'Connection is not encrypted (http://)',
        'Anything sent to or from this page can be read or modified by networks in between. Login and payment pages should always use https://.',
        'http://' + parts.displayHost,
      ),
    ],
  };
};

const brandInPathRule: Rule = ({ parts, refs }) => {
  if (!parts.hostname || refs.some((ref) => isSameOrSubdomain(parts.hostname, ref))) return { findings: [] };
  const rest = safeDecode(parts.path + parts.query + parts.fragment).toLowerCase();
  const ref = refs.find((r) => rest.includes(r));
  if (!ref) return { findings: [] };
  const raw = safeDecode(tail(parts));
  const idx = raw.toLowerCase().indexOf(ref);
  return {
    findings: [
      finding(
        'PR-09',
        'medium',
        `“${ref}” appears only in the path`,
        `The reference domain ${ref} is written after the host, where it is just text. The page is served by ${parts.displayHost}.`,
        raw.length > 90 ? raw.slice(0, 90) + '…' : raw,
      ),
    ],
    readsLike:
      idx === -1
        ? undefined
        : {
            ruleId: 'PR-09',
            appears: ref,
            appearsLabel: 'Mentions',
            actual: parts.displayHost,
            actualLabel: 'Actually goes to',
            segments: [
              ...prefixSegs(parts),
              { text: parts.displayHost, tone: 'actual' },
              ...portSeg(parts),
              { text: raw.slice(0, idx), tone: 'plain' },
              { text: raw.slice(idx, idx + ref.length), tone: 'deceptive' },
              { text: raw.slice(idx + ref.length), tone: 'plain' },
            ],
            note: 'Only the host decides where a link goes. Paths and query strings are free text.',
          },
    matchedReference: ref,
  };
};

const ambiguityRule: Rule = ({ prep, parts }) => {
  const out: Finding[] = [];
  if (prep.invisible.length) {
    out.push(
      finding(
        'PR-10',
        'medium',
        'Contains invisible or control characters',
        `The input includes ${prep.invisible.length} hidden character(s) (${describeChars(
          [...new Set(prep.invisible)].join(''),
        )}). These can make a link display differently from how it is parsed.`,
      ),
    );
  }
  if (prep.hasBackslash) {
    out.push(
      finding(
        'PR-10',
        'medium',
        'Backslashes are interpreted inconsistently',
        'Browsers treat “\\” as “/” in web links, but other parsers and people may not, so different tools can disagree about the host. PRISM uses the browser interpretation shown above.',
      ),
    );
  }
  if (prep.assumedScheme) {
    out.push(
      finding(
        'PR-10',
        'low',
        'No scheme given; https:// was assumed',
        'Without an explicit scheme, apps and QR scanners may open this differently. PRISM analyzed it as an https:// link.',
        prep.normalized,
      ),
    );
  }
  if (parts.hostType === 'single-label') {
    out.push(
      finding(
        'PR-10',
        'low',
        `“${parts.hostname}” is not a fully-qualified domain`,
        'A host without a dot resolves differently depending on the local network, so its owner cannot be determined.',
        parts.hostname,
      ),
    );
  }
  return { findings: out };
};

const RULE_PIPELINE: Rule[] = [
  userinfoRule,
  schemeRule,
  ipHostRule,
  shortenerRule,
  lookalikeRule,
  brandInHostRule,
  punycodeRule,
  httpRule,
  brandInPathRule,
  ambiguityRule,
];

// Which reads-like explanation wins when several apply.
const READS_LIKE_PRIORITY: RuleId[] = ['PR-01', 'PR-05', 'PR-06', 'PR-03', 'PR-07', 'PR-09'];

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low'];

export function computeVerdict(findings: Finding[], checks: Check[]): { verdict: Verdict; score: number } {
  const score = Math.min(
    100,
    findings.reduce((sum, f) => sum + SEVERITY_WEIGHT[f.severity], 0),
  );
  const severe = findings.some((f) => f.severity === 'critical' || f.severity === 'high');
  if (severe || score >= 60) return { verdict: 'Suspicious', score };
  // Safe needs positive evidence, not just the absence of findings.
  if (score === 0 && checks.every((c) => c.passed)) return { verdict: 'Safe', score };
  return { verdict: 'Review', score };
}

function buildChecks(parts: UrlParts, findings: Finding[]): Check[] {
  const fired = (id: RuleId) => findings.some((f) => f.ruleId === id);
  return [
    { label: 'Parsed by the standard (WHATWG) URL parser', passed: true },
    { label: 'Uses encrypted https://', passed: parts.scheme === 'https' },
    { label: 'Host is a named, fully-qualified domain', passed: parts.hostType === 'domain' },
    { label: 'No text hidden before an “@”', passed: !fired('PR-01') },
    { label: 'Destination is visible (not a shortener)', passed: !fired('PR-04') },
    {
      label: 'No imitation of a reference domain',
      passed: !fired('PR-05') && !fired('PR-06') && !fired('PR-09'),
    },
    { label: 'Plain ASCII host, unambiguous input', passed: !fired('PR-07') && !fired('PR-10') },
  ];
}

function summarize(verdict: Verdict, findings: Finding[]): string {
  const top = findings[0];
  if (verdict === 'Safe') {
    return 'No risk signals from PRISM’s local rules. This is a screening result, not a guarantee the site is trustworthy.';
  }
  if (verdict === 'Suspicious') {
    const extra = findings.length > 1 ? ` plus ${findings.length - 1} more signal${findings.length > 2 ? 's' : ''}` : '';
    return `${top.title}${extra}. Do not open this link without independent verification.`;
  }
  return `${top ? top.title : 'Some checks did not pass'}. Not clearly malicious, but verify before opening.`;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

function hostTypeOf(hostname: string): HostType {
  if (!hostname) return 'none';
  if (hostname.startsWith('[')) return 'ipv6';
  if (isIPv4(hostname)) return 'ipv4';
  if (!hostname.includes('.')) return 'single-label';
  return 'domain';
}

export function analyze(rawInput: string, options: AnalyzerOptions = DEFAULT_OPTIONS): AnalysisResult {
  const input = typeof rawInput === 'string' ? rawInput : '';
  const trimmed = input.trim();
  if (!trimmed) {
    return { ok: false, input, error: 'Nothing to analyze yet.', hint: 'Paste a link, or try one of the samples.' };
  }
  if (trimmed.length > MAX_INPUT_LENGTH) {
    return {
      ok: false,
      input,
      error: `That input is ${trimmed.length.toLocaleString()} characters long.`,
      hint: `PRISM screens links up to ${MAX_INPUT_LENGTH.toLocaleString()} characters. Unusually long links are themselves a warning sign.`,
    };
  }

  const prep = prepareInput(trimmed);
  let url: URL;
  try {
    url = new URL(prep.normalized);
  } catch {
    const hint = /\s/.test(trimmed)
      ? 'Links cannot contain spaces in the host. Check that you pasted a single, complete link.'
      : /^[a-z][a-z0-9+.-]*:\/\/?$/i.test(trimmed)
        ? 'The link has a scheme but no host.'
        : 'The standard URL parser rejected it. Check for stray characters or a broken host or port.';
    return { ok: false, input, error: 'PRISM couldn’t parse this as a URL.', hint };
  }

  const scheme = url.protocol.replace(/:$/, '').toLowerCase();
  const hostname = url.hostname.toLowerCase().replace(/\.$/, '');
  const hostType = hostTypeOf(hostname);

  if (prep.assumedScheme && hostType === 'single-label' && hostname !== 'localhost') {
    return {
      ok: false,
      input,
      error: 'That doesn’t look like a link.',
      hint: 'Include a scheme (https://) or a full domain such as campus.example.',
    };
  }
  if (WEB_SCHEMES.includes(scheme) && !hostname) {
    return { ok: false, input, error: 'This link has no host.', hint: 'A web link needs a host after “://”.' };
  }
  // Some browsers' parsers are lenient (e.g. Chrome accepts "exa mple.com" as "exa%20mple.com").
  // Enforce the same hostname grammar everywhere so verdicts do not depend on the engine.
  if (
    hostname &&
    hostType !== 'ipv6' &&
    (!/^[a-z0-9_.-]+$/.test(hostname) || hostname.split('.').some((label) => label === ''))
  ) {
    return {
      ok: false,
      input,
      error: 'The host contains characters that are not valid in a domain name.',
      hint: `“${hostname}” has spaces, percent-escapes, empty labels or other illegal characters. Check the pasted link.`,
    };
  }

  const displayHost = toUnicodeHost(hostname);
  const redacted = new URL(url.href);
  if (redacted.password) redacted.password = '****';
  const parts: UrlParts = {
    href: redacted.href,
    scheme,
    hostname,
    displayHost,
    registrable: hostType === 'domain' ? registrableDomain(hostname) : hostname,
    hostType,
    port: url.port,
    effectivePort: url.port || (scheme === 'https' ? '443' : scheme === 'http' ? '80' : ''),
    path: url.pathname,
    query: url.search,
    fragment: url.hash,
    username: safeDecode(url.username),
    hasPassword: url.password !== '',
  };

  const ctx: RuleContext = {
    input: trimmed,
    prep,
    url,
    parts,
    rawHost: rawHostOf(prep.normalized),
    refs: normalizeReferences(options.referenceDomains),
  };

  const findings: Finding[] = [];
  const readsLikeCandidates: ReadsLike[] = [];
  let matchedReference: string | null = null;
  for (const rule of RULE_PIPELINE) {
    const out = rule(ctx);
    findings.push(...out.findings);
    if (out.readsLike) readsLikeCandidates.push(out.readsLike);
    if (out.matchedReference && !matchedReference) matchedReference = out.matchedReference;
  }
  findings.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));

  const readsLike =
    READS_LIKE_PRIORITY.map((id) => readsLikeCandidates.find((r) => r.ruleId === id)).find(Boolean) ?? null;

  const checks = buildChecks(parts, findings);
  const { verdict, score } = computeVerdict(findings, checks);

  const analysis: Analysis = {
    ok: true,
    input,
    normalizedInput: prep.normalized,
    assumedScheme: prep.assumedScheme,
    parts,
    findings,
    verdict,
    score,
    checks,
    readsLike,
    matchedReference,
    summary: summarize(verdict, findings),
  };
  return analysis;
}
