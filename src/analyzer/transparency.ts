import { matchShortener } from './analyze';
import { RULES } from './config';
import type { Analysis, Finding, RuleMeta, Severity } from './types';

/**
 * How strongly a finding supports its conclusion. Derived only from the
 * severity the rule already assigned; it is not a probability.
 */
export type EvidenceKind = 'direct' | 'ambiguous' | 'hygiene';

export const EVIDENCE_KIND: Record<Severity, EvidenceKind> = {
  critical: 'direct',
  high: 'direct',
  medium: 'ambiguous',
  low: 'hygiene',
};

export const EVIDENCE_LABEL: Record<EvidenceKind, { label: string; meaning: string }> = {
  direct: {
    label: 'Direct evidence',
    meaning: 'The link text itself is structured to mislead or to run something other than a web page.',
  },
  ambiguous: {
    label: 'Ambiguous signal',
    meaning: 'Common in attacks, but also used legitimately. Needs a human decision.',
  },
  hygiene: {
    label: 'Hygiene weakness',
    meaning: 'Not deceptive on its own, but weakens protection or creates room for confusion.',
  },
};

export interface RedirectInfo {
  /** Shortener service from the configured list (the same match PR-04 used). */
  service: string;
  visibleHost: string;
  visiblePath: string;
  scheme: string;
}

export interface Transparency {
  conclusion: string;
  evidence: { finding: Finding; kind: EvidenceKind }[];
  observed: string[];
  unknown: string[];
  redirect: RedirectInfo | null;
  notTriggered: RuleMeta[];
}

export function redirectInfo(a: Analysis): RedirectInfo | null {
  if (!a.findings.some((f) => f.ruleId === 'PR-04')) return null;
  const service = matchShortener(a.parts.hostname);
  if (!service) return null;
  return {
    service,
    visibleHost: a.parts.hostname,
    visiblePath: a.parts.path + a.parts.query + a.parts.fragment,
    scheme: a.parts.scheme,
  };
}

/** Facts read from the parsed URL, and what offline rules cannot establish. */
export function explainLimits(a: Analysis): Transparency {
  const p = a.parts;
  const isWeb = p.scheme === 'http' || p.scheme === 'https';
  const redirect = redirectInfo(a);
  const fired = new Set(a.findings.map((f) => f.ruleId));

  const observed: string[] = [`Scheme is ${p.scheme}:${isWeb ? '' : ' (not a web link)'}`];
  if (p.hostname) {
    observed.push(
      `A browser would connect to the host ${p.displayHost}${p.displayHost !== p.hostname ? ` (registered as ${p.hostname})` : ''}`,
    );
    if (p.hostType === 'domain' && p.registrable !== p.hostname) {
      observed.push(`That host belongs to the registered domain ${p.registrable}`);
    }
  }
  if (p.effectivePort) observed.push(`Port ${p.effectivePort}${p.port ? ' (explicit)' : ' (default for the scheme)'}`);
  if (p.username || p.hasPassword) observed.push('The link carries userinfo before “@”, which is not part of the destination');
  if (isWeb) observed.push(`Path is ${p.path}${p.query ? `, with query ${p.query}` : ''}`);
  if (a.assumedScheme) observed.push('No scheme was given; https:// was assumed for analysis');
  observed.push(`${fired.size} of ${RULES.length} rules matched`);

  const unknown: string[] = [];
  if (redirect) {
    unknown.push(
      `The final destination of this ${redirect.service} link`,
      'How many redirects happen before a page loads',
      'The content of whatever page is eventually reached',
    );
  } else if (isWeb) {
    unknown.push(`Whether ${p.displayHost || 'the host'} redirects elsewhere when opened (PRISM sends no requests)`);
  } else {
    unknown.push(`What the application that handles ${p.scheme}: links will do with it`);
  }
  unknown.push(
    'Who operates the destination and whether they are legitimate',
    'Whether the site is currently hosting malware or phishing content',
    'Domain age, reputation or presence on threat-intelligence lists',
  );

  const conclusion =
    a.verdict === 'Safe'
      ? 'No suspicious rule matched and every positive check passed. That is not verification that the URL is safe.'
      : a.verdict === 'Review'
        ? 'The link raised signals that need a human decision. PRISM has not confirmed it is malicious.'
        : 'The link text shows direct or combined signs of deception. PRISM has not visited it to confirm.';

  return {
    conclusion,
    evidence: a.findings.map((finding) => ({ finding, kind: EVIDENCE_KIND[finding.severity] })),
    observed,
    unknown,
    redirect,
    notTriggered: RULES.filter((r) => !fired.has(r.id)),
  };
}
