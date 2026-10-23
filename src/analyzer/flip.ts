import { analyze, prepareInput } from './analyze';
import { editDistance, registrableDomain } from './domain';
import { homoglyphSwap } from './mutations';
import type { Analysis, AnalyzerOptions, RuleId, Verdict } from './types';

export interface FlipSuggestion {
  direction: 'improve' | 'worsen';
  from: Verdict;
  to: Verdict;
  url: string;
  change: string;
  detail: string;
  distance: number;
}

export interface FlipReport {
  primary: FlipSuggestion | null;
  secondary: FlipSuggestion | null;
  blockers: { ruleId: RuleId; text: string }[];
}

const RANK: Record<Verdict, number> = { Safe: 0, Review: 1, Suspicious: 2 };

interface Fix {
  ruleIds: RuleId[];
  change: string;
  apply: (u: URL) => void;
}

const INVISIBLE_OR_CONTROL = /[\u0000-\u001F\u007F­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

function cleanedHref(a: Analysis): string {
  const stripped = a.input.trim().replace(INVISIBLE_OR_CONTROL, '');
  try {
    return new URL(prepareInput(stripped).normalized).href;
  } catch {
    return a.parts.href;
  }
}

function fixesFor(a: Analysis): { fixes: Fix[]; blockers: FlipReport['blockers'] } {
  const fixes: Fix[] = [];
  const blockers: FlipReport['blockers'] = [];
  const { parts } = a;
  const ref = a.matchedReference;

  for (const f of a.findings) {
    switch (f.ruleId) {
      case 'PR-01':
        fixes.push({
          ruleIds: ['PR-01'],
          change: `Remove “${parts.username}${parts.hasPassword ? ':…' : ''}@” so nothing disguises the real host ${parts.displayHost}`,
          apply: (u) => {
            u.username = '';
            u.password = '';
          },
        });
        break;
      case 'PR-05':
      case 'PR-06':
        if (ref) {
          fixes.push({
            ruleIds: [f.ruleId],
            change: `Point at the genuine reference domain ${ref} instead of ${parts.registrable}`,
            apply: (u) => {
              const reg = registrableDomain(u.hostname);
              u.hostname = f.ruleId === 'PR-05' ? u.hostname.slice(0, u.hostname.length - reg.length) + ref : ref;
            },
          });
        }
        break;
      case 'PR-08':
        fixes.push({ ruleIds: ['PR-08'], change: 'Use https:// instead of http://', apply: (u) => void (u.protocol = 'https:') });
        break;
      case 'PR-09':
        fixes.push({
          ruleIds: ['PR-09'],
          change: `Drop the path that mentions ${ref ?? 'the reference domain'}`,
          apply: (u) => {
            u.pathname = '/';
            u.search = '';
            u.hash = '';
          },
        });
        break;
      case 'PR-03':
        blockers.push({
          ruleId: 'PR-03',
          text: f.severity === 'high'
            ? `Writing the host as ${parts.hostname} removes the disguise, but a raw IP still needs Review. Only a named domain you can verify would clear it.`
            : 'Only replacing the IP address with a named domain you can verify would clear this.',
        });
        if (f.severity === 'high') fixes.push({ ruleIds: ['PR-03'], change: `Write the host plainly as ${parts.hostname}`, apply: () => {} });
        break;
      case 'PR-04':
        blockers.push({ ruleId: 'PR-04', text: 'Expanding the short link to its real destination would let PRISM screen that host instead. PRISM does not follow redirects itself.' });
        break;
      case 'PR-02':
        blockers.push({
          ruleId: 'PR-02',
          text: 'No small edit makes a non-web link screenable. It would have to be replaced by an https:// link to a named domain.',
        });
        break;
      case 'PR-07':
        if (!a.findings.some((x) => x.ruleId === 'PR-05')) {
          blockers.push({ ruleId: 'PR-07', text: 'Only an all-ASCII hostname would clear the internationalized-host signal.' });
        }
        break;
      case 'PR-10':
        if (/scheme/i.test(f.title)) fixes.push({ ruleIds: ['PR-10'], change: 'Write the scheme explicitly as https://', apply: () => {} });
        else if (/backslash/i.test(f.title)) fixes.push({ ruleIds: ['PR-10'], change: 'Replace “\\” with “/”', apply: () => {} });
        else if (/invisible/i.test(f.title)) fixes.push({ ruleIds: ['PR-10'], change: 'Strip the invisible characters', apply: () => {} });
        else blockers.push({ ruleId: 'PR-10', text: 'Only a fully-qualified domain name would clear the unqualified-host signal.' });
        break;
    }
  }
  return { fixes, blockers };
}

function tryCandidate(
  a: Analysis,
  base: string,
  apply: (u: URL) => void,
  change: string,
  options: AnalyzerOptions,
  direction: FlipSuggestion['direction'],
): FlipSuggestion | null {
  let url: string;
  try {
    const u = new URL(base);
    apply(u);
    url = u.href;
  } catch {
    return null;
  }
  const r = analyze(url, options);
  if (!r.ok || r.verdict === a.verdict) return null;
  const better = RANK[r.verdict] < RANK[a.verdict];
  if ((direction === 'improve') !== better) return null;
  return {
    direction,
    from: a.verdict,
    to: r.verdict,
    url,
    change,
    detail: r.findings.length
      ? `Re-analyzed: ${r.verdict}. Remaining: ${r.findings.map((x) => x.ruleId).join(', ')}.`
      : `Re-analyzed: ${r.verdict}, all checks pass.`,
    distance: editDistance(a.input.trim(), url),
  };
}

function pick(cands: FlipSuggestion[]): { primary: FlipSuggestion | null; secondary: FlipSuggestion | null } {
  if (!cands.length) return { primary: null, secondary: null };
  const byDistance = [...cands].sort((x, y) => x.distance - y.distance);
  const primary = byDistance[0];
  // Secondary: the cheapest candidate that reaches a further verdict than the primary.
  const further = byDistance.find((c) =>
    primary.direction === 'improve' ? RANK[c.to] < RANK[primary.to] : RANK[c.to] > RANK[primary.to],
  );
  return { primary, secondary: further ?? null };
}

/** Find the smallest verified edit that changes this verdict. Every suggestion is re-analyzed. */
export function computeFlips(a: Analysis, options: AnalyzerOptions): FlipReport {
  const base = cleanedHref(a);

  if (a.verdict === 'Safe') {
    const cands: FlipSuggestion[] = [];
    if (a.parts.scheme === 'https') {
      const c = tryCandidate(a, base, (u) => void (u.protocol = 'http:'), 'Drop the “s” from https://', options, 'worsen');
      if (c) cands.push(c);
    }
    if (a.parts.hostType === 'domain') {
      const swapped = homoglyphSwap(a.parts.registrable);
      const c = tryCandidate(
        a,
        base,
        (u) => {
          u.hostname = u.hostname.slice(0, u.hostname.length - a.parts.registrable.length) + swapped;
        },
        `Change ${a.parts.registrable} to the lookalike ${swapped}`,
        options,
        'worsen',
      );
      if (c) cands.push(c);
      const at = tryCandidate(
        a,
        base,
        (u) => {
          u.username = a.parts.hostname;
          u.hostname = 'login-verify.example';
        },
        `Put “${a.parts.hostname}@” in front of a different host`,
        options,
        'worsen',
      );
      if (at) cands.push(at);
    }
    return { ...pick(cands), blockers: [] };
  }

  const { fixes, blockers } = fixesFor(a);
  const cands: FlipSuggestion[] = [];
  for (const fix of fixes) {
    const c = tryCandidate(a, base, fix.apply, fix.change, options, 'improve');
    if (c) cands.push(c);
  }
  if (fixes.length > 1) {
    const c = tryCandidate(
      a,
      base,
      (u) => fixes.forEach((f) => f.apply(u)),
      fixes.map((f) => f.change).join('; then '),
      options,
      'improve',
    );
    if (c) cands.push(c);
  }
  return { ...pick(cands), blockers };
}
