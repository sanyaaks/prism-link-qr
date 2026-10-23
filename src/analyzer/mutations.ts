import { analyze, matchShortener } from './analyze';
import { DEFAULT_REFERENCE_DOMAINS } from './config';
import { isSameOrSubdomain } from './domain';
import type { Analysis, AnalysisResult, AnalyzerOptions, Verdict } from './types';

export type MutationKind = 'attack' | 'benign';
export type MutationStatus = 'caught' | 'clean' | 'mismatch';

export interface MutationSpec {
  id: string;
  label: string;
  kind: MutationKind;
  technique: string;
  url: string;
  expected: Verdict;
  /** Detection depends on the baseline being a configured reference domain. */
  requiresReference?: boolean;
}

export interface MutationResult extends MutationSpec {
  result: AnalysisResult;
  actual: Verdict | 'Error';
  status: MutationStatus;
  note: string;
}

export interface Baseline {
  domain: string;
  path: string;
  isReference: boolean;
  url: string;
}

export interface MatrixReport {
  baseline: Baseline;
  results: MutationResult[];
  caught: number;
  clean: number;
  mismatches: number;
}

const LOOKALIKE_SWAPS: Array<[string, string]> = [
  ['m', 'rn'],
  ['w', 'vv'],
  ['d', 'cl'],
  ['l', '1'],
  ['o', '0'],
  ['i', '1'],
  ['e', '3'],
  ['s', '5'],
];

const CYRILLIC: Record<string, string> = { a: 'а', e: 'е', o: 'о', p: 'р', c: 'с', x: 'х', y: 'у', i: 'і' };

/** Swap one character in the domain's first label for a visual lookalike. */
export function homoglyphSwap(domain: string): string {
  const dot = domain.indexOf('.');
  const label = dot === -1 ? domain : domain.slice(0, dot);
  const rest = dot === -1 ? '' : domain.slice(dot);
  for (const [from, to] of LOOKALIKE_SWAPS) {
    const i = label.indexOf(from);
    if (i !== -1) return label.slice(0, i) + to + label.slice(i + from.length) + rest;
  }
  return label + label.slice(-1) + rest;
}

/** Replace one Latin letter with a Cyrillic twin and return the punycode host. */
export function cyrillicSwap(domain: string): string | null {
  const dot = domain.indexOf('.');
  const label = dot === -1 ? domain : domain.slice(0, dot);
  const rest = dot === -1 ? '' : domain.slice(dot);
  for (let i = 0; i < label.length; i++) {
    const twin = CYRILLIC[label[i]];
    if (!twin) continue;
    try {
      return new URL('https://' + label.slice(0, i) + twin + label.slice(i + 1) + rest).hostname;
    } catch {
      return null;
    }
  }
  return null;
}

export function baselineFor(analysis: Analysis | null, options: AnalyzerOptions): Baseline {
  const refs = options.referenceDomains.length ? options.referenceDomains : DEFAULT_REFERENCE_DOMAINS;
  let domain = refs[0];
  let path = '/login';
  if (analysis && analysis.parts.hostType === 'domain') {
    const host = analysis.parts.hostname;
    const isShortener = matchShortener(host) !== null;
    if (!isShortener) {
      domain = analysis.matchedReference ?? refs.find((r) => isSameOrSubdomain(host, r)) ?? analysis.parts.registrable;
      const fired = new Set(analysis.findings.map((f) => f.ruleId));
      if (analysis.parts.path !== '/' && !fired.has('PR-09')) path = analysis.parts.path;
    }
  }
  return {
    domain,
    path,
    isReference: refs.some((r) => isSameOrSubdomain(domain, r.toLowerCase())),
    url: `https://${domain}${path}`,
  };
}

export function generateMutations(b: Baseline): MutationSpec[] {
  const { domain: d, path: p } = b;
  const cyr = cyrillicSwap(d);
  const specs: MutationSpec[] = [
    {
      id: 'lookalike',
      label: 'Lookalike letters',
      kind: 'attack',
      technique: 'Swaps letters for visually similar ones (rn→m, 1→l).',
      url: `https://${homoglyphSwap(d)}${p}`,
      expected: 'Suspicious',
      requiresReference: true,
    },
    ...(cyr
      ? [
          {
            id: 'homograph',
            label: 'Cyrillic homograph',
            kind: 'attack' as const,
            technique: 'Replaces a Latin letter with an identical-looking Cyrillic one.',
            url: `https://${cyr}${p}`,
            expected: 'Suspicious' as const,
            requiresReference: true,
          },
        ]
      : []),
    {
      id: 'userinfo',
      label: 'Userinfo @ trick',
      kind: 'attack',
      technique: 'Puts the trusted name before “@” so it is parsed as a username.',
      url: `https://${d}@login-verify.example${p}`,
      expected: 'Suspicious',
    },
    {
      id: 'decimal-ip',
      label: 'Decimal IP host',
      kind: 'attack',
      technique: 'Encodes 192.168.1.1 as a single integer.',
      url: `http://3232235777${p}`,
      expected: 'Suspicious',
    },
    {
      id: 'subdomain',
      label: 'Name as subdomain',
      kind: 'attack',
      technique: 'Uses the trusted domain as a subdomain of another domain.',
      url: `https://${d}.account-verify.example${p}`,
      expected: 'Suspicious',
      requiresReference: true,
    },
    {
      id: 'script',
      label: 'Script scheme',
      kind: 'attack',
      technique: 'A javascript: link that runs code instead of loading a page.',
      url: 'javascript:alert(document.domain)',
      expected: 'Suspicious',
    },
    {
      id: 'path-mention',
      label: 'Name in path only',
      kind: 'attack',
      technique: 'Mentions the trusted domain after an unrelated host.',
      url: `https://login-verify.example/${d}${p}`,
      expected: 'Review',
      requiresReference: true,
    },
    {
      id: 'shortener',
      label: 'Shortened link',
      kind: 'attack',
      technique: 'Hides the destination behind a redirect service.',
      url: 'https://bit.ly/3xQ9aZk',
      expected: 'Review',
    },
    {
      id: 'http',
      label: 'HTTP downgrade',
      kind: 'attack',
      technique: 'Same host over unencrypted http://.',
      url: `http://${d}${p}`,
      expected: 'Review',
    },
    {
      id: 'uppercase',
      label: 'Uppercase host',
      kind: 'benign',
      technique: 'Hostnames are case-insensitive.',
      url: `https://${d.toUpperCase()}${p}`,
      expected: 'Safe',
    },
    {
      id: 'port',
      label: 'Alternate port 8443',
      kind: 'benign',
      technique: 'A non-default port on the same host.',
      url: `https://${d}:8443${p}`,
      expected: 'Safe',
    },
    {
      id: 'encoded-path',
      label: 'Percent-encoded path',
      kind: 'benign',
      technique: 'Encoded spaces and accented letters in the path.',
      url: `https://${d}${p.replace(/\/$/, '')}/r%C3%A9sum%C3%A9%20files`,
      expected: 'Safe',
    },
    {
      id: 'subdomain-legit',
      label: 'Extra subdomain',
      kind: 'benign',
      technique: 'A subdomain the domain owner controls.',
      url: `https://portal.${d}${p}`,
      expected: 'Safe',
    },
    {
      id: 'query',
      label: 'Query and fragment',
      kind: 'benign',
      technique: 'Encoded query parameters and an anchor.',
      url: `https://${d}${p}?next=%2Fdashboard&lang=en#top`,
      expected: 'Safe',
    },
    {
      id: 'trailing-dot',
      label: 'Trailing-dot FQDN',
      kind: 'benign',
      technique: 'An absolute DNS name ending in “.”.',
      url: `https://${d}.${p}`,
      expected: 'Safe',
    },
  ];
  return specs;
}

function noteFor(spec: MutationSpec, actual: Verdict | 'Error', isReference: boolean, result: AnalysisResult): string {
  if (actual === spec.expected) {
    if (!result.ok) return '';
    const top = result.findings[0];
    return top ? `${top.ruleId} · ${top.ruleName}` : 'All checks passed';
  }
  if (spec.requiresReference && !isReference) {
    return 'Not detected: baseline is not a configured reference domain, so there is nothing to impersonate.';
  }
  if (!result.ok) return result.error;
  const top = result.findings[0];
  return top ? `Got ${actual}: ${top.title}` : `Got ${actual} with no findings`;
}

export function runMatrix(analysis: Analysis | null, options: AnalyzerOptions): MatrixReport {
  const baseline = baselineFor(analysis, options);
  const results = generateMutations(baseline).map((spec): MutationResult => {
    const result = analyze(spec.url, options);
    const actual: Verdict | 'Error' = result.ok ? result.verdict : 'Error';
    const status: MutationStatus =
      actual === spec.expected ? (spec.kind === 'attack' ? 'caught' : 'clean') : 'mismatch';
    return { ...spec, result, actual, status, note: noteFor(spec, actual, baseline.isReference, result) };
  });
  return {
    baseline,
    results,
    caught: results.filter((r) => r.status === 'caught').length,
    clean: results.filter((r) => r.status === 'clean').length,
    mismatches: results.filter((r) => r.status === 'mismatch').length,
  };
}
