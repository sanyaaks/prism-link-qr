import type { AnalyzerOptions, RuleMeta, Severity } from './types';

/**
 * Domains PRISM explicitly protects against impersonation. Lookalike and
 * brand-misuse rules only fire on a comparison against one of these.
 * `campus.example` is illustrative (RFC 2606 reserved), not a real site.
 */
export const DEFAULT_REFERENCE_DOMAINS = [
  'campus.example',
  'paypal.com',
  'google.com',
  'microsoft.com',
  'apple.com',
];

export const DEFAULT_OPTIONS: AnalyzerOptions = {
  referenceDomains: DEFAULT_REFERENCE_DOMAINS,
};

export const URL_SHORTENERS = [
  'bit.ly',
  'tinyurl.com',
  't.co',
  'goo.gl',
  'ow.ly',
  'is.gd',
  'buff.ly',
  'rebrand.ly',
  'cutt.ly',
  'shorturl.at',
  'tiny.cc',
  'rb.gy',
  's.id',
  'lnkd.in',
  'qrco.de',
  'tinylink.net',
];

export const WEB_SCHEMES = ['http', 'https'];
/** Schemes that can execute code or read local content when opened. */
export const DANGEROUS_SCHEMES = ['javascript', 'data', 'vbscript', 'file', 'blob'];

export const MAX_INPUT_LENGTH = 4096;

export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 100,
  high: 60,
  medium: 30,
  low: 10,
};

export const RULES: RuleMeta[] = [
  {
    id: 'PR-01',
    name: 'Deceptive userinfo (@)',
    summary: 'Text before an “@” in the authority is a username, not the destination.',
    severities: ['critical', 'high'],
  },
  {
    id: 'PR-02',
    name: 'Non-web scheme',
    summary: 'The link is not http(s); it may run script, embed data or open another app.',
    severities: ['critical', 'medium'],
  },
  {
    id: 'PR-03',
    name: 'IP-address host',
    summary: 'The host is a raw IP (or an encoded number that decodes to one).',
    severities: ['high', 'medium'],
  },
  {
    id: 'PR-04',
    name: 'Known URL shortener',
    summary: 'The real destination is hidden behind a redirect PRISM does not follow.',
    severities: ['medium'],
  },
  {
    id: 'PR-05',
    name: 'Lookalike domain',
    summary: 'The domain is visually confusable with, or one edit away from, a reference domain.',
    severities: ['high', 'medium'],
  },
  {
    id: 'PR-06',
    name: 'Reference name misused in host',
    summary: 'A reference domain or brand appears in a host it does not control.',
    severities: ['high', 'medium'],
  },
  {
    id: 'PR-07',
    name: 'Internationalized (punycode) host',
    summary: 'The host uses non-ASCII characters that may imitate familiar letters.',
    severities: ['medium'],
  },
  {
    id: 'PR-08',
    name: 'Unencrypted HTTP',
    summary: 'Traffic is not encrypted and can be read or altered in transit.',
    severities: ['low'],
  },
  {
    id: 'PR-09',
    name: 'Reference domain in path',
    summary: 'A reference domain appears after the host, where it has no routing effect.',
    severities: ['medium'],
  },
  {
    id: 'PR-10',
    name: 'Ambiguous input',
    summary: 'Missing scheme, backslashes, invisible characters or an unqualified host.',
    severities: ['medium', 'low'],
  },
];

export const RULE_NAME = Object.fromEntries(RULES.map((r) => [r.id, r.name])) as Record<
  RuleMeta['id'],
  string
>;
