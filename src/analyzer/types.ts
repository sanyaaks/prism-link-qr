export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type Verdict = 'Safe' | 'Review' | 'Suspicious';

export type RuleId =
  | 'PR-01'
  | 'PR-02'
  | 'PR-03'
  | 'PR-04'
  | 'PR-05'
  | 'PR-06'
  | 'PR-07'
  | 'PR-08'
  | 'PR-09'
  | 'PR-10';

export interface RuleMeta {
  id: RuleId;
  name: string;
  summary: string;
  severities: Severity[];
}

export interface Finding {
  ruleId: RuleId;
  ruleName: string;
  severity: Severity;
  title: string;
  explanation: string;
  evidence?: string;
}

export type HostType = 'domain' | 'single-label' | 'ipv4' | 'ipv6' | 'none';

export interface UrlParts {
  /** Serialized URL as produced by the WHATWG URL parser. */
  href: string;
  scheme: string;
  /** Normalized ASCII hostname (lowercase, punycode, no trailing dot). */
  hostname: string;
  /** Hostname with punycode labels decoded for display. */
  displayHost: string;
  /** Best-effort registrable domain (e.g. "campus.example"). */
  registrable: string;
  hostType: HostType;
  port: string;
  effectivePort: string;
  path: string;
  query: string;
  fragment: string;
  username: string;
  hasPassword: boolean;
}

export type SegmentTone = 'plain' | 'muted' | 'deceptive' | 'actual';

export interface Segment {
  text: string;
  tone: SegmentTone;
}

export interface ReadsLike {
  ruleId: RuleId;
  appears: string;
  appearsLabel: string;
  actual: string;
  actualLabel: string;
  segments: Segment[];
  note: string;
}

export interface Check {
  label: string;
  passed: boolean;
}

export interface Analysis {
  ok: true;
  input: string;
  /** Input after trimming and (if needed) adding an assumed scheme. */
  normalizedInput: string;
  assumedScheme: boolean;
  parts: UrlParts;
  findings: Finding[];
  verdict: Verdict;
  score: number;
  checks: Check[];
  readsLike: ReadsLike | null;
  matchedReference: string | null;
  summary: string;
}

export interface AnalysisError {
  ok: false;
  input: string;
  error: string;
  hint: string;
}

export type AnalysisResult = Analysis | AnalysisError;

export interface AnalyzerOptions {
  referenceDomains: string[];
}
