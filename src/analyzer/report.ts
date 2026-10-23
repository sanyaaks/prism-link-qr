import type { Analysis } from './types';

/** Plain-text summary of an analysis, suitable for pasting into a ticket or chat. */
export function formatReport(a: Analysis): string {
  const p = a.parts;
  const lines = [
    `PRISM screening — ${a.verdict.toUpperCase()} (risk score ${a.score}/100)`,
    `Input: ${a.input.trim()}`,
    '',
    `Scheme: ${p.scheme}`,
    `Host:   ${p.displayHost || '(none)'}${p.displayHost !== p.hostname ? ` [${p.hostname}]` : ''}`,
    `Port:   ${p.port || (p.effectivePort ? `default (${p.effectivePort})` : '—')}`,
    `Path:   ${p.path || '—'}`,
  ];
  if (a.readsLike) {
    lines.push('', `${a.readsLike.appearsLabel}: ${a.readsLike.appears}`, `${a.readsLike.actualLabel}: ${a.readsLike.actual}`);
  }
  lines.push('', a.findings.length ? 'Findings:' : 'Findings: none');
  for (const f of a.findings) {
    lines.push(`- [${f.ruleId}] ${f.severity.toUpperCase()} — ${f.title}`, `  ${f.explanation}`);
  }
  lines.push(
    '',
    'Local rule-based screening only. PRISM does not visit the link, follow redirects or verify the site.',
  );
  return lines.join('\n');
}
