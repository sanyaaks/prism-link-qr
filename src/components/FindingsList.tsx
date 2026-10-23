import type { Analysis } from '../analyzer/types';
import { CheckIcon, CrossIcon, SeverityBadge } from './ui';

export function FindingsList({ analysis: a }: { analysis: Analysis }) {
  return (
    <section aria-labelledby="findings-heading" className="card p-6 sm:p-8">
      <div className="flex items-baseline justify-between">
        <h3 id="findings-heading" className="font-serif text-2xl">
          Findings
        </h3>
        <span className="text-xs text-white/45">
          {new Set(a.findings.map((f) => f.ruleId)).size} of 10 rules triggered
        </span>
      </div>

      {a.findings.length === 0 ? (
        <p className="mt-5 rounded-xl border border-dashed border-white/[0.12] px-4 py-6 text-sm leading-relaxed text-white/60">
          No rule fired. Every positive check below passed, which is why this link is marked Safe. PRISM only knows what
          the link text says, not what the site does.
        </p>
      ) : (
        <ol className="mt-5 space-y-3">
          {a.findings.map((f, i) => (
            <li
              key={`${f.ruleId}-${i}`}
              className="animate-rise rounded-xl border border-white/[0.07] bg-white/[0.02] p-4 transition-colors hover:border-white/15"
              style={{ animationDelay: `${i * 60}ms` }}
            >
              <div className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-xs text-pulse">{f.ruleId}</span>
                <SeverityBadge severity={f.severity} />
                <span className="text-xs text-white/40">{f.ruleName}</span>
              </div>
              <p className="mt-2 font-medium text-white">{f.title}</p>
              <p className="mt-1.5 text-sm leading-relaxed text-white/65">{f.explanation}</p>
              {f.evidence && (
                <p className="mono mt-3 break-all rounded-md bg-black/25 px-2.5 py-1.5 text-xs text-white/55">{f.evidence}</p>
              )}
            </li>
          ))}
        </ol>
      )}

      <div className="mt-7">
        <p className="eyebrow">Positive checks</p>
        <ul className="mt-3 grid gap-x-6 gap-y-2 sm:grid-cols-2">
          {a.checks.map((c) => (
            <li key={c.label} className="flex items-start gap-2 text-sm">
              <span
                className={`mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full ${
                  c.passed ? 'bg-verdict-safe/15 text-verdict-safe' : 'bg-verdict-suspicious/15 text-verdict-suspicious'
                }`}
              >
                {c.passed ? <CheckIcon /> : <CrossIcon />}
              </span>
              <span className={c.passed ? 'text-white/70' : 'text-white/90'}>
                {c.label}
                <span className="sr-only">{c.passed ? ' (passed)' : ' (failed)'}</span>
              </span>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
