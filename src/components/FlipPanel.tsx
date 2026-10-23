import { useMemo } from 'react';
import { diffMiddle } from '../analyzer/domain';
import type { FlipReport, FlipSuggestion } from '../analyzer/flip';
import { FlaskIcon, VerdictPill } from './ui';

function UrlDiff({ before, after }: { before: string; after: string }) {
  const d = diffMiddle(before, after);
  return (
    <p className="mono break-all text-white/55">
      {d.prefix}
      {d.a && <del className="rounded-sm bg-verdict-suspicious/10 text-verdict-suspicious decoration-2">{d.a}</del>}
      {d.b && <ins className="rounded-sm bg-pulse/15 text-pulse no-underline">{d.b}</ins>}
      {d.suffix}
    </p>
  );
}

function Suggestion({
  s,
  input,
  onTest,
  emphasis,
}: {
  s: FlipSuggestion;
  input: string;
  onTest: (url: string) => void;
  emphasis: boolean;
}) {
  return (
    <div className={`rounded-xl border p-4 ${emphasis ? 'border-pulse/30 bg-pulse/[0.04]' : 'border-white/[0.08] bg-white/[0.02]'}`}>
      <div className="flex flex-wrap items-center gap-2">
        <VerdictPill verdict={s.from} size="xs" />
        <span className="text-white/35" aria-hidden>
          →
        </span>
        <VerdictPill verdict={s.to} size="xs" />
        <span className="ml-auto font-mono text-[11px] text-white/40">
          {s.distance} char{s.distance === 1 ? '' : 's'} changed
        </span>
      </div>
      <p className="mt-3 text-[15px] text-white">{s.change}</p>
      <div className="mt-3 rounded-lg bg-black/25 px-3 py-2">
        <UrlDiff before={input} after={s.url} />
      </div>
      <div className="mt-3 flex flex-wrap items-center justify-between gap-3">
        <p className="text-xs text-white/45">{s.detail}</p>
        <button type="button" className="btn-ghost py-1.5 text-xs" onClick={() => onTest(s.url)}>
          <FlaskIcon /> Test this URL
        </button>
      </div>
    </div>
  );
}

export function FlipPanel({ report, input, onTest }: { report: FlipReport; input: string; onTest: (url: string) => void }) {
  const worsen = report.primary?.direction === 'worsen';
  const intro = useMemo(() => {
    if (!report.primary) return 'No small, verifiable edit changes this verdict.';
    return worsen
      ? 'This link passes today. Here is how little it would take for PRISM to stop trusting it.'
      : 'The smallest edit that changes the outcome, verified by re-running the analyzer.';
  }, [report.primary, worsen]);

  return (
    <section aria-labelledby="flip-heading" className="card p-6 sm:p-8">
      <h3 id="flip-heading" className="font-serif text-2xl">
        What would flip this verdict
      </h3>
      <p className="mt-2 text-sm text-white/55">{intro}</p>

      <div className="mt-5 space-y-3">
        {report.primary && <Suggestion s={report.primary} input={input.trim()} onTest={onTest} emphasis />}
        {report.secondary && <Suggestion s={report.secondary} input={input.trim()} onTest={onTest} emphasis={false} />}
      </div>

      {report.blockers.length > 0 && (
        <ul className="mt-5 space-y-2">
          {report.blockers.map((b) => (
            <li key={b.ruleId + b.text} className="flex gap-3 text-sm text-white/60">
              <span className="font-mono text-xs leading-5 text-pulse">{b.ruleId}</span>
              <span>{b.text}</span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
