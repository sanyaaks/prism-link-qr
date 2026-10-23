import type { MatrixReport, MutationResult } from '../analyzer/mutations';
import { FlaskIcon, ResetIcon, SectionHeading, VerdictPill } from './ui';

const STATUS: Record<MutationResult['status'], { card: string; badge: string; label: string }> = {
  caught: {
    card: 'border-verdict-suspicious/30 bg-verdict-suspicious/[0.05] hover:border-verdict-suspicious/50',
    badge: 'bg-verdict-suspicious/15 text-verdict-suspicious',
    label: 'Attack detected',
  },
  clean: {
    card: 'border-verdict-safe/25 bg-verdict-safe/[0.04] hover:border-verdict-safe/45',
    badge: 'bg-verdict-safe/15 text-verdict-safe',
    label: 'Expected safe',
  },
  mismatch: {
    card: 'border-verdict-review/40 bg-verdict-review/[0.06] hover:border-verdict-review/60',
    badge: 'bg-verdict-review/20 text-verdict-review',
    label: 'Mismatch',
  },
};

interface Props {
  report: MatrixReport | null;
  onRun: () => void;
  onAnalyze: (url: string) => void;
  onAddReference: (domain: string) => void;
}

export function MutationMatrix({ report, onRun, onAnalyze, onAddReference }: Props) {
  return (
    <section id="matrix" aria-labelledby="matrix-heading" className="scroll-mt-24">
      <SectionHeading
        eyebrow="Attack & safe mutation matrix"
        title={<span id="matrix-heading">Stress-test the analyzer</span>}
      >
        <button type="button" className={report ? 'btn-ghost' : 'btn-primary'} onClick={onRun}>
          {report ? <ResetIcon /> : <FlaskIcon />}
          {report ? 'Regenerate' : 'Generate mutations'}
        </button>
      </SectionHeading>

      {!report ? (
        <div className="card flex flex-col gap-3 p-6 text-sm text-white/60 sm:p-8">
          <p className="max-w-2xl leading-relaxed">
            Generates deceptive and legitimate variants of the current link (or{' '}
            <span className="font-mono text-white/80">campus.example</span> when nothing has been analyzed), runs every
            variant through the same analyzer, and compares each verdict with what a careful human would expect.
          </p>
        </div>
      ) : (
        <div className="animate-fade">
          <div className="card mb-5 flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0 text-sm text-white/65">
              Baseline{' '}
              <span className="mono break-all text-white">{report.baseline.url}</span>
              {!report.baseline.isReference && (
                <span className="mt-1 block text-xs text-verdict-review">
                  {report.baseline.domain} is not a reference domain, so impersonation variants cannot be confirmed.{' '}
                  <button
                    type="button"
                    className="underline decoration-dotted underline-offset-2 hover:text-white"
                    onClick={() => onAddReference(report.baseline.domain)}
                  >
                    Add it as a reference
                  </button>
                </span>
              )}
            </div>
            <dl className="flex shrink-0 gap-5 text-center" aria-label="Matrix summary">
              {[
                ['Attacks detected', report.caught, 'text-verdict-suspicious'],
                ['Safe as expected', report.clean, 'text-verdict-safe'],
                ['Mismatches', report.mismatches, report.mismatches ? 'text-verdict-review' : 'text-white/40'],
              ].map(([label, n, cls]) => (
                <div key={label as string}>
                  <dd className={`font-serif text-3xl ${cls}`}>{n}</dd>
                  <dt className="text-[11px] text-white/45">{label}</dt>
                </div>
              ))}
            </dl>
          </div>

          <ul className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
            {report.results.map((r, i) => {
              const st = STATUS[r.status];
              return (
                <li
                  key={r.id}
                  className={`animate-rise flex flex-col rounded-xl border p-4 transition-colors ${st.card}`}
                  style={{ animationDelay: `${i * 35}ms` }}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-[11px] uppercase tracking-[0.14em] text-white/45">
                      {r.kind === 'attack' ? 'Attack variant' : 'Legitimate variant'}
                    </span>
                    <span className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${st.badge}`}>{st.label}</span>
                  </div>
                  <p className="mt-2 font-medium text-white">{r.label}</p>
                  <p className="mt-0.5 text-xs text-white/50">{r.technique}</p>
                  <p className="mono mt-3 break-all rounded-md bg-black/25 px-2.5 py-1.5 text-xs text-white/75">{r.url}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-2 text-xs text-white/45">
                    <span>Expected</span>
                    <VerdictPill verdict={r.expected} size="xs" />
                    <span>Got</span>
                    <VerdictPill verdict={r.actual} size="xs" />
                  </div>
                  {r.note && <p className="mt-2 text-xs leading-relaxed text-white/55">{r.note}</p>}
                  <button
                    type="button"
                    className="mt-auto self-start pt-3 text-xs text-pulse underline-offset-4 hover:underline"
                    onClick={() => onAnalyze(r.url)}
                  >
                    Analyze this variant →
                  </button>
                </li>
              );
            })}
          </ul>
        </div>
      )}
    </section>
  );
}
