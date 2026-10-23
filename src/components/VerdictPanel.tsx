import type { Analysis, AnalyzerOptions } from '../analyzer/types';
import type { InputSource } from '../lib/source';
import { downloadAnalysisReport } from '../reports/pdf';
import { formatReport } from '../analyzer/report';
import { ArrowLeft, AsyncButton, CopyButton, DownloadIcon, GridIcon, ResetIcon, VERDICT_STYLE, VerdictGlyph } from './ui';

interface Props {
  analysis: Analysis;
  source: InputSource;
  options: AnalyzerOptions;
  canGoBack: boolean;
  onBack: () => void;
  onReset: () => void;
  onMatrix: () => void;
}

function Field({ label, value, hint, wide }: { label: string; value: string; hint?: string; wide?: boolean }) {
  return (
    <div className={`min-w-0 ${wide ? 'col-span-2' : ''}`}>
      <dt className="text-[11px] uppercase tracking-[0.16em] text-white/40">{label}</dt>
      <dd className="mono mt-1 break-all text-white/90">
        {value || <span className="text-white/30">—</span>}
        {hint && <span className="ml-2 font-sans text-xs text-white/40">{hint}</span>}
      </dd>
    </div>
  );
}

export function VerdictPanel({ analysis: a, source, options, canGoBack, onBack, onReset, onMatrix }: Props) {
  const s = VERDICT_STYLE[a.verdict];
  const p = a.parts;
  const hostTypeHint: Record<typeof p.hostType, string> = {
    domain: '',
    'single-label': 'unqualified',
    ipv4: 'IPv4 literal',
    ipv6: 'IPv6 literal',
    none: 'no host',
  };
  return (
    <section aria-labelledby="verdict-heading" className="card relative overflow-hidden">
      <div className={`absolute inset-x-0 top-0 h-px ${s.bar}`} aria-hidden />
      <div className="grid gap-8 p-6 sm:p-8 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <div className="flex flex-col">
          <div className="flex flex-wrap items-center gap-2">
            <p className="eyebrow">Verdict</p>
            {source.kind === 'qr' && (
              <span className="max-w-full truncate rounded-full border border-pulse/30 bg-pulse/[0.06] px-2 py-0.5 text-[11px] text-pulse" title={source.fileName}>
                From QR image · {source.fileName}
              </span>
            )}
          </div>
          <div className="mt-3 flex items-center gap-3">
            <span className={`flex h-11 w-11 shrink-0 items-center justify-center rounded-full border ${s.border} ${s.bg} ${s.text}`}>
              <VerdictGlyph verdict={a.verdict} />
            </span>
            <h2 id="verdict-heading" className={`font-serif text-5xl leading-none sm:text-6xl ${s.text}`}>
              {a.verdict}
            </h2>
          </div>
          <p className="mt-2 text-xs uppercase tracking-[0.16em] text-white/45">{s.tagline}</p>
          <p className="mt-5 max-w-md text-[15px] leading-relaxed text-white/80">{a.summary}</p>

          <div className="mt-6 max-w-xs">
            <div className="flex items-baseline justify-between text-xs text-white/50">
              <span>Risk score</span>
              <span className="font-mono text-white/80">{a.score}/100</span>
            </div>
            <div
              className="mt-2 h-1 overflow-hidden rounded-full bg-white/10"
              role="meter"
              aria-label="Risk score"
              aria-valuemin={0}
              aria-valuemax={100}
              aria-valuenow={a.score}
            >
              <div className={`h-full rounded-full ${s.bar} transition-[width] duration-700 ease-out`} style={{ width: `${Math.max(a.score, 2)}%` }} />
            </div>
          </div>

          <div className="mt-auto flex flex-wrap items-start gap-2 pt-7">
            <AsyncButton
              onRun={() => downloadAnalysisReport(a, source, options)}
              label="Download PDF report"
              busyLabel="Preparing PDF…"
              className="btn-primary"
              icon={<DownloadIcon />}
            />
            <CopyButton text={() => formatReport(a)} label="Copy findings" />
            <button type="button" className="btn-ghost" onClick={onMatrix}>
              <GridIcon /> Mutation matrix
            </button>
            {canGoBack && (
              <button type="button" className="btn-quiet" onClick={onBack}>
                <ArrowLeft /> Previous link
              </button>
            )}
            <button type="button" className="btn-quiet" onClick={onReset}>
              <ResetIcon /> Reset
            </button>
          </div>
        </div>

        <div className="min-w-0 rounded-xl border border-white/[0.07] bg-carbon-900/60 p-5">
          <div className="flex items-center justify-between gap-3">
            <p className="eyebrow">Parsed destination</p>
            {a.assumedScheme && (
              <span className="rounded-full border border-white/15 px-2 py-0.5 text-[11px] text-white/55">https:// assumed</span>
            )}
          </div>
          <p className="mono mt-3 break-all rounded-lg bg-black/25 px-3 py-2.5 text-white/70">{p.href}</p>
          <dl className="mt-5 grid grid-cols-2 gap-x-6 gap-y-4">
            <Field label="Scheme" value={p.scheme} />
            <Field label="Port" value={p.port || p.effectivePort} hint={p.port ? 'explicit' : p.effectivePort ? 'default' : undefined} />
            <Field
              label="Actual hostname"
              value={p.displayHost}
              hint={[hostTypeHint[p.hostType], p.displayHost !== p.hostname ? `= ${p.hostname}` : ''].filter(Boolean).join(' · ')}
              wide
            />
            {p.hostType === 'domain' && p.registrable !== p.hostname && (
              <Field label="Registered domain" value={p.registrable} wide />
            )}
            {(p.username || p.hasPassword) && (
              <Field label="Userinfo (ignored for routing)" value={`${p.username}${p.hasPassword ? ':****' : ''}`} wide />
            )}
            <Field label="Path" value={p.path} wide />
            {p.query && <Field label="Query" value={p.query} wide />}
            {p.fragment && <Field label="Fragment" value={p.fragment} wide />}
          </dl>
        </div>
      </div>
    </section>
  );
}
