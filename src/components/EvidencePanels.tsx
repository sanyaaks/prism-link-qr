import type { ReactNode } from 'react';
import type { Transparency } from '../analyzer/transparency';
import { EVIDENCE_LABEL } from '../analyzer/transparency';
import { CheckIcon, SeverityBadge } from './ui';

export function RedirectPanel({ t }: { t: Transparency }) {
  const r = t.redirect;
  if (!r) return null;
  const rows: [string, ReactNode, string][] = [
    ['Visible hostname', <span className="mono text-pulse">{r.visibleHost}</span>, 'observed'],
    ['What PRISM detected', `This link uses ${r.service}, a recognized URL-shortening service (rule PR-04).`, 'observed'],
    [
      'What this means',
      'The visible URL does not reveal where you will end up. Short links can redirect to legitimate or malicious sites; using one is not proof of either.',
      'observed',
    ],
    [
      'Cannot be determined offline',
      'The final destination, how many redirects happen on the way, and what the eventual page contains. PRISM made no network request.',
      'unknown',
    ],
    ['Recommendation', 'Verify the destination with a trusted link-preview tool or ask the sender for the full URL before opening it.', 'advice'],
  ];
  return (
    <section aria-labelledby="redirect-heading" className="card p-6 sm:p-8">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p id="redirect-heading" className="eyebrow">
          Redirect transparency
        </p>
        <span className="rounded-full border border-white/15 px-2 py-0.5 text-[11px] text-white/55">No redirects followed</span>
      </div>
      <div className="mt-5 grid items-center gap-4 md:grid-cols-[1fr_auto_1fr]">
        <div className="min-w-0">
          <p className="text-xs text-white/45">Visible link</p>
          <p className="mono mt-1 break-all text-lg text-white">
            <span className="text-white/40">{r.scheme}://</span>
            <span className="text-pulse">{r.visibleHost}</span>
            <span className="text-white/60">{r.visiblePath}</span>
          </p>
        </div>
        <span className="hidden text-white/30 md:block" aria-hidden>
          ⟶
        </span>
        <div className="min-w-0 md:text-right">
          <p className="text-xs text-white/45">Final destination</p>
          <p className="mt-1 font-serif text-2xl text-white/50">Unknown offline</p>
        </div>
      </div>
      <dl className="mt-6 divide-y divide-white/[0.06] border-t border-white/[0.06]">
        {rows.map(([k, v, kind]) => (
          <div key={k} className="grid gap-1 py-3 sm:grid-cols-[13rem_1fr] sm:gap-4">
            <dt className={`text-xs font-medium uppercase tracking-[0.12em] ${kind === 'unknown' ? 'text-verdict-review' : 'text-white/45'}`}>{k}</dt>
            <dd className="text-sm leading-relaxed text-white/75">{v}</dd>
          </div>
        ))}
      </dl>
    </section>
  );
}

const KIND_STYLE = {
  direct: 'border-verdict-suspicious/40 text-verdict-suspicious',
  ambiguous: 'border-verdict-review/40 text-verdict-review',
  hygiene: 'border-white/20 text-white/60',
} as const;

export function EvidencePanel({ t, verdict }: { t: Transparency; verdict: string }) {
  return (
    <section aria-labelledby="evidence-heading" className="card p-6 sm:p-8">
      <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
        <div>
          <p className="eyebrow">Evidence &amp; limits</p>
          <h3 id="evidence-heading" className="mt-2 font-serif text-2xl">
            What PRISM can and cannot conclude
          </h3>
        </div>
        <p className="text-xs text-white/40">No confidence percentage is shown: the rules are deterministic, not calibrated.</p>
      </div>

      <p
        className={`mt-5 rounded-xl border px-4 py-3 text-sm leading-relaxed ${
          verdict === 'Safe' ? 'border-pulse/30 bg-pulse/[0.05] text-white/85' : 'border-white/10 bg-white/[0.02] text-white/75'
        }`}
      >
        {verdict === 'Safe' && <strong className="mr-1 text-pulse">No suspicious rule matched ≠ verified safe.</strong>}
        {t.conclusion}
      </p>

      {t.evidence.length > 0 && (
        <div className="mt-6">
          <p className="text-xs font-medium uppercase tracking-[0.12em] text-white/45">Strength of each signal</p>
          <ul className="mt-3 space-y-2">
            {t.evidence.map(({ finding, kind }, i) => (
              <li key={i} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-xs text-pulse">{finding.ruleId}</span>
                <SeverityBadge severity={finding.severity} />
                <span className={`rounded-full border px-2 py-0.5 text-[11px] ${KIND_STYLE[kind]}`} title={EVIDENCE_LABEL[kind].meaning}>
                  {EVIDENCE_LABEL[kind].label}
                </span>
                <span className="min-w-0 text-white/70">{finding.title}</span>
              </li>
            ))}
          </ul>
          <p className="mt-3 text-xs text-white/40">
            Direct = the link is built to mislead or execute. Ambiguous = common in attacks but also legitimate. Hygiene =
            weakens protection without deceiving.
          </p>
        </div>
      )}

      <div className="mt-6 grid gap-6 md:grid-cols-2">
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.12em] text-white/45">Observed in the URL</p>
          <ul className="mt-3 space-y-2">
            {t.observed.map((o) => (
              <li key={o} className="flex gap-2 text-sm text-white/75">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-pulse/15 text-pulse">
                  <CheckIcon />
                </span>
                <span className="min-w-0 break-words">{o}</span>
              </li>
            ))}
          </ul>
        </div>
        <div>
          <p className="text-xs font-medium uppercase tracking-[0.12em] text-verdict-review">Cannot be determined offline</p>
          <ul className="mt-3 space-y-2">
            {t.unknown.map((u) => (
              <li key={u} className="flex gap-2 text-sm text-white/65">
                <span className="mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full bg-verdict-review/15 text-[10px] font-semibold text-verdict-review" aria-hidden>
                  ?
                </span>
                <span className="min-w-0 break-words">{u}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      <div className="mt-6">
        <p className="text-xs font-medium uppercase tracking-[0.12em] text-white/45">
          Rules checked but not triggered ({t.notTriggered.length})
        </p>
        <ul className="mt-3 flex flex-wrap gap-1.5">
          {t.notTriggered.map((r) => (
            <li key={r.id} className="rounded-full border border-white/10 px-2.5 py-1 text-[11px] text-white/50" title={r.summary}>
              <span className="font-mono text-white/70">{r.id}</span> {r.name}
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
