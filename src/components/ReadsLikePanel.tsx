import type { ReadsLike, Segment } from '../analyzer/types';
import { ArrowRight } from './ui';

const TONE: Record<Segment['tone'], string> = {
  muted: 'text-white/35',
  plain: 'text-white/60',
  deceptive: 'text-verdict-suspicious line-through decoration-verdict-suspicious/80 decoration-2 bg-verdict-suspicious/10 rounded-sm px-0.5',
  actual: 'text-pulse font-medium',
};

export function SegmentStrip({ segments }: { segments: Segment[] }) {
  return (
    <p className="mono break-all text-[14px] sm:text-[15px]">
      {segments.map((s, i) =>
        s.tone === 'deceptive' ? (
          <del key={i} className={TONE.deceptive}>
            {s.text}
          </del>
        ) : (
          <span key={i} className={TONE[s.tone]}>
            {s.text}
          </span>
        ),
      )}
    </p>
  );
}

export function ReadsLikePanel({ data }: { data: ReadsLike }) {
  return (
    <section aria-labelledby="reads-like-heading" className="card relative overflow-hidden p-6 sm:p-8">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p id="reads-like-heading" className="eyebrow">
          Reads like vs. actually goes to
        </p>
        <span className="font-mono text-[11px] text-white/40">{data.ruleId}</span>
      </div>

      <div className="mt-6 grid items-center gap-6 md:grid-cols-[1fr_auto_1fr]">
        <div className="min-w-0">
          <p className="text-xs text-white/45">{data.appearsLabel}</p>
          <p className="mt-2 break-all font-serif text-3xl text-verdict-suspicious line-through decoration-verdict-suspicious/70 decoration-2 sm:text-4xl">
            {data.appears}
          </p>
        </div>
        <div className="flex justify-center text-white/30 md:px-2" aria-hidden>
          <span className="rotate-90 md:rotate-0">
            <ArrowRight size={28} />
          </span>
        </div>
        <div className="min-w-0 md:text-right">
          <p className="text-xs text-white/45">{data.actualLabel}</p>
          <p className="mt-2 break-all font-serif text-3xl text-pulse sm:text-4xl">{data.actual}</p>
        </div>
      </div>

      <div className="mt-7 rounded-xl border border-white/[0.07] bg-black/25 px-4 py-3">
        <SegmentStrip segments={data.segments} />
      </div>
      <p className="mt-3 text-sm text-white/55">
        {data.note} <span className="text-white/35">PRISM does not follow redirects; this is the parsed host only.</span>
      </p>
    </section>
  );
}
