import { forwardRef } from 'react';
import { SAMPLES, type Sample } from '../analyzer/samples';
import { ArrowRight, CloseIcon } from './ui';

interface Props {
  value: string;
  busy: boolean;
  onChange: (v: string) => void;
  onSubmit: () => void;
  onClear: () => void;
  onSample: (url: string) => void;
}

const KIND_DOT: Record<Sample['kind'], string> = {
  ordinary: 'bg-verdict-safe',
  deceptive: 'bg-verdict-suspicious',
  ambiguous: 'bg-verdict-review',
};

export const AnalyzerForm = forwardRef<HTMLInputElement, Props>(function AnalyzerForm(
  { value, busy, onChange, onSubmit, onClear, onSample },
  ref,
) {
  return (
    <div className="w-full">
      <form
        role="search"
        aria-label="Analyze a link"
        onSubmit={(e) => {
          e.preventDefault();
          onSubmit();
        }}
        className="group relative flex flex-col gap-2 rounded-2xl border border-white/[0.12] bg-midnight-900/80 p-2 shadow-[0_20px_60px_-30px_rgba(0,0,0,0.8)] backdrop-blur transition-colors focus-within:border-pulse/60 sm:flex-row sm:items-center"
      >
        <label htmlFor="url-input" className="sr-only">
          Link or QR code URL
        </label>
        <div className="relative flex min-w-0 flex-1 items-center">
          <span className="pointer-events-none pl-3 pr-2 font-mono text-xs text-white/35 sm:pl-4" aria-hidden>
            URL
          </span>
          <input
            ref={ref}
            id="url-input"
            type="text"
            inputMode="url"
            autoComplete="off"
            autoCapitalize="off"
            autoCorrect="off"
            spellCheck={false}
            placeholder="Paste a link or decoded QR content…"
            value={value}
            onChange={(e) => onChange(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Escape' && value) {
                e.preventDefault();
                onClear();
              }
            }}
            className="h-12 min-w-0 flex-1 bg-transparent pr-10 font-mono text-[15px] text-signal placeholder:font-sans placeholder:text-white/35 focus:outline-none focus-visible:outline-none"
          />
          {value && (
            <button
              type="button"
              onClick={onClear}
              aria-label="Clear input and results"
              title="Clear (Esc)"
              className="absolute right-1 rounded-full p-2 text-white/40 transition hover:bg-white/10 hover:text-white"
            >
              <CloseIcon />
            </button>
          )}
        </div>
        <button type="submit" className="btn-primary h-12 px-6 text-[15px]" disabled={busy || !value.trim()}>
          {busy ? 'Analyzing…' : 'Analyze'}
          {!busy && <ArrowRight />}
        </button>
      </form>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="mr-1 text-xs text-white/40">Try a sample:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.url}
            type="button"
            onClick={() => onSample(s.url)}
            title={s.url}
            className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-white/70 transition hover:border-white/25 hover:bg-white/[0.06] hover:text-white"
          >
            <span className={`h-1.5 w-1.5 rounded-full ${KIND_DOT[s.kind]}`} aria-hidden />
            {s.label}
            <span className="sr-only">({s.kind} sample)</span>
          </button>
        ))}
      </div>
    </div>
  );
});
