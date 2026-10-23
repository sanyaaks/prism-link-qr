import { useEffect, useRef, useState, type ReactNode } from 'react';
import type { Severity, Verdict } from '../analyzer/types';
import { copyText } from '../lib/clipboard';

export const VERDICT_STYLE: Record<
  Verdict,
  { text: string; bg: string; border: string; dot: string; bar: string; tagline: string }
> = {
  Safe: {
    text: 'text-verdict-safe',
    bg: 'bg-verdict-safe/10',
    border: 'border-verdict-safe/30',
    dot: 'bg-verdict-safe',
    bar: 'bg-verdict-safe',
    tagline: 'No risk signals from local rules',
  },
  Review: {
    text: 'text-verdict-review',
    bg: 'bg-verdict-review/10',
    border: 'border-verdict-review/30',
    dot: 'bg-verdict-review',
    bar: 'bg-verdict-review',
    tagline: 'Verify before opening',
  },
  Suspicious: {
    text: 'text-verdict-suspicious',
    bg: 'bg-verdict-suspicious/10',
    border: 'border-verdict-suspicious/30',
    dot: 'bg-verdict-suspicious',
    bar: 'bg-verdict-suspicious',
    tagline: 'Deceptive or dangerous signals',
  },
};

export function VerdictPill({ verdict, size = 'sm' }: { verdict: Verdict | 'Error'; size?: 'sm' | 'xs' }) {
  const s =
    verdict === 'Error'
      ? { text: 'text-white/60', bg: 'bg-white/5', border: 'border-white/15', dot: 'bg-white/40' }
      : VERDICT_STYLE[verdict];
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full border ${s.border} ${s.bg} ${s.text} ${
        size === 'xs' ? 'px-2 py-0.5 text-[11px]' : 'px-2.5 py-1 text-xs'
      } font-medium`}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot}`} aria-hidden />
      {verdict}
    </span>
  );
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-verdict-suspicious text-midnight-950',
  high: 'border border-verdict-suspicious/50 text-verdict-suspicious',
  medium: 'border border-verdict-review/50 text-verdict-review',
  low: 'border border-white/20 text-white/60',
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${SEVERITY_STYLE[severity]}`}
    >
      {severity}
    </span>
  );
}

export function CopyButton({
  text,
  label = 'Copy',
  className = 'btn-ghost',
}: {
  text: string | (() => string);
  label?: string;
  className?: string;
}) {
  const [state, setState] = useState<'idle' | 'copied' | 'failed'>('idle');
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <button
      type="button"
      className={className}
      onClick={async () => {
        const ok = await copyText(typeof text === 'function' ? text() : text);
        setState(ok ? 'copied' : 'failed');
        window.clearTimeout(timer.current);
        timer.current = window.setTimeout(() => setState('idle'), 1800);
      }}
    >
      <CopyIcon />
      <span aria-live="polite">{state === 'copied' ? 'Copied' : state === 'failed' ? 'Copy failed' : label}</span>
    </button>
  );
}

/** Button for an async export with loading and error feedback. */
export function AsyncButton({
  onRun,
  label,
  busyLabel,
  className = 'btn-ghost',
  disabled,
  icon,
}: {
  onRun: () => Promise<string | void>;
  label: string;
  busyLabel: string;
  className?: string;
  disabled?: boolean;
  icon?: ReactNode;
}) {
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'error'>('idle');
  const [msg, setMsg] = useState('');
  const timer = useRef<number>();
  useEffect(() => () => window.clearTimeout(timer.current), []);
  return (
    <span className="inline-flex flex-col">
      <button
        type="button"
        className={className}
        disabled={disabled || state === 'busy'}
        aria-busy={state === 'busy'}
        onClick={async () => {
          setState('busy');
          setMsg('');
          try {
            const out = await onRun();
            setState('done');
            setMsg(out ? `Saved ${out}` : 'Done');
          } catch (e) {
            setState('error');
            setMsg(e instanceof Error ? `Failed: ${e.message}` : 'Failed to generate the file.');
          }
          window.clearTimeout(timer.current);
          timer.current = window.setTimeout(() => setState('idle'), 4000);
        }}
      >
        {icon}
        {state === 'busy' ? busyLabel : label}
      </button>
      <span aria-live="polite" className={`mt-1 text-[11px] ${state === 'error' ? 'text-verdict-review' : 'text-white/45'}`}>
        {state === 'done' || state === 'error' ? msg : ''}
      </span>
    </span>
  );
}

export const DownloadIcon = () => (
  <svg width={16} height={16} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} strokeLinecap="round" strokeLinejoin="round" aria-hidden>
    <path d="M12 3v12M7 10l5 5 5-5M5 21h14" />
  </svg>
);

export function SectionHeading({ eyebrow, title, children }: { eyebrow: string; title: ReactNode; children?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-col gap-3 sm:flex-row sm:items-end sm:justify-between">
      <div>
        <p className="eyebrow">{eyebrow}</p>
        <h2 className="mt-2 font-serif text-3xl leading-tight sm:text-4xl">{title}</h2>
      </div>
      {children}
    </div>
  );
}

// ---------------------------------------------------------------------------
// Icons (inline, 1.5px stroke)
// ---------------------------------------------------------------------------

const base = {
  width: 16,
  height: 16,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.7,
  strokeLinecap: 'round' as const,
  strokeLinejoin: 'round' as const,
  'aria-hidden': true,
};

export const CopyIcon = () => (
  <svg {...base}>
    <rect x="9" y="9" width="11" height="11" rx="2" />
    <path d="M5 15V5a2 2 0 0 1 2-2h8" />
  </svg>
);
export const ArrowRight = ({ size = 16 }: { size?: number }) => (
  <svg {...base} width={size} height={size}>
    <path d="M5 12h14M13 6l6 6-6 6" />
  </svg>
);
export const ArrowLeft = () => (
  <svg {...base}>
    <path d="M19 12H5M11 6l-6 6 6 6" />
  </svg>
);
export const ResetIcon = () => (
  <svg {...base}>
    <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
    <path d="M3 3v5h5" />
  </svg>
);
export const CloseIcon = ({ size = 16 }: { size?: number }) => (
  <svg {...base} width={size} height={size}>
    <path d="M6 6l12 12M18 6L6 18" />
  </svg>
);
export const GridIcon = () => (
  <svg {...base}>
    <rect x="3" y="3" width="7" height="7" rx="1.5" />
    <rect x="14" y="3" width="7" height="7" rx="1.5" />
    <rect x="3" y="14" width="7" height="7" rx="1.5" />
    <rect x="14" y="14" width="7" height="7" rx="1.5" />
  </svg>
);
export const CheckIcon = () => (
  <svg {...base} width={14} height={14}>
    <path d="M5 12.5l4.5 4.5L19 7" />
  </svg>
);
export const CrossIcon = () => (
  <svg {...base} width={14} height={14}>
    <path d="M7 7l10 10M17 7L7 17" />
  </svg>
);
export const FlaskIcon = () => (
  <svg {...base}>
    <path d="M9 3h6M10 3v6l-5 9a2 2 0 0 0 1.8 3h10.4A2 2 0 0 0 19 18l-5-9V3" />
    <path d="M7.5 15h9" />
  </svg>
);

export function VerdictGlyph({ verdict, className = '' }: { verdict: Verdict; className?: string }) {
  const p = { ...base, width: 22, height: 22, className };
  if (verdict === 'Safe')
    return (
      <svg {...p}>
        <path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6z" />
        <path d="M8.5 12l2.5 2.5 4.5-5" />
      </svg>
    );
  if (verdict === 'Review')
    return (
      <svg {...p}>
        <circle cx="12" cy="12" r="9" />
        <path d="M12 7.5v5.5M12 16.5h.01" />
      </svg>
    );
  return (
    <svg {...p}>
      <path d="M10.3 3.9L2.4 17.6A2 2 0 0 0 4.1 20.6h15.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z" />
      <path d="M12 9v4.5M12 17h.01" />
    </svg>
  );
}
