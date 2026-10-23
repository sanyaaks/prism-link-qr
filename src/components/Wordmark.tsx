/** PRISM wordmark: a hairline prism splitting a white beam into a cyan signal. */
export function PrismMark({ size = 28, animated = false }: { size?: number; animated?: boolean }) {
  return (
    <svg width={size} height={size} viewBox="0 0 32 32" fill="none" aria-hidden>
      <path d="M2 18.5 L12.6 16.4" stroke="#FFFFFF" strokeOpacity="0.85" strokeWidth="1.3" strokeLinecap="round" />
      <path d="M16 5 L26.5 24.5 H5.5 Z" stroke="#FFFFFF" strokeWidth="1.5" strokeLinejoin="round" />
      <path
        d="M19.4 14.8 L30 10.5"
        stroke="#00D1B2"
        strokeWidth="1.6"
        strokeLinecap="round"
        className={animated ? 'origin-left animate-[fade_1.2s_ease-out_both]' : undefined}
      />
      <path d="M19.4 15.6 L30 14.2" stroke="#00D1B2" strokeOpacity="0.45" strokeWidth="1.1" strokeLinecap="round" />
    </svg>
  );
}

export function Wordmark({ compact = false }: { compact?: boolean }) {
  return (
    <span className="inline-flex items-center gap-2.5">
      <PrismMark size={compact ? 24 : 28} />
      <span className="font-serif text-[22px] font-semibold tracking-[0.18em] text-signal">PRISM</span>
    </span>
  );
}
