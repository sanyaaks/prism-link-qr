import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { analyze } from './analyzer/analyze';
import { DEFAULT_REFERENCE_DOMAINS } from './analyzer/config';
import { computeFlips } from './analyzer/flip';
import { runMatrix, type MatrixReport } from './analyzer/mutations';
import { explainLimits } from './analyzer/transparency';
import type { AnalysisResult, AnalyzerOptions } from './analyzer/types';
import { AnalyzerForm } from './components/AnalyzerForm';
import { EvidencePanel, RedirectPanel } from './components/EvidencePanels';
import { FindingsList } from './components/FindingsList';
import { FlipPanel } from './components/FlipPanel';
import { MutationMatrix } from './components/MutationMatrix';
import { QrScanner } from './components/QrScanner';
import { ReadsLikePanel } from './components/ReadsLikePanel';
import { VerdictPanel } from './components/VerdictPanel';
import { PrismMark, Wordmark } from './components/Wordmark';
import { ResetIcon } from './components/ui';
import { MANUAL_SOURCE, type InputSource } from './lib/source';

const ANALYSIS_DELAY_MS = 320;
const INPUT_TABS = [
  ['link', 'Paste a link'],
  ['qr', 'Scan a QR image'],
] as const;

function prefersReducedMotion(): boolean {
  return typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
}

function scrollToEl(el: HTMLElement | null) {
  if (!el) return;
  el.scrollIntoView({ behavior: prefersReducedMotion() ? 'auto' : 'smooth', block: 'start' });
}

function safeAnalyze(value: string, options: AnalyzerOptions): AnalysisResult {
  try {
    return analyze(value, options);
  } catch (e) {
    return {
      ok: false,
      input: value,
      error: 'The analyzer hit an unexpected error.',
      hint: e instanceof Error ? e.message : 'Please try a different input.',
    };
  }
}

export default function App() {
  const [input, setInput] = useState('');
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [references, setReferences] = useState<string[]>(DEFAULT_REFERENCE_DOMAINS);
  const [matrix, setMatrix] = useState<MatrixReport | null>(null);
  const [runId, setRunId] = useState(0);
  const [source, setSource] = useState<InputSource>(MANUAL_SOURCE);
  const [mode, setMode] = useState<'link' | 'qr'>('link');
  const [scrolled, setScrolled] = useState(false);
  const [scrollPercent, setScrollPercent] = useState(0);
  const [activeSection, setActiveSection] = useState<'link' | 'qr' | 'matrix'>('link');

  const options = useMemo<AnalyzerOptions>(() => ({ referenceDomains: references }), [references]);
  const optionsRef = useRef(options);
  optionsRef.current = options;

  const inputRef = useRef<HTMLInputElement>(null);
  const resultsRef = useRef<HTMLDivElement>(null);
  const matrixRef = useRef<HTMLDivElement>(null);
  const timer = useRef<number>();

  useEffect(() => () => window.clearTimeout(timer.current), []);

  const run = useCallback(
    (value: string, opts: { fromLink?: boolean; source?: InputSource } = {}) => {
      if (!value.trim()) {
        inputRef.current?.focus();
        return;
      }
      window.clearTimeout(timer.current);
      if (opts.fromLink && result?.ok && result.input.trim() !== value.trim()) {
        setHistory((h) => [...h, result.input].slice(-20));
      }
      setInput(value);
      setBusy(true);
      setMatrix(null);
      requestAnimationFrame(() => scrollToEl(resultsRef.current));
      timer.current = window.setTimeout(() => {
        setResult(safeAnalyze(value, optionsRef.current));
        setSource(opts.source ?? MANUAL_SOURCE);
        setRunId((n) => n + 1);
        setBusy(false);
      }, ANALYSIS_DELAY_MS);
    },
    [result],
  );

  const reset = useCallback(() => {
    window.clearTimeout(timer.current);
    setInput('');
    setResult(null);
    setBusy(false);
    setHistory([]);
    setMatrix(null);
    setSource(MANUAL_SOURCE);
    window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
    inputRef.current?.focus();
  }, []);

  const goBack = useCallback(() => {
    const prev = history[history.length - 1];
    if (prev === undefined) return;
    setHistory((h) => h.slice(0, -1));
    run(prev);
  }, [history, run]);

  const openMatrix = useCallback(() => {
    setMatrix(runMatrix(result?.ok ? result : null, optionsRef.current));
    requestAnimationFrame(() => scrollToEl(matrixRef.current));
  }, [result]);

  // Re-screen instantly when the reference list changes.
  const firstRender = useRef(true);
  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    setResult((r) => (r ? safeAnalyze(r.input, options) : r));
  }, [options]);

  // Keep a visible matrix in sync with the current analysis and references.
  useEffect(() => {
    setMatrix((m) => (m ? runMatrix(result?.ok ? result : null, options) : m));
  }, [result, options]);

  // "/" focuses the analyzer from anywhere.
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement | null;
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
      if (e.key === '/' && !typing && !e.metaKey && !e.ctrlKey && !e.altKey) {
        e.preventDefault();
        setMode('link');
        requestAnimationFrame(() => {
          inputRef.current?.focus();
          inputRef.current?.select();
        });
      }
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  useEffect(() => {
    const onScroll = () => {
      const y = window.scrollY;
      setScrolled(y > 16);
      const docHeight = document.documentElement.scrollHeight - window.innerHeight;
      setScrollPercent(docHeight > 0 ? Math.min(100, Math.max(0, (y / docHeight) * 100)) : 0);

      const matrixEl = matrixRef.current;
      if (matrixEl) {
        const rect = matrixEl.getBoundingClientRect();
        if (rect.top <= 240) {
          setActiveSection('matrix');
          return;
        }
      }
      setActiveSection(mode === 'qr' ? 'qr' : 'link');
    };

    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
    return () => window.removeEventListener('scroll', onScroll);
  }, [mode]);

  const flips = useMemo(() => (result?.ok ? computeFlips(result, options) : null), [result, options]);
  const limits = useMemo(() => (result?.ok ? explainLimits(result) : null), [result]);

  const openScanner = useCallback(() => {
    setMode('qr');
    requestAnimationFrame(() => scrollToEl(document.getElementById('analyzer')));
  }, []);

  const openLink = useCallback(() => {
    setMode('link');
    requestAnimationFrame(() => {
      scrollToEl(document.getElementById('analyzer'));
      inputRef.current?.focus();
    });
  }, []);

  return (
    <div className="relative min-h-screen">
      <a
        href="#url-input"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-full focus:bg-pulse focus:px-4 focus:py-2 focus:text-midnight-950"
      >
        Skip to analyzer
      </a>

      <header
        className={`sticky top-0 z-40 w-full transition-all duration-300 ${
          scrolled
            ? 'border-b border-white/[0.1] bg-midnight-950/85 py-2.5 shadow-[0_12px_32px_rgba(0,0,0,0.65)] backdrop-blur-xl'
            : 'border-b border-white/[0.05] bg-midnight-950/40 py-3.5 backdrop-blur-md'
        }`}
      >
        <div className="mx-auto flex max-w-6xl items-center justify-between px-4 sm:px-6">
          <a
            href="#top"
            aria-label="PRISM home"
            className="transition-opacity hover:opacity-90"
            onClick={(e) => {
              e.preventDefault();
              window.scrollTo({ top: 0, behavior: prefersReducedMotion() ? 'auto' : 'smooth' });
            }}
          >
            <Wordmark compact />
          </a>

          <nav className="flex items-center gap-2 sm:gap-3" aria-label="Primary">
            <div className="flex items-center rounded-full border border-white/10 bg-white/[0.03] p-1">
              <button
                type="button"
                onClick={openLink}
                className={`rounded-full px-3.5 py-1 text-xs font-medium transition-all ${
                  mode === 'link' && activeSection !== 'matrix'
                    ? 'bg-pulse text-midnight-950 shadow-[0_0_12px_rgba(0,209,178,0.4)]'
                    : 'text-white/65 hover:text-white'
                }`}
              >
                Link
              </button>
              <button
                type="button"
                onClick={openScanner}
                className={`rounded-full px-3.5 py-1 text-xs font-medium transition-all ${
                  mode === 'qr' && activeSection !== 'matrix'
                    ? 'bg-pulse text-midnight-950 shadow-[0_0_12px_rgba(0,209,178,0.4)]'
                    : 'text-white/65 hover:text-white'
                }`}
              >
                QR Scanner
              </button>
              <button
                type="button"
                onClick={() => {
                  if (!matrix) openMatrix();
                  else scrollToEl(matrixRef.current);
                }}
                className={`rounded-full px-3.5 py-1 text-xs font-medium transition-all ${
                  activeSection === 'matrix'
                    ? 'bg-pulse text-midnight-950 shadow-[0_0_12px_rgba(0,209,178,0.4)]'
                    : 'text-white/65 hover:text-white'
                }`}
              >
                Matrix
              </button>
            </div>

            <span className="hidden items-center gap-1.5 rounded-full border border-pulse/25 bg-pulse/[0.04] px-2.5 py-1 text-[11px] font-medium text-pulse sm:inline-flex">
              <span className="relative flex h-1.5 w-1.5">
                <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-pulse opacity-75" />
                <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-pulse" />
              </span>
              Runs locally
            </span>

            {scrolled && result && (
              <button
                type="button"
                onClick={reset}
                className="inline-flex items-center gap-1.5 rounded-full border border-white/15 bg-white/5 px-2.5 py-1 text-xs text-white/70 transition-all hover:border-white/30 hover:bg-white/10 hover:text-white"
                title="Start a new analysis"
              >
                <ResetIcon />
                <span className="hidden md:inline">New scan</span>
              </button>
            )}
          </nav>
        </div>

        {/* Dynamic scroll progress indicator */}
        <div className="absolute inset-x-0 bottom-0 h-[2px] bg-white/[0.03] overflow-hidden" aria-hidden>
          <div
            className="h-full bg-gradient-to-r from-pulse/30 via-pulse to-pulse/30 transition-[width] duration-75 ease-out shadow-[0_0_8px_rgba(0,209,178,0.6)]"
            style={{ width: `${scrollPercent}%` }}
          />
        </div>
      </header>

      <main id="top">
        {/* Hero */}
        <section id="analyzer" className="relative scroll-mt-16">
          <div className="grid-backdrop pointer-events-none absolute inset-0" aria-hidden />
          <div className="relative mx-auto max-w-6xl px-4 pb-14 pt-16 sm:px-6 sm:pb-20 sm:pt-24">
            <p className="eyebrow animate-rise">Explainable QR &amp; link risk screening</p>
            <h1 className="mt-5 max-w-4xl animate-rise font-serif text-[42px] font-medium leading-[1.05] tracking-tight [animation-delay:60ms] sm:text-6xl lg:text-7xl">
              See where a link <em className="text-pulse">really</em> goes.
            </h1>
            <p className="mt-6 max-w-2xl animate-rise text-base leading-relaxed text-white/65 [animation-delay:120ms] sm:text-lg">
              PRISM separates what a URL <span className="text-white">appears</span> to say from where it{' '}
              <span className="text-white">actually</span> points, then explains every signal in plain English. Ten
              transparent rules, run entirely in your browser.
            </p>
            <div className={`mt-10 animate-rise [animation-delay:180ms] ${mode === 'qr' ? 'max-w-5xl' : 'max-w-3xl'}`}>
              <div role="tablist" aria-label="Input type" className="mb-3 inline-flex rounded-full border border-white/10 bg-white/[0.03] p-1">
                {INPUT_TABS.map(([m, label]) => (
                  <button
                    key={m}
                    id={`tab-${m}`}
                    type="button"
                    role="tab"
                    aria-selected={mode === m}
                    aria-controls={`panel-${m}`}
                    tabIndex={mode === m ? 0 : -1}
                    onClick={() => setMode(m)}
                    onKeyDown={(e) => {
                      if (e.key === 'ArrowRight' || e.key === 'ArrowLeft') {
                        e.preventDefault();
                        const next = mode === 'link' ? 'qr' : 'link';
                        setMode(next);
                        requestAnimationFrame(() => document.getElementById(`tab-${next}`)?.focus());
                      }
                    }}
                    className={`rounded-full px-4 py-1.5 text-sm transition ${
                      mode === m ? 'bg-pulse text-midnight-950' : 'text-white/60 hover:text-white'
                    }`}
                  >
                    {label}
                  </button>
                ))}
              </div>
              {mode === 'link' ? (
                <div id="panel-link" role="tabpanel" aria-labelledby="tab-link">
                  <AnalyzerForm
                    ref={inputRef}
                    value={input}
                    busy={busy}
                    onChange={setInput}
                    onSubmit={() => run(input)}
                    onClear={reset}
                    onSample={(u) => run(u, { fromLink: true })}
                  />
                  <p className="mt-4 hidden text-xs text-white/35 sm:block">
                    <kbd className="rounded border border-white/15 px-1.5 font-mono">Enter</kbd> to analyze ·{' '}
                    <kbd className="rounded border border-white/15 px-1.5 font-mono">Esc</kbd> to clear ·{' '}
                    <kbd className="rounded border border-white/15 px-1.5 font-mono">/</kbd> to focus
                  </p>
                </div>
              ) : (
                <div id="panel-qr" role="tabpanel" aria-labelledby="tab-qr">
                  <QrScanner busy={busy} onAnalyze={(value, src) => run(value, { fromLink: true, source: src })} />
                </div>
              )}
            </div>
          </div>
        </section>

        {/* Results */}
        <div ref={resultsRef} className="mx-auto max-w-6xl scroll-mt-20 px-4 sm:px-6" aria-live="polite" aria-busy={busy}>
          {busy ? (
            <div className="card flex items-center gap-4 p-6 sm:p-8" role="status">
              <PrismMark size={32} />
              <div className="flex-1">
                <p className="text-sm text-white/80">Parsing and running 10 local rules…</p>
                <div className="mt-3 h-px overflow-hidden bg-white/10">
                  <div className="h-full w-1/3 animate-beam bg-pulse" />
                </div>
              </div>
            </div>
          ) : !result ? (
            <div className="card grid gap-6 p-6 sm:grid-cols-3 sm:p-8">
              {[
                ['01', 'A verdict you can audit', 'Safe, Review or Suspicious, with every triggered rule, its severity and why.'],
                ['02', 'Reads like vs. goes to', 'The hostname a link pretends to reference, set against its parsed destination.'],
                ['03', 'What would flip it', 'The smallest edit that changes the outcome, re-checked by the same analyzer.'],
              ].map(([n, t, d]) => (
                <div key={n}>
                  <p className="font-mono text-xs text-pulse">{n}</p>
                  <p className="mt-2 font-serif text-xl">{t}</p>
                  <p className="mt-1.5 text-sm leading-relaxed text-white/55">{d}</p>
                </div>
              ))}
            </div>
          ) : !result.ok ? (
            <div role="alert" className="card animate-rise border-verdict-review/30 p-6 sm:p-8">
              <p className="eyebrow text-verdict-review">Could not analyze</p>
              <p className="mt-3 font-serif text-3xl">{result.error}</p>
              <p className="mt-2 text-sm text-white/60">{result.hint}</p>
              {result.input.trim() && (
                <p className="mono mt-4 break-all rounded-lg bg-black/25 px-3 py-2 text-white/50">{result.input}</p>
              )}
              <div className="mt-5 flex gap-2">
                <button type="button" className="btn-ghost" onClick={() => inputRef.current?.focus()}>
                  Edit input
                </button>
                <button type="button" className="btn-quiet" onClick={reset}>
                  <ResetIcon /> Reset
                </button>
              </div>
            </div>
          ) : (
            <div key={runId} className="flex flex-col gap-5">
              <div className="animate-rise">
                <VerdictPanel
                  analysis={result}
                  source={source}
                  options={options}
                  canGoBack={history.length > 0}
                  onBack={goBack}
                  onReset={reset}
                  onMatrix={openMatrix}
                />
              </div>
              {result.readsLike && (
                <div className="animate-rise [animation-delay:80ms]">
                  <ReadsLikePanel data={result.readsLike} />
                </div>
              )}
              {limits?.redirect && (
                <div className="animate-rise [animation-delay:100ms]">
                  <RedirectPanel t={limits} />
                </div>
              )}
              <div className="grid animate-rise gap-5 [animation-delay:140ms] lg:grid-cols-[minmax(0,7fr)_minmax(0,5fr)]">
                <FindingsList analysis={result} />
                {flips && <FlipPanel report={flips} input={result.input} onTest={(u) => run(u, { fromLink: true })} />}
              </div>
              {limits && (
                <div className="animate-rise [animation-delay:200ms]">
                  <EvidencePanel t={limits} verdict={result.verdict} />
                </div>
              )}
            </div>
          )}
        </div>

        <div ref={matrixRef} className="mx-auto mt-24 max-w-6xl scroll-mt-20 px-4 sm:px-6">
          <MutationMatrix
            report={matrix}
            onRun={openMatrix}
            onAnalyze={(u) => run(u, { fromLink: true })}
            onAddReference={(d) => setReferences((r) => (r.includes(d) ? r : [...r, d]))}
          />
        </div>
      </main>

      <footer className="mt-28 border-t border-white/[0.06]">
        <div className="mx-auto flex max-w-6xl flex-col gap-4 px-4 py-10 text-xs text-white/40 sm:flex-row sm:items-center sm:justify-between sm:px-6">
          <Wordmark compact />
          <p className="max-w-xl leading-relaxed">
            Local, rule-based screening of link text. PRISM does not open links, follow redirects or verify websites,
            and a Safe verdict is not a guarantee.
          </p>
        </div>
      </footer>
    </div>
  );
}
