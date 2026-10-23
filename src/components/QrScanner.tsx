import { useCallback, useEffect, useRef, useState } from 'react';
import { classifyQrContent, type QrContent } from '../qr/classify';
import { decodeQrImage, QR_ACCEPT, QR_MAX_BYTES } from '../qr/decodeImage';
import type { InputSource } from '../lib/source';
import { ArrowRight, CloseIcon } from './ui';

const SAMPLES: { file: string; label: string; tone: string }[] = [
  { file: 'campus-portal.png', label: 'Campus poster', tone: 'bg-verdict-safe' },
  { file: 'at-disguise.png', label: '@ disguise', tone: 'bg-verdict-suspicious' },
  { file: 'short-link.png', label: 'Short link', tone: 'bg-verdict-review' },
  { file: 'script-link.png', label: 'Script link', tone: 'bg-verdict-suspicious' },
  { file: 'wifi.png', label: 'Wi-Fi code', tone: 'bg-white/50' },
  { file: 'plain-text.png', label: 'Plain text', tone: 'bg-white/50' },
];

type Status = 'idle' | 'decoding' | 'decoded' | 'error';

/** Render hidden/control characters as visible markers. React escapes the rest. */
function withVisibleHidden(s: string) {
  const parts: (string | JSX.Element)[] = [];
  let buf = '';
  let k = 0;
  for (const ch of Array.from(s)) {
    const cp = ch.codePointAt(0) ?? 0;
    const hidden =
      (cp < 0x20 && ch !== '\n') || cp === 0x7f || cp === 0xad || (cp >= 0x200b && cp <= 0x200f) || (cp >= 0x202a && cp <= 0x202e) || (cp >= 0x2060 && cp <= 0x2069) || cp === 0xfeff;
    if (!hidden) {
      buf += ch;
      continue;
    }
    if (buf) parts.push(buf);
    buf = '';
    parts.push(
      <span key={k++} className="mx-0.5 rounded bg-verdict-review/20 px-1 text-[10px] text-verdict-review" title="Hidden character">
        U+{cp.toString(16).toUpperCase().padStart(4, '0')}
      </span>,
    );
  }
  if (buf) parts.push(buf);
  return parts;
}

interface Props {
  onAnalyze: (value: string, source: InputSource) => void;
  busy: boolean;
}

export function QrScanner({ onAnalyze, busy }: Props) {
  const [file, setFile] = useState<File | null>(null);
  const [preview, setPreview] = useState<string | null>(null);
  const [status, setStatus] = useState<Status>('idle');
  const [error, setError] = useState('');
  const [content, setContent] = useState<QrContent | null>(null);
  const [dims, setDims] = useState<{ width: number; height: number } | null>(null);
  const [dragging, setDragging] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);
  const job = useRef(0);

  // Revoke the preview object URL whenever it is replaced or the scanner unmounts.
  useEffect(() => () => {
    if (preview) URL.revokeObjectURL(preview);
  }, [preview]);

  const reset = useCallback(() => {
    job.current++;
    setFile(null);
    setPreview(null);
    setStatus('idle');
    setError('');
    setContent(null);
    setDims(null);
    if (inputRef.current) inputRef.current.value = '';
  }, []);

  const handleFile = useCallback(async (f: File) => {
    const id = ++job.current;
    setFile(f);
    setContent(null);
    setDims(null);
    setError('');
    setStatus('decoding');
    setPreview(f.type.startsWith('image/') || /\.(png|jpe?g|webp|gif|bmp)$/i.test(f.name) ? URL.createObjectURL(f) : null);
    try {
      const { text, width, height } = await decodeQrImage(f);
      if (id !== job.current) return;
      setContent(classifyQrContent(text));
      setDims({ width, height });
      setStatus('decoded');
    } catch (e) {
      if (id !== job.current) return;
      setError(e instanceof Error ? e.message : 'The image could not be decoded.');
      setStatus('error');
    }
  }, []);

  const loadSample = useCallback(
    async (name: string) => {
      try {
        // Same-origin static asset bundled with the app; no external request.
        const res = await fetch(`${import.meta.env.BASE_URL}qr-samples/${name}`);
        if (!res.ok) throw new Error();
        const blob = await res.blob();
        await handleFile(new File([blob], name, { type: 'image/png' }));
      } catch {
        setError('The sample image could not be loaded.');
        setStatus('error');
      }
    },
    [handleFile],
  );

  // Allow pasting an image from the clipboard while the scanner is visible.
  useEffect(() => {
    const onPaste = (e: ClipboardEvent) => {
      const item = [...(e.clipboardData?.files ?? [])].find((f) => f.type.startsWith('image/'));
      if (item) {
        e.preventDefault();
        void handleFile(item);
      }
    };
    window.addEventListener('paste', onPaste);
    return () => window.removeEventListener('paste', onPaste);
  }, [handleFile]);

  const submit = () => {
    if (!content?.analyzable || !file) return;
    onAnalyze(content.analyzable, { kind: 'qr', fileName: file.name, decoded: content.display, contentLabel: content.label });
  };

  const actionLabel =
    content?.kind === 'web-url' || content?.kind === 'schemeless-url' ? 'Analyze decoded link' : 'Run rule check (will not open it)';

  return (
    <div className="w-full">
      <div className="grid gap-4 md:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        {/* Drop zone / preview */}
        <div
          onDragOver={(e) => {
            e.preventDefault();
            setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDragging(false);
            const f = e.dataTransfer.files[0];
            if (f) void handleFile(f);
          }}
          className={`relative flex min-h-[220px] flex-col items-center justify-center overflow-hidden rounded-2xl border border-dashed bg-midnight-900/80 p-4 text-center transition-colors ${
            dragging ? 'border-pulse bg-pulse/5' : 'border-white/20'
          }`}
        >
          {preview ? (
            <>
              <img src={preview} alt={`Uploaded QR image ${file?.name ?? ''}`} className="max-h-48 rounded-lg bg-white object-contain p-1" />
              <p className="mt-3 max-w-full truncate text-xs text-white/50">
                {file?.name} · {file ? (file.size / 1024).toFixed(1) : 0} KB{dims ? ` · ${dims.width}×${dims.height}px` : ''}
              </p>
            </>
          ) : (
            <>
              <svg width="40" height="40" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.4" className="text-white/40" aria-hidden>
                <rect x="3" y="3" width="6" height="6" rx="1" />
                <rect x="15" y="3" width="6" height="6" rx="1" />
                <rect x="3" y="15" width="6" height="6" rx="1" />
                <path d="M15 15h2v2h-2zM19 19h2v2h-2zM15 19h2M19 15h2" />
              </svg>
              <p className="mt-3 text-sm text-white/75">Drop a QR image here, paste it, or</p>
            </>
          )}
          <div className="mt-3 flex flex-wrap justify-center gap-2">
            <label className="btn-ghost cursor-pointer focus-within:outline focus-within:outline-2 focus-within:outline-offset-2 focus-within:outline-pulse">
              {preview ? 'Choose another image' : 'Choose image'}
              <input
                ref={inputRef}
                type="file"
                accept={QR_ACCEPT.join(',')}
                className="sr-only"
                aria-describedby="qr-help"
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void handleFile(f);
                }}
              />
            </label>
            {file && preview && (
              <a href={preview} download={file.name} className="btn-quiet">
                Download
              </a>
            )}
            {file && (
              <button type="button" className="btn-quiet" onClick={reset}>
                <CloseIcon size={14} /> Remove
              </button>
            )}
          </div>
          <p id="qr-help" className="mt-3 text-[11px] text-white/35">
            PNG, JPEG, WebP, GIF or BMP up to {QR_MAX_BYTES / 1024 / 1024} MB. Decoded in your browser; never uploaded.
          </p>
        </div>

        {/* Decoded content */}
        <div className="flex min-w-0 flex-col rounded-2xl border border-white/[0.12] bg-midnight-900/80 p-5" aria-live="polite">
          {status === 'idle' && (
            <div className="my-auto text-sm leading-relaxed text-white/60">
              <p className="font-serif text-xl text-white">QR codes hide their destination.</p>
              <p className="mt-2">
                A printed code on a poster or handout shows nothing about where it leads. PRISM decodes it locally so you can
                read what it contains before your phone opens it. Decoding reveals the contents; it does not make them
                trustworthy.
              </p>
            </div>
          )}
          {status === 'decoding' && (
            <div className="my-auto" role="status">
              <p className="text-sm text-white/80">Decoding locally…</p>
              <div className="mt-3 h-px overflow-hidden bg-white/10">
                <div className="h-full w-1/3 animate-beam bg-pulse" />
              </div>
            </div>
          )}
          {status === 'error' && (
            <div role="alert" className="my-auto">
              <p className="eyebrow text-verdict-review">Could not decode</p>
              <p className="mt-2 text-sm text-white/80">{error}</p>
            </div>
          )}
          {status === 'decoded' && content && (
            <div className="flex min-w-0 flex-1 flex-col animate-fade">
              <div className="flex flex-wrap items-center gap-2">
                <p className="eyebrow">Decoded content</p>
                <span
                  className={`rounded-full px-2 py-0.5 text-[11px] font-medium ${
                    content.kind === 'web-url'
                      ? 'bg-pulse/15 text-pulse'
                      : content.kind === 'dangerous-scheme'
                        ? 'bg-verdict-suspicious/15 text-verdict-suspicious'
                        : 'bg-white/10 text-white/70'
                  }`}
                >
                  {content.label}
                </span>
                <span className="ml-auto font-mono text-[11px] text-white/40">{Array.from(content.raw).length} chars</span>
              </div>
              <pre className="mono mt-3 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded-lg bg-black/30 px-3 py-2.5 text-white/90">
                {withVisibleHidden(content.display)}
              </pre>
              {content.hiddenChars > 0 && (
                <p className="mt-2 text-xs text-verdict-review">
                  Contains {content.hiddenChars} hidden character{content.hiddenChars > 1 ? 's' : ''}, shown as U+ markers.
                </p>
              )}
              <p className="mt-3 text-sm leading-relaxed text-white/65">{content.explanation}</p>
              <div className="mt-auto pt-4">
                {content.analyzable ? (
                  <button type="button" className="btn-primary" onClick={submit} disabled={busy}>
                    {actionLabel} <ArrowRight />
                  </button>
                ) : (
                  <p className="text-xs text-white/45">No verdict: this content is not a link.</p>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="mt-4 flex flex-wrap items-center gap-2">
        <span className="mr-1 text-xs text-white/40">Sample QR images:</span>
        {SAMPLES.map((s) => (
          <button
            key={s.file}
            type="button"
            onClick={() => void loadSample(s.file)}
            className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.03] px-3 py-1.5 text-xs text-white/70 transition hover:border-white/25 hover:bg-white/[0.06] hover:text-white"
          >
            <span className={`h-1.5 w-1.5 rounded-full ${s.tone}`} aria-hidden />
            {s.label}
          </button>
        ))}
      </div>
    </div>
  );
}
