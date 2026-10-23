import jsQR from 'jsqr';
import { jsPDF, type jsPDFOptions } from 'jspdf';
import { autoTable } from 'jspdf-autotable';
import QRCode from 'qrcode';
import { describe, expect, it } from 'vitest';
import { analyze } from './analyzer/analyze';
import { DEFAULT_OPTIONS, RULES } from './analyzer/config';
import { explainLimits } from './analyzer/transparency';
import type { Analysis } from './analyzer/types';
import { classifyQrContent } from './qr/classify';
import { validateQrFile } from './qr/decodeImage';
import { buildAnalysisPdf } from './reports/pdf';
import { pdfSafe, reportId } from './reports/pdfText';

const ok = (u: string): Analysis => {
  const r = analyze(u);
  if (!r.ok) throw new Error(r.error);
  return r;
};

/** Render a QR code to RGBA pixels (with quiet zone) without a canvas. */
function qrPixels(text: string, scale = 6) {
  const qr = QRCode.create(text, { errorCorrectionLevel: 'M' });
  const n = qr.modules.size;
  const quiet = 4;
  const size = (n + quiet * 2) * scale;
  const data = new Uint8ClampedArray(size * size * 4).fill(255);
  for (let r = 0; r < n; r++)
    for (let c = 0; c < n; c++) {
      if (!qr.modules.get(r, c)) continue;
      for (let y = 0; y < scale; y++)
        for (let x = 0; x < scale; x++) {
          const i = (((r + quiet) * scale + y) * size + (c + quiet) * scale + x) * 4;
          data[i] = data[i + 1] = data[i + 2] = 0;
        }
    }
  return { data, size };
}

// Same constructor, but uncompressed so tests can search the content stream for text.
class PlainPDFImpl extends jsPDF {
  constructor(o?: jsPDFOptions) {
    super({ ...o, compress: false });
  }
}
const PlainPDF = PlainPDFImpl as unknown as typeof jsPDF;

describe('QR decoding (jsQR, offline)', () => {
  it.each([
    'https://campus.example@login-verify.example/sso',
    'https://bit.ly/3xCampus',
    'WIFI:T:WPA;S:CampusGuest;P:hunter2;;',
    'https://cаmpus.example/',
  ])('round-trips %s', (text) => {
    const { data, size } = qrPixels(text);
    expect(jsQR(data, size, size)?.data).toBe(text);
  });
  it('returns null for an image without a QR code', () => {
    const blank = new Uint8ClampedArray(200 * 200 * 4).fill(255);
    expect(jsQR(blank, 200, 200)).toBeNull();
  });
});

describe('QR file validation', () => {
  it('accepts common image types', () => {
    for (const type of ['image/png', 'image/jpeg', 'image/webp']) expect(validateQrFile({ name: 'a', type, size: 1000 })).toBeNull();
  });
  it('rejects non-images, empty and oversized files', () => {
    expect(validateQrFile({ name: 'a.pdf', type: 'application/pdf', size: 10 })).toMatch(/not a supported image/);
    expect(validateQrFile({ name: 'a.svg', type: 'image/svg+xml', size: 10 })).toMatch(/not a supported image/);
    expect(validateQrFile({ name: 'a.png', type: 'image/png', size: 0 })).toMatch(/empty/);
    expect(validateQrFile({ name: 'a.png', type: 'image/png', size: 11 * 1024 * 1024 })).toMatch(/limit/);
  });
  it('falls back to the extension when the MIME type is missing', () => {
    expect(validateQrFile({ name: 'scan.JPG', type: '', size: 5 })).toBeNull();
    expect(validateQrFile({ name: 'scan.exe', type: '', size: 5 })).not.toBeNull();
  });
});

describe('QR content classification', () => {
  it('passes web URLs to the analyzer unchanged', () => {
    const c = classifyQrContent('  https://campus.example/x  ');
    expect(c).toMatchObject({ kind: 'web-url', analyzable: 'https://campus.example/x' });
    expect(c.raw).toBe('  https://campus.example/x  ');
  });
  it('flags dangerous schemes and never yields Safe', () => {
    const c = classifyQrContent('javascript:alert(1)');
    expect(c.kind).toBe('dangerous-scheme');
    expect(ok(c.analyzable!).verdict).toBe('Suspicious');
  });
  it('treats app schemes as non-web', () => {
    for (const s of ['mailto:a@campus.example', 'tel:+15550100', 'sms:+15550100', 'otpauth://totp/x?secret=A']) {
      const c = classifyQrContent(s);
      expect(c.kind).toBe('app-scheme');
      expect(ok(c.analyzable!).verdict).not.toBe('Safe');
    }
  });
  it('masks Wi-Fi passwords and offers no verdict', () => {
    const c = classifyQrContent('WIFI:T:WPA;S:CampusGuest;P:hunter2;;');
    expect(c.kind).toBe('wifi');
    expect(c.analyzable).toBeNull();
    expect(c.display).not.toContain('hunter2');
    expect(c.raw).toContain('hunter2');
  });
  it('treats prose as text, not a link', () => {
    expect(classifyQrContent('Room 204. Lab starts at 10:00').kind).toBe('text');
    expect(classifyQrContent('').kind).toBe('empty');
    expect(classifyQrContent('BEGIN:VCARD\nFN:Jo\nEND:VCARD').kind).toBe('contact');
  });
  it('recognizes scheme-less domains and lets the analyzer flag them', () => {
    const c = classifyQrContent('campus.example/login');
    expect(c.kind).toBe('schemeless-url');
    expect(ok(c.analyzable!).findings.map((f) => f.ruleId)).toContain('PR-10');
    expect(classifyQrContent('localhost:3000').kind).toBe('text');
  });
  it('counts hidden characters', () => {
    expect(classifyQrContent('https://campus.example/a​b').hiddenChars).toBe(1);
  });
});

describe('redirect transparency', () => {
  it('reports the shortener from the analyzer’s own PR-04 match', () => {
    const t = explainLimits(ok('https://bit.ly/3xCampus?ref=poster'));
    expect(t.redirect).toEqual({ service: 'bit.ly', visibleHost: 'bit.ly', visiblePath: '/3xCampus?ref=poster', scheme: 'https' });
    expect(t.unknown.join(' ')).toMatch(/final destination/i);
  });
  it('uses the parsed host, not string splitting', () => {
    expect(explainLimits(ok('https://campus.example@bit.ly/x')).redirect?.visibleHost).toBe('bit.ly');
    expect(explainLimits(ok('https://BIT.LY/x')).redirect?.visibleHost).toBe('bit.ly');
  });
  it('is absent for ordinary URLs, which still list redirects as unknown', () => {
    const t = explainLimits(ok('https://campus.example/'));
    expect(t.redirect).toBeNull();
    expect(t.unknown[0]).toMatch(/redirects elsewhere/);
    expect(t.conclusion).toMatch(/not verification/);
  });
  it('keeps the existing verdict for shorteners', () => {
    expect(ok('https://bit.ly/3xCampus').verdict).toBe('Review');
  });
  it('lists rules that did not trigger', () => {
    const t = explainLimits(ok('https://bit.ly/abc'));
    expect(t.notTriggered.map((r) => r.id)).not.toContain('PR-04');
    expect(t.notTriggered).toHaveLength(RULES.length - 1);
  });
});

describe('PDF reports', () => {
  it('sanitizes text to Latin-1 with visible markers', () => {
    expect(pdfSafe('cаmpus “x” → y​')).toBe('c[U+0430]mpus "x" -> y[U+200B]');
    expect(pdfSafe('résumé')).toBe('résumé');
  });
  it('creates unique report IDs', () => {
    const d = new Date(2026, 9, 14, 11, 32, 24);
    expect(reportId('A', d)).toMatch(/^PRISM-A-20261014-113224-[0-9A-F]{4}$/);
  });
  it('builds a valid multi-page analysis PDF matching the analysis', () => {
    const a = ok('http://campus.example@3232235777/' + 'very-long-segment-'.repeat(30));
    const doc = buildAnalysisPdf(PlainPDF, autoTable, {
      analysis: a,
      source: { kind: 'qr', fileName: 'poster.png', decoded: a.input, contentLabel: 'Web link' },
      options: DEFAULT_OPTIONS,
      generatedAt: new Date(),
      id: 'PRISM-A-TEST',
    });
    const out = doc.output();
    expect(out.startsWith('%PDF-')).toBe(true);
    expect(doc.getNumberOfPages()).toBeGreaterThanOrEqual(2);
    for (const s of ['URL Analysis Report', 'Suspicious', 'PR-01', 'PR-03', 'PR-08', 'poster.png', 'PRISM-A-TEST', 'Page 1 of']) {
      expect(out).toContain(s);
    }
  });
  it('wraps very long URLs within the content width', () => {
    const doc = new jsPDF({ unit: 'mm', format: 'a4' });
    doc.setFontSize(9);
    const lines: string[] = doc.splitTextToSize('https://campus.example/' + 'a'.repeat(600), 178);
    expect(lines.length).toBeGreaterThan(3);
    for (const l of lines) expect(doc.getTextWidth(l)).toBeLessThanOrEqual(178.5);
  });
  it('includes redirect transparency for shorteners', () => {
    const out = buildAnalysisPdf(PlainPDF, autoTable, {
      analysis: ok('https://bit.ly/3xCampus'),
      source: { kind: 'manual' },
      options: DEFAULT_OPTIONS,
      generatedAt: new Date(),
      id: 'R',
    }).output();
    expect(out).toContain('Redirect transparency');
    expect(out).toContain('Unknown. PRISM does not follow redirects');
  });
});

