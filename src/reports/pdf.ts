import type { jsPDF as JsPDF } from 'jspdf';
import type { autoTable as AutoTableFn, RowInput, UserOptions } from 'jspdf-autotable';
import { computeFlips } from '../analyzer/flip';
import { EVIDENCE_LABEL, explainLimits } from '../analyzer/transparency';
import type { Analysis, AnalyzerOptions, Verdict } from '../analyzer/types';
import type { InputSource } from '../lib/source';
import { dateStamp, pdfSafe, reportId, timeStamp } from './pdfText';

type JsPDFCtor = typeof JsPDF;
type AutoTable = typeof AutoTableFn;
type RGB = [number, number, number];

const NAVY: RGB = [0, 31, 63];
const CYAN: RGB = [0, 168, 143]; // darker Cyan Pulse for print legibility
const INK: RGB = [33, 37, 41];
const MUTED: RGB = [100, 108, 118];
const RULE_LINE: RGB = [222, 226, 230];
export const PDF_VERDICT_COLOR: Record<Verdict | 'Error', RGB> = {
  Safe: [31, 140, 90],
  Review: [190, 115, 0],
  Suspicious: [200, 45, 45],
  Error: [100, 108, 118],
};

const PAGE_W = 210;
const PAGE_H = 297;
const MARGIN = 16;
const CONTENT_W = PAGE_W - MARGIN * 2;
const FOOTER_SPACE = 18;

const DISCLAIMER =
  'PRISM performs local, deterministic, rule-based screening of link text only. It does not open links, follow redirects, ' +
  'inspect webpages or query threat-intelligence services. A Safe verdict means no implemented rule matched; it does not ' +
  'guarantee that a URL is harmless. Domains ending in .example are illustrative.';

/** Small layout helper over jsPDF + autoTable with a flowing y cursor. */
class Writer {
  y = MARGIN;
  constructor(
    readonly doc: JsPDF,
    private readonly autoTable: AutoTable,
    private readonly id: string,
  ) {}

  header(title: string, subtitle: string, meta: [string, string][]) {
    const d = this.doc;
    d.setFillColor(...NAVY);
    d.rect(0, 0, PAGE_W, 38, 'F');
    // Prism mark: triangle with an exiting cyan beam
    d.setDrawColor(255, 255, 255);
    d.setLineWidth(0.5);
    d.triangle(MARGIN + 6, 10, MARGIN + 12, 21, MARGIN, 21, 'S');
    d.setDrawColor(0, 209, 178);
    d.setLineWidth(0.7);
    d.line(MARGIN + 8, 15, MARGIN + 15, 12.5);
    d.setTextColor(255, 255, 255);
    d.setFont('helvetica', 'bold');
    d.setFontSize(15);
    d.text('PRISM', MARGIN + 18, 19);
    d.setFont('helvetica', 'normal');
    d.setFontSize(8);
    d.setTextColor(0, 209, 178);
    d.text('EXPLAINABLE QR & LINK RISK SCREENING', MARGIN + 18, 24);
    d.setTextColor(255, 255, 255);
    d.setFontSize(13);
    d.setFont('helvetica', 'bold');
    d.text(pdfSafe(title), MARGIN, 33);
    d.setFont('helvetica', 'normal');
    d.setFontSize(7.5);
    d.setTextColor(200, 212, 225);
    meta.forEach(([k, v], i) => {
      d.text(`${k}: ${pdfSafe(v)}`, PAGE_W - MARGIN, 14 + i * 4.5, { align: 'right' });
    });
    this.y = 46;
    if (subtitle) this.para(subtitle, { size: 8.5, color: MUTED });
  }

  ensure(h: number) {
    if (this.y + h > PAGE_H - FOOTER_SPACE) {
      this.doc.addPage();
      this.y = MARGIN + 4;
    }
  }

  h2(text: string) {
    this.ensure(16);
    this.y += 4;
    const d = this.doc;
    d.setFont('helvetica', 'bold');
    d.setFontSize(11.5);
    d.setTextColor(...NAVY);
    d.text(pdfSafe(text), MARGIN, this.y);
    d.setDrawColor(...CYAN);
    d.setLineWidth(0.6);
    d.line(MARGIN, this.y + 1.8, MARGIN + 12, this.y + 1.8);
    this.y += 7;
  }

  para(text: string, o: { size?: number; color?: RGB; bold?: boolean; indent?: number } = {}) {
    const d = this.doc;
    const size = o.size ?? 9;
    const indent = o.indent ?? 0;
    d.setFont('helvetica', o.bold ? 'bold' : 'normal');
    d.setFontSize(size);
    d.setTextColor(...(o.color ?? INK));
    const lh = size * 0.45;
    const lines: string[] = d.splitTextToSize(pdfSafe(text), CONTENT_W - indent);
    for (const line of lines) {
      this.ensure(lh);
      d.text(line, MARGIN + indent, this.y);
      this.y += lh;
    }
    this.y += 1.5;
  }

  bullets(items: string[], color: RGB = INK) {
    for (const item of items) {
      this.ensure(5);
      this.doc.setFillColor(...CYAN);
      this.doc.circle(MARGIN + 1.2, this.y - 1.1, 0.6, 'F');
      this.para(item, { indent: 4, color });
      this.y -= 0.8;
    }
    this.y += 1;
  }

  verdictBox(verdict: Verdict | 'Error', headline: string, detail: string) {
    const d = this.doc;
    const color = PDF_VERDICT_COLOR[verdict];
    d.setFont('helvetica', 'normal');
    d.setFontSize(9);
    const lines: string[] = d.splitTextToSize(pdfSafe(detail), CONTENT_W - 12);
    const h = 16 + lines.length * 4.1;
    this.ensure(h + 4);
    d.setFillColor(248, 249, 250);
    d.setDrawColor(...RULE_LINE);
    d.roundedRect(MARGIN, this.y, CONTENT_W, h, 2, 2, 'FD');
    d.setFillColor(...color);
    d.rect(MARGIN, this.y, 2.2, h, 'F');
    d.setFont('helvetica', 'bold');
    d.setFontSize(18);
    d.setTextColor(...color);
    d.text(pdfSafe(headline), MARGIN + 7, this.y + 9);
    d.setFont('helvetica', 'normal');
    d.setFontSize(9);
    d.setTextColor(...INK);
    lines.forEach((l, i) => d.text(l, MARGIN + 7, this.y + 15 + i * 4.1));
    this.y += h + 5;
  }

  table(head: string[], body: RowInput[], extra: Partial<UserOptions> = {}) {
    this.ensure(14);
    this.autoTable(this.doc, {
      startY: this.y,
      margin: { left: MARGIN, right: MARGIN, top: MARGIN + 4, bottom: FOOTER_SPACE },
      head: head.length ? [head.map(pdfSafe)] : undefined,
      body: body.map((row) =>
        Array.isArray(row) ? row.map((c) => (typeof c === 'string' ? pdfSafe(c) : c)) : row,
      ) as RowInput[],
      theme: 'grid',
      styles: { font: 'helvetica', fontSize: 8, cellPadding: 1.8, overflow: 'linebreak', textColor: INK, lineColor: RULE_LINE, lineWidth: 0.2, valign: 'top' },
      headStyles: { fillColor: NAVY, textColor: [255, 255, 255], fontStyle: 'bold' },
      alternateRowStyles: { fillColor: [248, 249, 250] },
      ...extra,
    });
    // jspdf-autotable records the end position on the document.
    this.y = (this.doc as unknown as { lastAutoTable: { finalY: number } }).lastAutoTable.finalY + 5;
  }

  kv(rows: [string, string][]) {
    this.table([], rows, {
      theme: 'plain',
      styles: { font: 'helvetica', fontSize: 8.5, cellPadding: 1.4, overflow: 'linebreak', textColor: INK },
      columnStyles: { 0: { cellWidth: 42, fontStyle: 'bold', textColor: MUTED } },
    });
  }

  finalize() {
    const d = this.doc;
    const n = d.getNumberOfPages();
    for (let i = 1; i <= n; i++) {
      d.setPage(i);
      d.setDrawColor(...RULE_LINE);
      d.setLineWidth(0.2);
      d.line(MARGIN, PAGE_H - 12, PAGE_W - MARGIN, PAGE_H - 12);
      d.setFont('helvetica', 'normal');
      d.setFontSize(7);
      d.setTextColor(...MUTED);
      d.text(`PRISM - ${this.id} - Generated locally; rule-based screening, not a safety guarantee.`, MARGIN, PAGE_H - 7.5);
      d.text(`Page ${i} of ${n}`, PAGE_W - MARGIN, PAGE_H - 7.5, { align: 'right' });
    }
  }
}

// ---------------------------------------------------------------------------
// Report 1: individual URL analysis
// ---------------------------------------------------------------------------

export interface AnalysisReportData {
  analysis: Analysis;
  source: InputSource;
  options: AnalyzerOptions;
  generatedAt: Date;
  id: string;
}

export function buildAnalysisPdf(jsPDF: JsPDFCtor, autoTable: AutoTable, data: AnalysisReportData): JsPDF {
  const { analysis: a, source, options, generatedAt, id } = data;
  const doc = new jsPDF({ unit: 'mm', format: 'a4', compress: true });
  doc.setProperties({ title: `PRISM URL Analysis ${id}`, subject: 'Rule-based URL screening report', creator: 'PRISM (local)' });
  const w = new Writer(doc, autoTable, id);
  const t = explainLimits(a);
  const flips = computeFlips(a, options);
  const p = a.parts;

  w.header('URL Analysis Report', '', [
    ['Report ID', id],
    ['Generated', timeStamp(generatedAt)],
    ['Input source', source.kind === 'qr' ? 'QR image' : 'Manual entry'],
  ]);

  w.verdictBox(a.verdict, `${a.verdict}  -  risk score ${a.score}/100`, `${a.summary} ${t.conclusion}`);

  w.h2('Submitted input');
  const inputRows: [string, string][] = [['Original input', a.input.trim()]];
  if (a.normalizedInput !== a.input.trim()) inputRows.push(['Analyzed as', a.normalizedInput]);
  if (source.kind === 'qr') {
    inputRows.push(['QR image file', source.fileName], ['Decoded content type', source.contentLabel], ['Decoded content', source.decoded]);
  }
  w.kv(inputRows);

  w.h2('URL anatomy');
  const anatomy: [string, string][] = [
    ['Scheme', p.scheme],
    ['Actual hostname', p.displayHost ? `${p.displayHost}${p.displayHost !== p.hostname ? `  (DNS: ${p.hostname})` : ''}` : '(none)'],
  ];
  if (p.hostType === 'domain' && p.registrable !== p.hostname) anatomy.push(['Registered domain', p.registrable]);
  anatomy.push(['Host type', p.hostType], ['Port', p.port ? `${p.port} (explicit)` : p.effectivePort ? `${p.effectivePort} (default)` : '-']);
  if (p.username || p.hasPassword) anatomy.push(['Userinfo (ignored for routing)', `${p.username}${p.hasPassword ? ':****' : ''}`]);
  anatomy.push(['Path', p.path || '-']);
  if (p.query) anatomy.push(['Query', p.query]);
  if (p.fragment) anatomy.push(['Fragment', p.fragment]);
  anatomy.push(['Parsed URL', p.href]);
  w.kv(anatomy);

  if (a.readsLike) {
    w.h2('Reads like vs. actually goes to');
    w.kv([
      [a.readsLike.appearsLabel, a.readsLike.appears],
      [a.readsLike.actualLabel, a.readsLike.actual],
    ]);
    w.para(a.readsLike.note, { color: MUTED, size: 8.5 });
  }

  if (t.redirect) {
    w.h2('Redirect transparency');
    w.kv([
      ['Visible hostname', t.redirect.visibleHost],
      ['Recognized service', `${t.redirect.service} (configured URL shortener, rule PR-04)`],
      ['Visible path', t.redirect.visiblePath || '/'],
      ['Final destination', 'Unknown. PRISM does not follow redirects or query external services.'],
    ]);
  }

  w.h2('Triggered rules');
  if (a.findings.length === 0) {
    w.para('No rule matched. Every positive check passed. This means the implemented rules found nothing, not that the URL is verified safe.');
  } else {
    w.table(
      ['Rule', 'Severity', 'Evidence type', 'Finding and explanation', 'Evidence'],
      a.findings.map((f) => [
        `${f.ruleId}\n${f.ruleName}`,
        f.severity.toUpperCase(),
        EVIDENCE_LABEL[t.evidence.find((e) => e.finding === f)!.kind].label,
        `${f.title}\n\n${f.explanation}`,
        f.evidence ?? '-',
      ]),
      {
        columnStyles: { 0: { cellWidth: 30 }, 1: { cellWidth: 18 }, 2: { cellWidth: 22 }, 4: { cellWidth: 40 } },
        didParseCell: (h) => {
          if (h.section === 'body' && h.column.index === 1) {
            const sev = String(h.cell.raw).toLowerCase();
            h.cell.styles.textColor =
              sev === 'critical' || sev === 'high' ? PDF_VERDICT_COLOR.Suspicious : sev === 'medium' ? PDF_VERDICT_COLOR.Review : MUTED;
            h.cell.styles.fontStyle = 'bold';
          }
        },
      },
    );
  }

  w.h2('Positive checks');
  w.table(['Check', 'Result'], a.checks.map((c) => [c.label, c.passed ? 'Passed' : 'Failed']), { columnStyles: { 1: { cellWidth: 22 } } });

  if (a.findings.length) {
    w.h2('Findings detail');
    for (const f of a.findings) {
      w.para(`${f.ruleId} (${f.severity}) - ${f.title}`, { bold: true, size: 9 });
      w.para(f.explanation, { indent: 3 });
      if (f.evidence) w.para(`Evidence: ${f.evidence}`, { indent: 3, color: MUTED });
    }
  }

  w.h2('Observed facts');
  w.bullets(t.observed);
  w.h2('Cannot be determined offline');
  w.bullets(t.unknown, MUTED);

  w.h2('Rules that did not match');
  w.para(t.notTriggered.length ? t.notTriggered.map((r) => `${r.id} ${r.name}`).join('; ') : 'Every rule matched.', { size: 8.5 });

  w.h2('What would flip this verdict');
  if (flips.primary || flips.secondary) {
    w.table(
      ['Change', 'Resulting URL', 'Verdict'],
      [flips.primary, flips.secondary].filter(Boolean).map((f) => [f!.change, f!.url, `${f!.from} -> ${f!.to}`]),
      { columnStyles: { 2: { cellWidth: 30 } } },
    );
    w.para('Each suggested URL was re-analyzed by the same analyzer to confirm the stated verdict.', { size: 8, color: MUTED });
  } else {
    w.para('No small, verifiable edit changes this verdict.', { size: 8.5 });
  }
  if (flips.blockers.length) w.bullets(flips.blockers.map((b) => `${b.ruleId}: ${b.text}`), MUTED);

  w.h2('Reference domains used');
  w.para(options.referenceDomains.join(', ') || '(none; lookalike rules disabled)', { size: 8.5 });

  w.h2('Limitations and disclaimer');
  w.para(DISCLAIMER, { color: MUTED, size: 8.5 });

  w.finalize();
  return doc;
}

// ---------------------------------------------------------------------------
// Browser entry points (lazy-load jsPDF so it is not in the main bundle)
// ---------------------------------------------------------------------------

async function loadPdfLib() {
  const [{ jsPDF }, { autoTable }] = await Promise.all([import('jspdf'), import('jspdf-autotable')]);
  return { jsPDF, autoTable };
}

export async function downloadAnalysisReport(a: Analysis, source: InputSource, options: AnalyzerOptions): Promise<string> {
  const { jsPDF, autoTable } = await loadPdfLib();
  const generatedAt = new Date();
  const doc = buildAnalysisPdf(jsPDF, autoTable, { analysis: a, source, options, generatedAt, id: reportId('A', generatedAt) });
  const filename = `PRISM_URL_Analysis_${dateStamp(generatedAt)}.pdf`;
  doc.save(filename);
  return filename;
}

