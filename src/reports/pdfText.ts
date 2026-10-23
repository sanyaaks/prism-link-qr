const REPLACEMENTS: Record<string, string> = {
  '“': '"', '”': '"', '„': '"', '‘': "'", '’': "'", '‚': "'",
  '–': '-', '—': '-', '−': '-', '…': '...', '•': '-', '·': '-',
  '→': '->', '←': '<-', '✓': 'OK', '✗': 'X', '×': 'x', '≠': '!=', '≤': '<=', '≥': '>=',
  ' ': ' ',
};

/**
 * Make untrusted text printable with jsPDF's built-in (Latin-1) fonts.
 * Characters outside Latin-1 are shown as [U+XXXX] rather than silently
 * dropped, which matters for homograph URLs. Invisible characters become visible markers.
 */
export function pdfSafe(input: string): string {
  let out = '';
  for (const ch of Array.from(input ?? '')) {
    const cp = ch.codePointAt(0) ?? 0;
    if (REPLACEMENTS[ch] !== undefined) out += REPLACEMENTS[ch];
    else if (cp === 0x09 || cp === 0x0a) out += ch === '\t' ? ' ' : '\n';
    else if (cp < 0x20 || (cp >= 0x7f && cp < 0xa0) || cp === 0xad) out += `[U+${cp.toString(16).toUpperCase().padStart(4, '0')}]`;
    else if (cp <= 0xff) out += ch;
    else out += `[U+${cp.toString(16).toUpperCase().padStart(4, '0')}]`;
  }
  return out;
}

export function dateStamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}`;
}

export function timeStamp(d: Date): string {
  const p = (n: number) => String(n).padStart(2, '0');
  return `${dateStamp(d)} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/** e.g. PRISM-A-20261014-113224-7F3A. Timestamp plus random suffix. */
export function reportId(prefix: 'A' | 'T', d: Date): string {
  const rand = new Uint8Array(2);
  if (typeof crypto !== 'undefined' && crypto.getRandomValues) crypto.getRandomValues(rand);
  else rand.set([Math.random() * 256, Math.random() * 256]);
  const hex = [...rand].map((b) => b.toString(16).padStart(2, '0')).join('').toUpperCase();
  return `PRISM-${prefix}-${dateStamp(d).replace(/-/g, '')}-${timeStamp(d).slice(11).replace(/:/g, '')}-${hex}`;
}
