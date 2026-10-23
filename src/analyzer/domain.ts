/** Hostname helpers: punycode decoding, registrable domains and confusable skeletons. */

const BASE = 36;
const T_MIN = 1;
const T_MAX = 26;
const SKEW = 38;
const DAMP = 700;

function adapt(delta: number, numPoints: number, firstTime: boolean): number {
  let d = firstTime ? Math.floor(delta / DAMP) : delta >> 1;
  d += Math.floor(d / numPoints);
  let k = 0;
  while (d > ((BASE - T_MIN) * T_MAX) >> 1) {
    d = Math.floor(d / (BASE - T_MIN));
    k += BASE;
  }
  return Math.floor(k + ((BASE - T_MIN + 1) * d) / (d + SKEW));
}

function digitOf(cp: number): number {
  if (cp >= 0x30 && cp < 0x3a) return 26 + (cp - 0x30);
  if (cp >= 0x41 && cp < 0x5b) return cp - 0x41;
  if (cp >= 0x61 && cp < 0x7b) return cp - 0x61;
  return BASE;
}

/** RFC 3492 punycode decoder for a single label (without the "xn--" prefix). */
export function decodePunycode(input: string): string {
  const output: number[] = [];
  const basic = Math.max(input.lastIndexOf('-'), 0);
  for (let j = 0; j < basic; j++) output.push(input.charCodeAt(j));
  let n = 128;
  let bias = 72;
  let i = 0;
  for (let index = basic > 0 ? basic + 1 : 0; index < input.length; ) {
    const oldi = i;
    for (let w = 1, k = BASE; ; k += BASE) {
      if (index >= input.length) throw new Error('Invalid punycode');
      const digit = digitOf(input.charCodeAt(index++));
      if (digit >= BASE) throw new Error('Invalid punycode');
      i += digit * w;
      const t = k <= bias ? T_MIN : k >= bias + T_MAX ? T_MAX : k - bias;
      if (digit < t) break;
      w *= BASE - t;
    }
    const len = output.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    output.splice(i++, 0, n);
  }
  return String.fromCodePoint(...output);
}

export function toUnicodeHost(host: string): string {
  return host
    .split('.')
    .map((label) => {
      if (!label.startsWith('xn--')) return label;
      try {
        return decodePunycode(label.slice(4));
      } catch {
        return label;
      }
    })
    .join('.');
}

const MULTI_PART_SLDS = new Set(['co', 'com', 'ac', 'gov', 'edu', 'org', 'net', 'ne', 'or', 'go']);

/** Approximate registrable domain (no public-suffix list; handles common ccSLDs like co.uk). */
export function registrableDomain(host: string): string {
  const labels = host.split('.').filter(Boolean);
  if (labels.length <= 2) return labels.join('.');
  const tld = labels[labels.length - 1];
  const sld = labels[labels.length - 2];
  if (tld.length === 2 && MULTI_PART_SLDS.has(sld)) return labels.slice(-3).join('.');
  return labels.slice(-2).join('.');
}

export function isSameOrSubdomain(host: string, domain: string): boolean {
  return host === domain || host.endsWith('.' + domain);
}

/** Common non-Latin confusables mapped to the Latin letter they imitate. */
const CONFUSABLES: Record<string, string> = {
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
  'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'һ': 'h', 'ԛ': 'q', 'ԝ': 'w',
  'ο': 'o', 'α': 'a', 'ν': 'v', 'ρ': 'p', 'ι': 'i', 'κ': 'k', 'τ': 't',
  'ɡ': 'g', 'ı': 'i', 'ℓ': 'l',
};

export function foldConfusables(s: string): string {
  return Array.from(s.normalize('NFD').replace(/[̀-ͯ]/g, ''))
    .map((ch) => CONFUSABLES[ch] ?? ch)
    .join('')
    .toLowerCase();
}

/**
 * Visual skeleton: two strings with the same skeleton are likely to be read
 * as the same domain by a person (e.g. "carnpus" and "campus").
 */
export function skeleton(s: string): string {
  return foldConfusables(s)
    .replace(/rn/g, 'm')
    .replace(/vv/g, 'w')
    .replace(/cl/g, 'd')
    .replace(/[0]/g, 'o')
    .replace(/[1i!|]/g, 'l')
    .replace(/3/g, 'e')
    .replace(/5/g, 's');
}

/** Optimal-string-alignment (restricted Damerau-Levenshtein) distance. */
export function editDistance(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const d: number[][] = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array<number>(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

/** Split two strings into shared prefix, differing middles and shared suffix. */
export function diffMiddle(a: string, b: string): { prefix: string; a: string; b: string; suffix: string } {
  const ca = Array.from(a);
  const cb = Array.from(b);
  let p = 0;
  while (p < ca.length && p < cb.length && ca[p] === cb[p]) p++;
  let s = 0;
  while (s < ca.length - p && s < cb.length - p && ca[ca.length - 1 - s] === cb[cb.length - 1 - s]) s++;
  return {
    prefix: ca.slice(0, p).join(''),
    a: ca.slice(p, ca.length - s).join(''),
    b: cb.slice(p, cb.length - s).join(''),
    suffix: ca.slice(ca.length - s).join(''),
  };
}

export function describeChars(s: string): string {
  // Quote ASCII runs together ("rn"); spell out non-ASCII characters by code point.
  const out: string[] = [];
  let run = '';
  for (const ch of Array.from(s)) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp <= 0x7e) {
      run += ch;
      continue;
    }
    if (run) out.push(`“${run}”`);
    run = '';
    out.push(`“${ch}” (U+${cp.toString(16).toUpperCase().padStart(4, '0')})`);
  }
  if (run) out.push(`“${run}”`);
  return out.join(' ');
}

const IPV4_RE = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/;

export function isIPv4(host: string): boolean {
  return IPV4_RE.test(host);
}

export function describeIPv4(host: string): string | null {
  const m = IPV4_RE.exec(host);
  if (!m) return null;
  const [a, b] = [Number(m[1]), Number(m[2])];
  if (a === 127) return 'a loopback address (this device)';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168)) {
    return 'a private-network address';
  }
  if (a === 169 && b === 254) return 'a link-local address';
  if (a === 0) return 'an unspecified address';
  return null;
}
