import { DANGEROUS_SCHEMES } from '../analyzer/config';

export type QrContentKind =
  | 'web-url'
  | 'schemeless-url'
  | 'dangerous-scheme'
  | 'app-scheme'
  | 'wifi'
  | 'contact'
  | 'text'
  | 'empty';

export interface QrContent {
  kind: QrContentKind;
  /** Exactly what the QR code encodes. */
  raw: string;
  /** Raw content with secrets (e.g. Wi-Fi passwords) masked, for display and reports. */
  display: string;
  /** Value to hand to the analyzer, or null when it should not be screened as a link. */
  analyzable: string | null;
  scheme: string | null;
  label: string;
  explanation: string;
  hiddenChars: number;
}

const HIDDEN_RE = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F­​-‏‪-‮⁠-⁤⁦-⁩﻿]/g;

function maskWifi(raw: string): string {
  return raw.replace(/(^|;)P:((?:\\.|[^;])*)/i, (_m, pre: string, pw: string) => `${pre}P:${'•'.repeat(Math.min(pw.length, 12) || 0)}`);
}

/** Classify decoded QR text. Never executes or navigates; only decides what is safe to analyze. */
export function classifyQrContent(decoded: string): QrContent {
  const raw = decoded;
  const trimmed = raw.trim();
  const hiddenChars = (raw.match(HIDDEN_RE) ?? []).length;
  const base = { raw, display: raw, hiddenChars };

  if (!trimmed) {
    return { ...base, kind: 'empty', analyzable: null, scheme: null, label: 'Empty', explanation: 'The QR code decoded to empty content. There is nothing to analyze.' };
  }

  const schemeMatch = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(trimmed);
  const scheme = schemeMatch ? schemeMatch[1].toLowerCase() : null;

  if (scheme === 'http' || scheme === 'https') {
    return {
      ...base,
      kind: 'web-url',
      analyzable: trimmed,
      scheme,
      label: 'Web link',
      explanation: 'The QR code contains a web link. It goes through the same analyzer as a pasted link. Decoding it does not make it trustworthy.',
    };
  }
  if (scheme === 'wifi') {
    return {
      ...base,
      display: maskWifi(raw),
      kind: 'wifi',
      analyzable: null,
      scheme,
      label: 'Wi-Fi configuration',
      explanation: 'This QR code configures a Wi-Fi network, not a web page. PRISM screens links only, so there is no verdict. The password is masked here and in reports.',
    };
  }
  if (/^BEGIN:(VCARD|VEVENT|VCALENDAR)/i.test(trimmed) || scheme === 'mecard') {
    return {
      ...base,
      kind: 'contact',
      analyzable: null,
      scheme,
      label: 'Contact or calendar data',
      explanation: 'This QR code holds structured contact or event data, not a link. Check any URLs inside it individually.',
    };
  }
  if (scheme && DANGEROUS_SCHEMES.includes(scheme)) {
    return {
      ...base,
      kind: 'dangerous-scheme',
      analyzable: trimmed,
      scheme,
      label: `${scheme}: content`,
      explanation: `A ${scheme}: QR code can run script or render content directly instead of opening a website. PRISM will not open it. You can still run the rules to see why it is flagged.`,
    };
  }
  // Single-word schemes like mailto:, tel:, sms:, geo:, otpauth: (but not "localhost:3000")
  const afterScheme = schemeMatch ? trimmed.slice(schemeMatch[0].length) : '';
  if (scheme && !scheme.includes('.') && !/^\d+(?:[/?#]|$)/.test(afterScheme)) {
    return {
      ...base,
      kind: 'app-scheme',
      analyzable: trimmed,
      scheme,
      label: `${scheme}: link`,
      explanation: `This QR code opens another application (${scheme}:), not a web page. It cannot be screened as a normal web URL. Running the rules shows this as a non-web scheme, never as Safe.`,
    };
  }
  if (!/\s/.test(trimmed) && /^[^/?#@]*[a-z0-9-]\.[a-z]{2,}(?::\d+)?(?:[/?#]|$)/i.test(trimmed)) {
    return {
      ...base,
      kind: 'schemeless-url',
      analyzable: trimmed,
      scheme: null,
      label: 'Link without a scheme',
      explanation: 'This looks like a domain with no scheme. Scanner apps may open it differently. PRISM analyzes it as https:// and flags the ambiguity.',
    };
  }
  return {
    ...base,
    kind: 'text',
    analyzable: null,
    scheme: null,
    label: 'Plain text',
    explanation: 'The QR code contains text, not a link, so PRISM gives no verdict. Successfully decoding it says nothing about whether it is safe to act on.',
  };
}
