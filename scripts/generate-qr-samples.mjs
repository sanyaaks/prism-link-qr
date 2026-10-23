// Regenerates the sample QR images used by the scanner demo: `npm run samples:qr`.
import QRCode from 'qrcode';
import { mkdirSync } from 'node:fs';

export const QR_SAMPLES = {
  'campus-portal': 'https://campus.example/library/hours',
  'at-disguise': 'https://campus.example@login-verify.example/sso',
  'short-link': 'https://bit.ly/3xCampus',
  'script-link': 'javascript:alert(document.domain)',
  'wifi': 'WIFI:T:WPA;S:CampusGuest;P:not-a-real-password;;',
  'plain-text': 'Cyber Club meets in Room 204 on Friday at 4pm.',
};

const dir = new URL('../public/qr-samples/', import.meta.url);
mkdirSync(dir, { recursive: true });
for (const [name, text] of Object.entries(QR_SAMPLES)) {
  await QRCode.toFile(new URL(`${name}.png`, dir).pathname.replace(/^\/([A-Za-z]:)/, '$1'), text, {
    width: 360,
    margin: 3,
    errorCorrectionLevel: 'M',
  });
}
console.log(`Wrote ${Object.keys(QR_SAMPLES).length} QR samples`);
