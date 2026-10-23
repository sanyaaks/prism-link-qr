import type { DecodeRequest, DecodeResponse } from './decode.worker';

export const QR_MAX_BYTES = 10 * 1024 * 1024;
export const QR_ACCEPT = ['image/png', 'image/jpeg', 'image/webp', 'image/gif', 'image/bmp'];
const EXT_RE = /\.(png|jpe?g|webp|gif|bmp)$/i;
/** Decode attempts at these maximum dimensions: large photos often decode better downscaled. */
const SCALES = [1600, 800];
const TIMEOUT_MS = 10000;

export class QrError extends Error {}

/** Reject anything that is not a reasonably sized raster image. Pure; safe to unit test. */
export function validateQrFile(file: { name: string; type: string; size: number }): string | null {
  const typeOk = file.type ? QR_ACCEPT.includes(file.type.toLowerCase()) : EXT_RE.test(file.name);
  if (!typeOk) {
    return `“${file.name}” is not a supported image. Use PNG, JPEG, WebP, GIF or BMP.`;
  }
  if (file.size === 0) return `“${file.name}” is empty.`;
  if (file.size > QR_MAX_BYTES) {
    return `“${file.name}” is ${(file.size / 1024 / 1024).toFixed(1)} MB. The limit is ${QR_MAX_BYTES / 1024 / 1024} MB.`;
  }
  return null;
}

async function loadBitmap(file: Blob): Promise<ImageBitmap | HTMLImageElement> {
  if (typeof createImageBitmap === 'function') {
    try {
      return await createImageBitmap(file);
    } catch {
      // fall back to <img>, which supports a few more formats in some browsers
    }
  }
  const url = URL.createObjectURL(file);
  try {
    const img = new Image();
    img.decoding = 'async';
    img.src = url;
    await img.decode();
    return img;
  } catch {
    throw new QrError('The file could not be read as an image. It may be corrupted or not really an image.');
  } finally {
    URL.revokeObjectURL(url);
  }
}

function pixels(img: ImageBitmap | HTMLImageElement, maxDim: number): ImageData {
  const w0 = 'naturalWidth' in img ? img.naturalWidth : img.width;
  const h0 = 'naturalHeight' in img ? img.naturalHeight : img.height;
  if (!w0 || !h0) throw new QrError('The image has no pixels.');
  const scale = Math.min(1, maxDim / Math.max(w0, h0));
  const w = Math.max(1, Math.round(w0 * scale));
  const h = Math.max(1, Math.round(h0 * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) throw new QrError('This browser cannot read image pixels.');
  ctx.fillStyle = '#fff'; // flatten transparency onto white so transparent QR PNGs decode
  ctx.fillRect(0, 0, w, h);
  ctx.drawImage(img, 0, 0, w, h);
  return ctx.getImageData(0, 0, w, h);
}

/** Main-thread fallback, loaded only if the Worker is unavailable. */
async function decodeOnMainThread(img: ImageData): Promise<string | null> {
  const { default: jsQR } = await import('jsqr');
  return jsQR(img.data, img.width, img.height, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

let worker: Worker | null = null;
let workerBroken = false;
let nextId = 1;

function getWorker(): Worker | null {
  if (workerBroken || typeof Worker === 'undefined') return null;
  if (!worker) {
    try {
      worker = new Worker(new URL('./decode.worker.ts', import.meta.url), { type: 'module' });
    } catch {
      workerBroken = true;
      return null;
    }
  }
  return worker;
}

function decodeInWorker(img: ImageData): Promise<string | null> {
  const w = getWorker();
  if (!w) return decodeOnMainThread(img);
  const id = nextId++;
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => {
      cleanup();
      reject(new QrError('Decoding took too long. Try a smaller or sharper image.'));
    }, TIMEOUT_MS);
    const onMessage = (e: MessageEvent<DecodeResponse>) => {
      if (e.data.id !== id) return;
      cleanup();
      if ('error' in e.data) reject(new QrError(`The decoder failed: ${e.data.error}`));
      else resolve(e.data.text);
    };
    const onError = () => {
      cleanup();
      workerBroken = true;
      worker = null;
      // Retry on the main thread rather than failing outright.
      decodeOnMainThread(img).then(resolve, reject);
    };
    function cleanup() {
      window.clearTimeout(timer);
      w!.removeEventListener('message', onMessage);
      w!.removeEventListener('error', onError);
    }
    w.addEventListener('message', onMessage);
    w.addEventListener('error', onError);
    // Transfer a copy so the original pixels stay usable for the main-thread fallback.
    const buf = img.data.slice().buffer;
    w.postMessage({ id, data: buf, width: img.width, height: img.height } satisfies DecodeRequest, [buf]);
  });
}

/** Decode a QR image entirely in the browser. Returns the raw encoded text. */
export async function decodeQrImage(file: File): Promise<{ text: string; width: number; height: number }> {
  const invalid = validateQrFile(file);
  if (invalid) throw new QrError(invalid);
  const img = await loadBitmap(file);
  const width = 'naturalWidth' in img ? img.naturalWidth : img.width;
  const height = 'naturalHeight' in img ? img.naturalHeight : img.height;
  try {
    // Skip a smaller scale when the image is already below it; it would decode identical pixels.
    const scales = SCALES.filter((s, i) => i === 0 || Math.max(width, height) > s);
    for (const max of scales) {
      const text = await decodeInWorker(pixels(img, max));
      if (text !== null) return { text, width, height };
    }
  } finally {
    if ('close' in img) img.close();
  }
  throw new QrError('No QR code was found in this image. Make sure the whole code is visible, in focus and not too small.');
}
