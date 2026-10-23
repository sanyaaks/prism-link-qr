/// <reference lib="webworker" />
import jsQR from 'jsqr';

export interface DecodeRequest {
  id: number;
  data: ArrayBuffer;
  width: number;
  height: number;
}

export type DecodeResponse = { id: number; text: string | null } | { id: number; error: string };

self.onmessage = (e: MessageEvent<DecodeRequest>) => {
  const { id, data, width, height } = e.data;
  try {
    const code = jsQR(new Uint8ClampedArray(data), width, height, { inversionAttempts: 'attemptBoth' });
    (self as DedicatedWorkerGlobalScope).postMessage({ id, text: code ? code.data : null } satisfies DecodeResponse);
  } catch (err) {
    (self as DedicatedWorkerGlobalScope).postMessage({ id, error: err instanceof Error ? err.message : 'Decoder failed' } satisfies DecodeResponse);
  }
};
