/** Where the analyzed input came from. Carried into results and reports. */
export type InputSource =
  | { kind: 'manual' }
  | {
      kind: 'qr';
      fileName: string;
      /** Decoded content as displayed (secrets masked). */
      decoded: string;
      contentLabel: string;
    };

export const MANUAL_SOURCE: InputSource = { kind: 'manual' };
