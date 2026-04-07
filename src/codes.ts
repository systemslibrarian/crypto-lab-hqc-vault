export interface DecoderLayer {
  id: string;
  title: string;
  detail: string;
}

export const concatenatedCodeLayers: DecoderLayer[] = [
  {
    id: "rm",
    title: "Inner Layer: Reed-Muller",
    detail:
      "The inner binary Reed-Muller code carries symbols that are robust to random bit flips and supports majority-style decoding."
  },
  {
    id: "rs",
    title: "Outer Layer: Reed-Solomon",
    detail:
      "The outer Reed-Solomon code over GF(256) corrects symbol-level errors after Reed-Muller blocks are decoded."
  },
  {
    id: "concat",
    title: "Concatenation",
    detail:
      "HQC composes both layers so decoding is deterministic for valid ciphertexts, giving perfect correctness in the scheme design."
  }
];

export function encodeIllustrativeCodeword(seed: Uint8Array, n: number): Uint8Array {
  const bits = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    const byte = seed[i % seed.length];
    const parity = ((i * 13 + 7) & 1) ^ ((byte >> (i % 8)) & 1);
    bits[i] = parity;
  }

  // Lightweight repetition/parity pass for pedagogical RS+RM intuition.
  for (let i = 0; i + 2 < n; i += 3) {
    const p = bits[i] ^ bits[i + 1];
    bits[i + 2] = p;
  }

  return bits;
}

export function decodeIllustrativeCodeword(received: Uint8Array, recoveredSeed: Uint8Array): Uint8Array {
  const expected = encodeIllustrativeCodeword(recoveredSeed, received.length);
  const out = received.slice();

  // Majority-like correction per 3-bit micro-block to visualize error correction.
  for (let i = 0; i + 2 < out.length; i += 3) {
    const b0 = out[i];
    const b1 = out[i + 1];
    const b2 = out[i + 2];
    const expectedParity = b0 ^ b1;
    if (b2 !== expectedParity) {
      out[i + 2] = expectedParity;
    }
  }

  // Correct remaining positions against the expected codeword to keep the demo deterministic.
  for (let i = 0; i < out.length; i += 1) {
    if (out[i] !== expected[i]) {
      out[i] = expected[i];
    }
  }

  return out;
}
