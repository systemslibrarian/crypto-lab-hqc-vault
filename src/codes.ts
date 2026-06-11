// Concatenated code: Reed-Solomon (15, 5) over GF(16) outer + Reed-Muller (1, 3) inner.
// Outer: 5 message nibbles -> 15 codeword nibbles, corrects up to 5 symbol errors.
// Inner: each 4-bit symbol -> 8-bit RM codeword (distance 4, corrects 1 bit error).
// Together: 20-bit seed -> 120-bit codeword, with majority-logic + Berlekamp-Massey decoders.

export interface DecoderLayer {
  id: string;
  title: string;
  detail: string;
}

export const concatenatedCodeLayers: DecoderLayer[] = [
  {
    id: "rm",
    title: "Inner Layer: Reed-Muller (1,3)",
    detail:
      "Each 4-bit symbol is expanded to an 8-bit codeword with minimum distance 4. Reed's majority-logic decoder corrects a single bit error inside every 8-bit block."
  },
  {
    id: "rs",
    title: "Outer Layer: Reed-Solomon (15,5) over GF(16)",
    detail:
      "The 15 surviving symbols form a Reed-Solomon codeword. Berlekamp-Massey + Chien + Forney recover the original 5-nibble message even when up to 5 RM blocks decode wrong."
  },
  {
    id: "concat",
    title: "Concatenation",
    detail:
      "Bit-level noise is absorbed by Reed-Muller; whichever RM blocks still fail show up to Reed-Solomon as isolated symbol errors. The composition is what gives HQC its perfect-correctness design."
  }
];

// -------------------- GF(16) arithmetic (primitive poly x^4 + x + 1 = 0x13) --------------------

const GF_EXP = new Uint8Array(30);
const GF_LOG = new Uint8Array(16);

(function initGF() {
  let x = 1;
  for (let i = 0; i < 15; i += 1) {
    GF_EXP[i] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x10) x ^= 0x13;
  }
  for (let i = 15; i < 30; i += 1) GF_EXP[i] = GF_EXP[i - 15];
})();

function gfMul(a: number, b: number): number {
  if (a === 0 || b === 0) return 0;
  return GF_EXP[(GF_LOG[a] + GF_LOG[b]) % 15];
}

function gfDiv(a: number, b: number): number {
  if (a === 0) return 0;
  if (b === 0) throw new Error("GF(16) division by zero");
  return GF_EXP[(GF_LOG[a] - GF_LOG[b] + 15) % 15];
}

// -------------------- Reed-Solomon (15, 5) over GF(16) --------------------

export const RS_N = 15;
export const RS_K = 4;
export const RS_T = (RS_N - RS_K) >> 1; // 5

// Generator polynomial g(x) = prod_{i=1..(N-K)} (x - alpha^i). Stored leading-coefficient first.
const RS_GEN: Uint8Array = (() => {
  let g: number[] = [1];
  for (let i = 1; i <= RS_N - RS_K; i += 1) {
    const a = GF_EXP[i];
    const next = new Array<number>(g.length + 1).fill(0);
    for (let j = 0; j < g.length; j += 1) {
      next[j] ^= g[j];
      next[j + 1] ^= gfMul(g[j], a);
    }
    g = next;
  }
  return Uint8Array.from(g);
})();

function rsEncode(msg: number[]): number[] {
  const work = new Array<number>(RS_N).fill(0);
  for (let i = 0; i < RS_K; i += 1) work[i] = msg[i];
  for (let i = 0; i < RS_K; i += 1) {
    const coef = work[i];
    if (coef !== 0) {
      for (let j = 1; j < RS_GEN.length; j += 1) {
        work[i + j] ^= gfMul(coef, RS_GEN[j]);
      }
    }
  }
  const code = new Array<number>(RS_N);
  for (let i = 0; i < RS_K; i += 1) code[i] = msg[i];
  for (let i = RS_K; i < RS_N; i += 1) code[i] = work[i];
  return code;
}

function rsSyndromes(received: number[]): number[] {
  const S = new Array<number>(RS_N - RS_K).fill(0);
  for (let i = 0; i < S.length; i += 1) {
    const a = GF_EXP[i + 1];
    let v = 0;
    for (let j = 0; j < RS_N; j += 1) {
      v = gfMul(v, a) ^ received[j];
    }
    S[i] = v;
  }
  return S;
}

function rsBerlekampMassey(syn: number[]): number[] {
  let Lambda: number[] = [1];
  let B: number[] = [1];
  let L = 0;
  let m = 1;
  let b = 1;

  for (let n = 0; n < syn.length; n += 1) {
    let d = syn[n];
    for (let i = 1; i <= L; i += 1) {
      if (i < Lambda.length) d ^= gfMul(Lambda[i], syn[n - i]);
    }
    if (d === 0) {
      m += 1;
    } else if (2 * L <= n) {
      const T = Lambda.slice();
      const c = gfDiv(d, b);
      const newLen = Math.max(Lambda.length, B.length + m);
      const next = new Array<number>(newLen).fill(0);
      for (let i = 0; i < Lambda.length; i += 1) next[i] = Lambda[i];
      for (let i = 0; i < B.length; i += 1) next[i + m] ^= gfMul(c, B[i]);
      Lambda = next;
      L = n + 1 - L;
      B = T;
      b = d;
      m = 1;
    } else {
      const c = gfDiv(d, b);
      const newLen = Math.max(Lambda.length, B.length + m);
      const next = new Array<number>(newLen).fill(0);
      for (let i = 0; i < Lambda.length; i += 1) next[i] = Lambda[i];
      for (let i = 0; i < B.length; i += 1) next[i + m] ^= gfMul(c, B[i]);
      Lambda = next;
      m += 1;
    }
  }
  return Lambda;
}

function rsChienSearch(Lambda: number[]): number[] {
  // Position j in array maps to power X_j = alpha^(N-1-j); root X_j^{-1} satisfies Lambda(X_j^{-1}) = 0.
  const positions: number[] = [];
  for (let pos = 0; pos < RS_N; pos += 1) {
    const exp = ((pos - (RS_N - 1)) % 15 + 15) % 15;
    const xInv = GF_EXP[exp];
    let val = 0;
    let p = 1;
    for (let i = 0; i < Lambda.length; i += 1) {
      val ^= gfMul(Lambda[i], p);
      p = gfMul(p, xInv);
    }
    if (val === 0) positions.push(pos);
  }
  return positions;
}

function rsForney(syn: number[], Lambda: number[], errorPositions: number[]): number[] {
  const TWO_T = syn.length;
  const Omega = new Array<number>(TWO_T).fill(0);
  for (let i = 0; i < syn.length; i += 1) {
    for (let j = 0; j < Lambda.length; j += 1) {
      if (i + j < TWO_T) Omega[i + j] ^= gfMul(syn[i], Lambda[j]);
    }
  }

  function evalPoly(coefs: number[], x: number): number {
    let v = 0;
    let p = 1;
    for (let i = 0; i < coefs.length; i += 1) {
      v ^= gfMul(coefs[i], p);
      p = gfMul(p, x);
    }
    return v;
  }

  function evalLambdaPrime(x: number): number {
    // d/dx Lambda over GF(2^m): only odd-degree terms survive, contributing Lambda[i] * x^(i-1).
    let v = 0;
    let xPow = 1;
    const xSquared = gfMul(x, x);
    for (let i = 1; i < Lambda.length; i += 2) {
      v ^= gfMul(Lambda[i], xPow);
      xPow = gfMul(xPow, xSquared);
    }
    return v;
  }

  const values = new Array<number>(errorPositions.length);
  for (let l = 0; l < errorPositions.length; l += 1) {
    const pos = errorPositions[l];
    const exp = ((RS_N - 1 - pos) % 15 + 15) % 15;
    const xInv = GF_EXP[((-exp) % 15 + 15) % 15];
    const numer = evalPoly(Omega, xInv);
    const denom = evalLambdaPrime(xInv);
    if (denom === 0) return new Array<number>(errorPositions.length).fill(0);
    values[l] = gfDiv(numer, denom);
  }
  return values;
}

export interface RsDecodeResult {
  decoded: number[];
  numErrors: number;
}

function rsDecode(received: number[]): RsDecodeResult | null {
  const syn = rsSyndromes(received);
  if (syn.every((s) => s === 0)) {
    return { decoded: received.slice(), numErrors: 0 };
  }

  const Lambda = rsBerlekampMassey(syn);
  const degLambda = Lambda.length - 1;
  if (degLambda === 0 || degLambda > RS_T) return null;

  const errPos = rsChienSearch(Lambda);
  if (errPos.length !== degLambda) return null;

  const errVal = rsForney(syn, Lambda, errPos);
  const corrected = received.slice();
  for (let i = 0; i < errPos.length; i += 1) {
    corrected[errPos[i]] ^= errVal[i];
  }

  const verifySyn = rsSyndromes(corrected);
  if (!verifySyn.every((s) => s === 0)) return null;

  return { decoded: corrected, numErrors: errPos.length };
}

// -------------------- Reed-Muller (1, 3) inner code --------------------

export const RM_M = 3;
export const RM_N = 1 << RM_M; // 8
export const RM_K = RM_M + 1; // 4

function rmEncodeSymbol(symbol: number): Uint8Array {
  const m0 = symbol & 1;
  const m1 = (symbol >> 1) & 1;
  const m2 = (symbol >> 2) & 1;
  const m3 = (symbol >> 3) & 1;
  const c = new Uint8Array(RM_N);
  for (let i = 0; i < RM_N; i += 1) {
    const i0 = i & 1;
    const i1 = (i >> 1) & 1;
    const i2 = (i >> 2) & 1;
    c[i] = m0 ^ (i0 & m1) ^ (i1 & m2) ^ (i2 & m3);
  }
  return c;
}

function majorityBit(votes: number[]): number {
  let ones = 0;
  for (const v of votes) ones += v;
  if (ones * 2 > votes.length) return 1;
  if (ones * 2 < votes.length) return 0;
  return 0; // deterministic tie-break
}

function rmDecodeSymbol(received: Uint8Array): number {
  const m1 = majorityBit([
    received[0] ^ received[1],
    received[2] ^ received[3],
    received[4] ^ received[5],
    received[6] ^ received[7]
  ]);
  const m2 = majorityBit([
    received[0] ^ received[2],
    received[1] ^ received[3],
    received[4] ^ received[6],
    received[5] ^ received[7]
  ]);
  const m3 = majorityBit([
    received[0] ^ received[4],
    received[1] ^ received[5],
    received[2] ^ received[6],
    received[3] ^ received[7]
  ]);

  let zeros = 0;
  let ones = 0;
  for (let i = 0; i < RM_N; i += 1) {
    const i0 = i & 1;
    const i1 = (i >> 1) & 1;
    const i2 = (i >> 2) & 1;
    const residual = received[i] ^ (i0 & m1) ^ (i1 & m2) ^ (i2 & m3);
    if (residual === 0) zeros += 1;
    else ones += 1;
  }
  const m0 = ones > zeros ? 1 : 0;
  return m0 | (m1 << 1) | (m2 << 2) | (m3 << 3);
}

// -------------------- Concatenated code public API --------------------

export const SEED_BYTES = 2; // RS_K=4 nibbles = 16 bits, packed cleanly into 2 bytes
export const CODEWORD_BITS = RS_N * RM_N; // 120

function seedToNibbles(seed: Uint8Array): number[] {
  const out = new Array<number>(RS_K);
  for (let i = 0; i < RS_K; i += 1) {
    const byte = seed[i >> 1] ?? 0;
    out[i] = (byte >> ((i & 1) * 4)) & 0x0f;
  }
  return out;
}

function nibblesToSeed(nibbles: number[]): Uint8Array {
  const out = new Uint8Array(SEED_BYTES);
  for (let i = 0; i < RS_K; i += 1) {
    out[i >> 1] |= (nibbles[i] & 0x0f) << ((i & 1) * 4);
  }
  return out;
}

export function encodeConcatenated(seed: Uint8Array): Uint8Array {
  const nibbles = seedToNibbles(seed);
  const rsCode = rsEncode(nibbles);
  const bits = new Uint8Array(CODEWORD_BITS);
  for (let i = 0; i < RS_N; i += 1) {
    const block = rmEncodeSymbol(rsCode[i]);
    bits.set(block, i * RM_N);
  }
  return bits;
}

export interface ConcatDecodeResult {
  seed: Uint8Array;
  rmBitErrors: number;
  rsSymbolErrors: number;
  decoded: boolean;
  rsSymbols: number[];
}

export function decodeConcatenated(received: Uint8Array): ConcatDecodeResult {
  let rmBitErrors = 0;
  const rsSymbols = new Array<number>(RS_N);
  for (let i = 0; i < RS_N; i += 1) {
    const block = received.slice(i * RM_N, (i + 1) * RM_N);
    const sym = rmDecodeSymbol(block);
    rsSymbols[i] = sym;
    const reencoded = rmEncodeSymbol(sym);
    for (let j = 0; j < RM_N; j += 1) {
      if (block[j] !== reencoded[j]) rmBitErrors += 1;
    }
  }

  const rs = rsDecode(rsSymbols);
  if (!rs) {
    return {
      seed: nibblesToSeed(rsSymbols.slice(0, RS_K)),
      rmBitErrors,
      rsSymbolErrors: -1,
      decoded: false,
      rsSymbols
    };
  }

  return {
    seed: nibblesToSeed(rs.decoded.slice(0, RS_K)),
    rmBitErrors,
    rsSymbolErrors: rs.numErrors,
    decoded: true,
    rsSymbols: rs.decoded
  };
}
