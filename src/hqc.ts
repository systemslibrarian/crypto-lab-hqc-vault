import {
  CODEWORD_BITS,
  SEED_BYTES,
  decodeConcatenated,
  encodeConcatenated
} from "./codes";

export type HqcLevel = "hqc-128" | "hqc-192" | "hqc-256";

export interface HqcParams {
  id: HqcLevel;
  label: string;
  n: number;
  w: number;
  w_e: number;
  w_r: number;
  pkBytes: number;
  ctBytes: number;
  ssBytes: number;
}

export interface IllustrativeParams {
  n: number;
  w: number;
  w_e: number;
  w_r: number;
  pkBytes: number;
  ctBytes: number;
}

export interface HqcKeyPair {
  params: HqcParams;
  illustrative: IllustrativeParams;
  publicKey: {
    h: Uint8Array;
    s: Uint8Array;
  };
  privateKey: {
    x: Uint32Array;
    y: Uint32Array;
  };
}

export interface HqcCiphertext {
  u: Uint8Array;
  v: Uint8Array;
  d: Uint8Array;
}

export interface EncapTrace {
  messageSeed: Uint8Array;
  codewordBits: Uint8Array; // first CODEWORD_BITS bits actually used
  r1: Uint32Array;
  r2: Uint32Array;
  e: Uint32Array;
  epsilon: Uint32Array;
  hr2: Uint8Array;
  sr2: Uint8Array;
  uBits: Uint8Array;
  vBits: Uint8Array;
}

export interface HqcEncapsulation {
  ciphertext: HqcCiphertext;
  sharedSecret: Uint8Array;
  messageSeed: Uint8Array;
  trace: EncapTrace;
}

export interface DecapTrace {
  yu: Uint8Array;
  noisyCodewordBits: Uint8Array; // first CODEWORD_BITS bits
  rmBitErrors: number;
  rsSymbolErrors: number;
  decoded: boolean;
}

export interface HqcDecapsulation {
  sharedSecret: Uint8Array;
  recoveredSeed: Uint8Array;
  verified: boolean;
  trace: DecapTrace;
}

export interface AesEnvelope {
  iv: Uint8Array;
  ciphertext: Uint8Array;
}

export const HQC_PARAMS: Record<HqcLevel, HqcParams> = {
  "hqc-128": {
    id: "hqc-128",
    label: "HQC-128 (NIST Level 1)",
    n: 17669,
    w: 66,
    w_e: 75,
    w_r: 75,
    pkBytes: 2249,
    ctBytes: 4497,
    ssBytes: 64
  },
  "hqc-192": {
    id: "hqc-192",
    label: "HQC-192 (NIST Level 3)",
    n: 35851,
    w: 100,
    w_e: 114,
    w_r: 114,
    pkBytes: 4522,
    ctBytes: 9042,
    ssBytes: 64
  },
  "hqc-256": {
    id: "hqc-256",
    label: "HQC-256 (NIST Level 5)",
    n: 57637,
    w: 131,
    w_e: 149,
    w_r: 149,
    pkBytes: 7245,
    ctBytes: 14485,
    ssBytes: 64
  }
};

// Hand-picked illustrative parameters: large enough that QC structure is real, small enough
// that the noise from x*r2 - y*r1 - y*e + epsilon stays inside the concatenated code's error
// budget on essentially every run (verified empirically by the Verify panel).
export const ILLUSTRATIVE_PARAMS: Record<HqcLevel, IllustrativeParams> = {
  "hqc-128": { n: 384, w: 3, w_e: 3, w_r: 3, pkBytes: Math.ceil(384 / 8) * 2, ctBytes: Math.ceil(384 / 8) * 2 + 32 },
  "hqc-192": { n: 512, w: 4, w_e: 4, w_r: 4, pkBytes: Math.ceil(512 / 8) * 2, ctBytes: Math.ceil(512 / 8) * 2 + 32 },
  "hqc-256": { n: 768, w: 5, w_e: 5, w_r: 5, pkBytes: Math.ceil(768 / 8) * 2, ctBytes: Math.ceil(768 / 8) * 2 + 32 }
};

function randomBytes(len: number): Uint8Array {
  const out = new Uint8Array(len);
  crypto.getRandomValues(out);
  return out;
}

function randomBitVector(n: number): Uint8Array {
  const bytes = randomBytes(Math.ceil(n / 8));
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = (bytes[i >> 3] >> (i & 7)) & 1;
  }
  return out;
}

function randomSparse(n: number, weight: number): Uint32Array {
  const used = new Set<number>();
  while (used.size < weight) {
    const slot = crypto.getRandomValues(new Uint32Array(1))[0] % n;
    used.add(slot);
  }
  return Uint32Array.from(Array.from(used).sort((a, b) => a - b));
}

function sparseToDense(n: number, sparse: Uint32Array): Uint8Array {
  const out = new Uint8Array(n);
  for (const idx of sparse) {
    out[idx] = 1;
  }
  return out;
}

function xorBits(a: Uint8Array, b: Uint8Array): Uint8Array {
  const out = new Uint8Array(a.length);
  for (let i = 0; i < a.length; i += 1) {
    out[i] = a[i] ^ b[i];
  }
  return out;
}

export function circulantMultiplyDenseSparse(h: Uint8Array, sparse: Uint32Array, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (const shift of sparse) {
    for (let i = 0; i < n; i += 1) {
      out[i] ^= h[(i + n - shift) % n];
    }
  }
  return out;
}

function xorSparseNoise(target: Uint8Array, noise: Uint32Array): Uint8Array {
  const out = target.slice();
  for (const idx of noise) {
    out[idx] ^= 1;
  }
  return out;
}

export function bitsToBytes(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i += 1) {
    out[i >> 3] |= bits[i] << (i & 7);
  }
  return out;
}

export function bytesToBits(bytes: Uint8Array, n: number): Uint8Array {
  const out = new Uint8Array(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = (bytes[i >> 3] >> (i & 7)) & 1;
  }
  return out;
}

async function sha256(parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((acc, p) => acc + p.length, 0);
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const p of parts) {
    joined.set(p, offset);
    offset += p.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", joined);
  return new Uint8Array(digest);
}

export function shortHex(bytes: Uint8Array, max = 96): string {
  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  if (hex.length <= max) return hex;
  return `${hex.slice(0, max)}...`;
}

export function fullHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function constantTimeEq(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let acc = 0;
  for (let i = 0; i < a.length; i += 1) acc |= a[i] ^ b[i];
  return acc === 0;
}

export async function generateIllustrativeKeyPair(level: HqcLevel): Promise<HqcKeyPair> {
  const params = HQC_PARAMS[level];
  const ill = ILLUSTRATIVE_PARAMS[level];
  const n = ill.n;

  const h = randomBitVector(n);
  const x = randomSparse(n, ill.w);
  const y = randomSparse(n, ill.w);

  const xDense = sparseToDense(n, x);
  const hTimesY = circulantMultiplyDenseSparse(h, y, n);
  const s = xorBits(xDense, hTimesY); // s = x + h*y (no extra noise in standard HQC)

  return {
    params,
    illustrative: ill,
    publicKey: { h, s },
    privateKey: { x, y }
  };
}

export async function encapsulateIllustrative(keyPair: HqcKeyPair): Promise<HqcEncapsulation> {
  const n = keyPair.publicKey.h.length;
  const { w_r, w_e } = keyPair.illustrative;

  const messageSeed = randomBytes(SEED_BYTES);
  const codewordBits = encodeConcatenated(messageSeed);

  const codeword = new Uint8Array(n);
  codeword.set(codewordBits.subarray(0, Math.min(CODEWORD_BITS, n)));

  const r1 = randomSparse(n, w_r);
  const r2 = randomSparse(n, w_r);
  const e = randomSparse(n, w_e);
  const epsilon = randomSparse(n, w_e);

  const r1Dense = sparseToDense(n, r1);
  const hr2 = circulantMultiplyDenseSparse(keyPair.publicKey.h, r2, n);
  const uBits = xorSparseNoise(xorBits(r1Dense, hr2), e);

  const sr2 = circulantMultiplyDenseSparse(keyPair.publicKey.s, r2, n);
  const vBits = xorSparseNoise(xorBits(codeword, sr2), epsilon);

  const u = bitsToBytes(uBits);
  const v = bitsToBytes(vBits);

  const d = await sha256([messageSeed, u, v, keyPair.publicKey.s]);
  const sharedSecret = await sha256([messageSeed, u, v, d]);

  return {
    ciphertext: { u, v, d },
    sharedSecret,
    messageSeed,
    trace: {
      messageSeed,
      codewordBits,
      r1,
      r2,
      e,
      epsilon,
      hr2,
      sr2,
      uBits,
      vBits
    }
  };
}

export async function decapsulateIllustrative(
  keyPair: HqcKeyPair,
  ciphertext: HqcCiphertext
): Promise<HqcDecapsulation> {
  const n = keyPair.publicKey.h.length;

  const uBits = bytesToBits(ciphertext.u, n);
  const vBits = bytesToBits(ciphertext.v, n);
  const yu = circulantMultiplyDenseSparse(uBits, keyPair.privateKey.y, n);
  const noisy = xorBits(vBits, yu);
  const noisyCodewordBits = noisy.slice(0, CODEWORD_BITS);

  const decodeResult = decodeConcatenated(noisyCodewordBits);
  const recoveredSeed = decodeResult.seed;

  const expectedD = await sha256([recoveredSeed, ciphertext.u, ciphertext.v, keyPair.publicKey.s]);
  const verified = decodeResult.decoded && constantTimeEq(expectedD, ciphertext.d);

  // Implicit rejection: derive key from a fixed zero seed if verification fails.
  // Real HQC uses sigma (a per-key random) plus extra hashing; we keep it simple but distinct.
  const sharedSecret = verified
    ? await sha256([recoveredSeed, ciphertext.u, ciphertext.v, ciphertext.d])
    : await sha256([new Uint8Array(SEED_BYTES), ciphertext.u, ciphertext.v, ciphertext.d, Uint8Array.of(0xff)]);

  return {
    sharedSecret,
    recoveredSeed,
    verified,
    trace: {
      yu,
      noisyCodewordBits,
      rmBitErrors: decodeResult.rmBitErrors,
      rsSymbolErrors: decodeResult.rsSymbolErrors,
      decoded: decodeResult.decoded
    }
  };
}

export async function encryptWithSharedSecret(
  sharedSecret: Uint8Array,
  plaintext: string
): Promise<AesEnvelope> {
  const keyMaterial = sharedSecret.slice(0, 32);
  const aesKey = await crypto.subtle.importKey("raw", keyMaterial, "AES-GCM", false, ["encrypt"]);
  const iv = randomBytes(12);
  const ivView = new Uint8Array(iv.buffer as ArrayBuffer, iv.byteOffset, iv.byteLength);
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv: ivView }, aesKey, encoded);
  return { iv, ciphertext: new Uint8Array(ciphertext) };
}

export async function decryptWithSharedSecret(
  sharedSecret: Uint8Array,
  envelope: AesEnvelope
): Promise<string> {
  const keyMaterial = sharedSecret.slice(0, 32);
  const aesKey = await crypto.subtle.importKey("raw", keyMaterial, "AES-GCM", false, ["decrypt"]);
  const ivView = new Uint8Array(
    envelope.iv.buffer as ArrayBuffer,
    envelope.iv.byteOffset,
    envelope.iv.byteLength
  );
  const ctView = new Uint8Array(
    envelope.ciphertext.buffer as ArrayBuffer,
    envelope.ciphertext.byteOffset,
    envelope.ciphertext.byteLength
  );
  const plainBuffer = await crypto.subtle.decrypt({ name: "AES-GCM", iv: ivView }, aesKey, ctView);
  return new TextDecoder().decode(plainBuffer);
}

// Tamper helper: returns a new ciphertext with one bit flipped in u, v, or d.
export function flipCiphertextBit(
  ciphertext: HqcCiphertext,
  field: "u" | "v" | "d",
  bitIndex: number
): HqcCiphertext {
  const target = ciphertext[field];
  const out = new Uint8Array(target);
  const byteIdx = bitIndex >> 3;
  const bit = bitIndex & 7;
  if (byteIdx < out.length) out[byteIdx] ^= 1 << bit;
  return {
    u: field === "u" ? out : new Uint8Array(ciphertext.u),
    v: field === "v" ? out : new Uint8Array(ciphertext.v),
    d: field === "d" ? out : new Uint8Array(ciphertext.d)
  };
}

// Inject `count` random bit flips into v (the codeword carrier).
export function flipRandomBits(
  ciphertext: HqcCiphertext,
  field: "u" | "v",
  count: number
): { ciphertext: HqcCiphertext; positions: number[] } {
  const target = field === "u" ? ciphertext.u : ciphertext.v;
  const totalBits = target.length * 8;
  const safeCount = Math.max(0, Math.min(count, totalBits));
  const used = new Set<number>();
  while (used.size < safeCount) {
    const idx = crypto.getRandomValues(new Uint32Array(1))[0] % totalBits;
    used.add(idx);
  }
  const positions = Array.from(used);
  const out = new Uint8Array(target);
  for (const idx of positions) {
    out[idx >> 3] ^= 1 << (idx & 7);
  }
  return {
    ciphertext: {
      u: field === "u" ? out : new Uint8Array(ciphertext.u),
      v: field === "v" ? out : new Uint8Array(ciphertext.v),
      d: new Uint8Array(ciphertext.d)
    },
    positions
  };
}
