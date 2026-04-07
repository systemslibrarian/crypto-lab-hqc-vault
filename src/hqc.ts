import { decodeIllustrativeCodeword, encodeIllustrativeCodeword } from "./codes";

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

export interface HqcKeyPair {
  params: HqcParams;
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

export interface HqcEncapsulation {
  ciphertext: HqcCiphertext;
  sharedSecret: Uint8Array;
  messageSeed: Uint8Array;
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

const ILLUSTRATIVE_DIMENSION = 1024;

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

function circulantMultiplyDenseSparse(h: Uint8Array, sparse: Uint32Array, n: number): Uint8Array {
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

function bitsToBytes(bits: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(bits.length / 8));
  for (let i = 0; i < bits.length; i += 1) {
    out[i >> 3] |= bits[i] << (i & 7);
  }
  return out;
}

function bytesToBits(bytes: Uint8Array, n: number): Uint8Array {
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
  if (hex.length <= max) {
    return hex;
  }
  return `${hex.slice(0, max)}...`;
}

export function fullHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function generateIllustrativeKeyPair(level: HqcLevel): Promise<HqcKeyPair> {
  const params = HQC_PARAMS[level];
  const n = Math.min(params.n, ILLUSTRATIVE_DIMENSION);

  const h = randomBitVector(n);
  const x = randomSparse(n, params.w);
  const y = randomSparse(n, params.w);
  const e = randomSparse(n, params.w_e);

  const xDense = sparseToDense(n, x);
  const hTimesY = circulantMultiplyDenseSparse(h, y, n);
  const s = xorSparseNoise(xorBits(xDense, hTimesY), e);

  return {
    params,
    publicKey: { h, s },
    privateKey: { x, y }
  };
}

export async function encapsulateIllustrative(keyPair: HqcKeyPair): Promise<HqcEncapsulation> {
  const n = keyPair.publicKey.h.length;
  const { w_r, w_e } = keyPair.params;

  const messageSeed = randomBytes(32);
  const codeword = encodeIllustrativeCodeword(messageSeed, n);

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

  const helperPad = await sha256([u, v, keyPair.publicKey.s]);
  const d = new Uint8Array(messageSeed.length);
  for (let i = 0; i < messageSeed.length; i += 1) {
    d[i] = messageSeed[i] ^ helperPad[i];
  }

  const sharedSecret = await sha256([messageSeed, u, v, d]);

  return {
    ciphertext: { u, v, d },
    sharedSecret,
    messageSeed
  };
}

export async function decapsulateIllustrative(
  keyPair: HqcKeyPair,
  ciphertext: HqcCiphertext
): Promise<{ sharedSecret: Uint8Array; recoveredSeed: Uint8Array; decoderBits: Uint8Array }> {
  const helperPad = await sha256([ciphertext.u, ciphertext.v, keyPair.publicKey.s]);
  const recoveredSeed = new Uint8Array(ciphertext.d.length);

  for (let i = 0; i < ciphertext.d.length; i += 1) {
    recoveredSeed[i] = ciphertext.d[i] ^ helperPad[i];
  }

  const decoded = decodeIllustrativeCodeword(bytesToBits(ciphertext.v, keyPair.publicKey.h.length), recoveredSeed);
  const sharedSecret = await sha256([recoveredSeed, ciphertext.u, ciphertext.v, ciphertext.d]);

  return {
    sharedSecret,
    recoveredSeed,
    decoderBits: decoded
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
  const plainBuffer = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: ivView },
    aesKey,
    ctView
  );
  return new TextDecoder().decode(plainBuffer);
}
