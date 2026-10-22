/* The first unit tests in this lab.
 *
 * hqc-vault had no test runner and no unit tests -- only a Playwright a11y
 * suite -- while 195 of its 234 sibling labs use vitest. So the KEM's symmetric
 * half had no ground truth of any kind: the SHA-256 that derives the shared
 * secret (src/hqc.ts:219) and the AES-256-GCM that uses it as a key
 * (src/hqc.ts:358) were entirely unverified.
 *
 * THE VECTORS ARE COPIED FROM THE PUBLICATION, not reproduced from WebCrypto.
 * Both come from NIST's Cryptographic Algorithm Validation Program response
 * files, fetched from csrc.nist.gov:
 *
 *   shabytetestvectors.zip -> SHA256ShortMsg.rsp, the Len = 24 case
 *   gcmtestvectors.zip     -> gcmEncryptExtIV256.rsp, first Count in the
 *                             [Keylen = 256] [IVlen = 96] [PTlen = 128]
 *                             [AADlen = 0] [Taglen = 128] section
 *
 * The GCM section matches what this lab does: a 256-bit key, a 12-byte IV, no
 * additional data, the default tag length.
 *
 * The digest vector is asserted THROUGH the lab's sha256() rather than against
 * crypto.subtle, because an assertion on subtle tests the runtime. A mutation
 * proved that distinction in crypto-lab-bike-vault, where the subtle-facing
 * version let a SHA-1 substitution pass unnoticed.
 */
import { describe, it, expect } from 'vitest';
import {
  sha256,
  bitsToBytes,
  bytesToBits,
  encryptWithSharedSecret,
  decryptWithSharedSecret,
  HQC_PARAMS,
} from './hqc';
import { comparisonRows } from './compare';

const hex = (h: string) => Uint8Array.from((h.match(/../g) ?? []).map((b) => parseInt(b, 16)));
const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

// HQC team specification dated 12 October 2026, Tables 8-9:
// https://pqc-hqc.org/doc/hqc_specifications_2026_10_12.pdf
// Keep the visible parameter chart tied to this version, including its new
// compressed decapsulation-key default and HQC-1 DFR label in compare.ts.
describe('published HQC-1/3/5 parameters used by the sizing chart', () => {
  it.each([
    ['hqc-128', 17669, 67, 76, 2241, 32, 4433],
    ['hqc-192', 35851, 101, 114, 4514, 32, 8978],
    ['hqc-256', 57637, 132, 150, 7237, 32, 14421],
  ] as const)('%s matches Tables 8-9', (name, n, w, wr, pk, dk, ct) => {
    const p = HQC_PARAMS[name];
    expect([p.n, p.w, p.w_r, p.w_e, p.pkBytes, p.dkBytes, p.ctBytes])
      .toEqual([n, w, wr, wr, pk, dk, ct]);
  });

  it('labels the revised HQC-1 DFR bound and benchmark provenance', () => {
    const row = comparisonRows.find((candidate) => candidate.variant === 'HQC-128');
    expect(row?.correctness).toContain('2^-127');
    expect(row?.source).toContain('2026-10-12');
    expect(row?.source).toContain('historical Round-4');
  });
});

const CAVP_GCM = {
  key: '31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22',
  iv: '0d18e06c7c725ac9e362e1ce',
  pt: '2db5168e932556f8089a0622981d017d',
  ct: 'fa4362189661d163fcd6a56d8bf0405a',
  tag: 'd636ac1bbedd5cc3ee727dc2ab4a9489',
};

describe('published NIST vectors for the symmetric half of the KEM', () => {
  it('the shared-secret digest matches CAVP SHA256ShortMsg.rsp, Len = 24', async () => {
    expect(toHex(await sha256([hex('b4190e')])))
      .toBe('dff2e73091f6c05e528896c4c831b9448653dc2ff043528f6769437bc7b975c2');
  });

  it('it concatenates its parts before hashing, rather than hashing each', async () => {
    /* The function takes an array and digests the JOIN. Splitting the same bytes
       across parts must not change the answer -- that is the contract
       encapsulation relies on when it hashes several components together. */
    const whole = await sha256([hex('b4190e')]);
    const split = await sha256([hex('b4'), hex('19'), hex('0e')]);
    expect(toHex(split)).toBe(toHex(whole));
  });

  it('its output is exactly the 32 bytes AES-256 needs as a raw key', async () => {
    expect((await sha256([hex('b4190e')])).length).toBe(32);
  });

  it('AES-256-GCM matches CAVP gcmEncryptExtIV256.rsp, tag appended and 128 bits', async () => {
    const key = await crypto.subtle.importKey(
      'raw', hex(CAVP_GCM.key), 'AES-GCM', false, ['encrypt']);
    const out = new Uint8Array(await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: hex(CAVP_GCM.iv) }, key, hex(CAVP_GCM.pt)));
    expect(toHex(out)).toBe(CAVP_GCM.ct + CAVP_GCM.tag);
    expect(out.length).toBe(16 + 16);
  });
});

describe('the envelope the shared secret seals', () => {
  const secret = () => hex(CAVP_GCM.key);

  it('round-trips, with a 12-byte IV and the tag beyond the plaintext', async () => {
    const env = await encryptWithSharedSecret(secret(), 'the syndrome decoded');
    expect(env.iv.length).toBe(12);
    expect(env.ciphertext.length)
      .toBe(new TextEncoder().encode('the syndrome decoded').length + 16);
    expect(await decryptWithSharedSecret(secret(), env)).toBe('the syndrome decoded');
  });

  it('a wrong shared secret fails rather than returning plaintext', async () => {
    const env = await encryptWithSharedSecret(secret(), 'fail closed');
    const wrong = secret(); wrong[31] ^= 1;
    await expect(decryptWithSharedSecret(wrong, env)).rejects.toThrow();
  });

  it('a tampered ciphertext fails even with the right secret', async () => {
    const env = await encryptWithSharedSecret(secret(), 'tamper target');
    const bad = { iv: env.iv, ciphertext: Uint8Array.from(env.ciphertext) };
    bad.ciphertext[0] ^= 1;
    await expect(decryptWithSharedSecret(secret(), bad)).rejects.toThrow();
  });
});

describe('the bit packing the code words travel in', () => {
  it('round-trips through bytes and back', () => {
    const bits = Uint8Array.from([1, 0, 1, 1, 0, 0, 0, 1, 1, 0]);
    expect(Array.from(bytesToBits(bitsToBytes(bits), bits.length))).toEqual(Array.from(bits));
  });

  /* LSB-FIRST, asserted from the implementation rather than from my assumption.
     `out[i >> 3] |= bits[i] << (i & 7)` puts bit 0 in the LOW bit, so the first
     bit of a code word is value 1 and the eighth is 0x80. My first version of
     this test asserted the opposite and failed -- worth pinning precisely,
     because bytesToBits has to use the same convention or every round trip
     silently reverses each byte, and a round-trip-only test cannot see that. */
  it('packs LSB-first: the first bit is the low bit of the first byte', () => {
    expect(bitsToBytes(Uint8Array.from([1, 0, 0, 0, 0, 0, 0, 0]))[0]).toBe(0x01);
    expect(bitsToBytes(Uint8Array.from([0, 0, 0, 0, 0, 0, 0, 1]))[0]).toBe(0x80);
    expect(bitsToBytes(Uint8Array.from([1, 1, 0, 0, 0, 0, 0, 0]))[0]).toBe(0x03);
  });

  it('bytesToBits reads back in the same order it was written', () => {
    /* The pair must agree. A reversed reader would still round-trip if the
       writer were reversed too, so this checks the reader against a byte
       whose bit order is known rather than against the writer. */
    expect(Array.from(bytesToBits(Uint8Array.from([0x01]), 8)))
      .toEqual([1, 0, 0, 0, 0, 0, 0, 0]);
    expect(Array.from(bytesToBits(Uint8Array.from([0x80]), 8)))
      .toEqual([0, 0, 0, 0, 0, 0, 0, 1]);
  });
});
