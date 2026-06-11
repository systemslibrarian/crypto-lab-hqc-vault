import type { GlossTerm } from "./ui";

export const GLOSSARY: Record<string, GlossTerm> = {
  kem: {
    short: "KEM (Key Encapsulation Mechanism)",
    long: "An asymmetric primitive that lets a sender derive a shared secret using only the receiver's public key. The sender outputs (ciphertext, shared_secret); the receiver recovers shared_secret from the ciphertext using their private key. KEMs replaced public-key encryption for key exchange because they are simpler to make CCA-secure."
  },
  dem: {
    short: "DEM (Data Encapsulation Mechanism)",
    long: "A symmetric authenticated cipher (here AES-256-GCM) that consumes the shared secret produced by a KEM and uses it to actually encrypt the message payload. KEM derives the key; DEM encrypts the bulk data."
  },
  dsd: {
    short: "DSD (Decisional Syndrome Decoding)",
    long: "The hardness assumption underlying HQC. Distinguishing a syndrome s = x + h*y from random (where x, y are sparse) is believed to be hard even for quantum adversaries. HQC's IND-CPA security reduces to a quasi-cyclic variant called QCSD."
  },
  qcsd: {
    short: "QCSD (Quasi-Cyclic Syndrome Decoding)",
    long: "The quasi-cyclic instantiation of the syndrome decoding problem. Using circulant blocks shrinks key sizes versus McEliece-style random codes but introduces structural assumptions that have so far resisted attack."
  },
  dfr: {
    short: "DFR (Decoding Failure Rate)",
    long: "The probability that a KEM's decoder cannot recover the message from a valid ciphertext, taken over the randomness of key generation and encapsulation. HQC's concatenated code is designed for perfect correctness (DFR = 0); BIKE only achieves a small, parameterized DFR like 2^-128."
  },
  fo: {
    short: "FO Transform (Fujisaki–Okamoto)",
    long: "A generic compiler from an IND-CPA encryption scheme to an IND-CCA KEM. The decapsulator re-encapsulates the recovered message and checks the ciphertext byte-for-byte; any mismatch triggers implicit rejection. The helper value d in HQC plays this verification role."
  },
  cca: {
    short: "IND-CCA (Indistinguishability under Chosen-Ciphertext Attack)",
    long: "The standard security goal for modern KEMs. An adversary granted a decapsulation oracle on any ciphertext except the challenge must still fail to distinguish two encapsulated secrets. The FO transform is what lifts HQC from IND-CPA to IND-CCA."
  },
  "gf(2)": {
    short: "GF(2) — the binary field",
    long: "The two-element field with addition = XOR and multiplication = AND. HQC's quasi-cyclic vectors and circulant operations all live over GF(2), which makes them efficient on commodity hardware."
  },
  "gf(16)": {
    short: "GF(16) — a 4-bit field",
    long: "The field with 16 elements, used here for the toy Reed-Solomon outer code. Each symbol is a 4-bit nibble; arithmetic uses log/exp tables built from the primitive polynomial x^4 + x + 1."
  },
  "reed-muller": {
    short: "Reed-Muller code RM(1, m)",
    long: "A linear code mapping m+1 bits into 2^m bits with minimum distance 2^(m-1). The dual is also Reed-Muller, which gives elegant fast-Hadamard-transform decoding. HQC uses RM(1, 7) in production; this demo uses RM(1, 3) for legibility."
  },
  "reed-solomon": {
    short: "Reed-Solomon code RS(n, k)",
    long: "A maximum-distance-separable code over a finite field. RS(n, k) has minimum distance n - k + 1 and corrects up to (n - k) / 2 symbol errors. Decoded here with Berlekamp-Massey + Chien search + Forney's algorithm."
  },
  "harvest-now-decrypt-later": {
    short: "Harvest-now-decrypt-later",
    long: "An adversary captures TLS traffic today and stores it, planning to decrypt it once large quantum computers exist. Any session whose long-term confidentiality matters past 2030 should already be migrating to post-quantum KEMs."
  },
  "quasi-cyclic": {
    short: "Quasi-cyclic codes",
    long: "Codes whose generator/parity-check matrices are made of circulant blocks. A circulant is fully described by its first row, so storage shrinks from O(n^2) to O(n). HQC, BIKE, and McEliece variants all exploit this structure."
  },
  "ml-kem": {
    short: "ML-KEM (FIPS 203)",
    long: "The standardized name for CRYSTALS-Kyber, NIST's first post-quantum KEM standard (FIPS 203, 2024). Lattice-based, currently the default recommendation; HQC was selected in 2025 as a code-based diversity track."
  },
  bike: {
    short: "BIKE",
    long: "Bit-Flipping Key Encapsulation. Another QC-based KEM that uses QC-MDPC decoding instead of HQC's concatenated codes. Smaller artifacts than HQC but a non-zero decoding failure rate is a structural design choice."
  },
  mceliece: {
    short: "Classic McEliece (1978)",
    long: "The original code-based public-key cryptosystem, by Robert McEliece. Uses random binary Goppa codes. Tiny ciphertexts and very high confidence after 45+ years of cryptanalysis, at the cost of enormous public keys (~1 MB)."
  },
  circulant: {
    short: "Circulant matrix",
    long: "A square matrix where each row is the previous row rotated by one position. Equivalent to multiplication in the polynomial ring F_2[X] / (X^n - 1). Cheap to store, cheap to multiply against sparse vectors."
  },
  "side-channel": {
    short: "Side-channel attack",
    long: "An attack that extracts secret information from a physical implementation rather than the math. Timing, cache behavior, power consumption, electromagnetic emissions all leak. Constant-time code aims to make every secret-dependent path take the same time."
  }
};
