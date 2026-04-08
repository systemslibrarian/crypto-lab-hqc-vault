# crypto-lab-hqc-vault

Live demo: https://systemslibrarian.github.io/crypto-lab-hqc-vault/

## What It Is

crypto-lab-hqc-vault is a browser-based educational demo centered on HQC, with Reed-Muller and Reed-Solomon shown as concatenated code layers and SHA-256 plus AES-256-GCM used in the illustrative KEM+DEM flow. HQC is an asymmetric post-quantum, code-based key-encapsulation mechanism whose job is to let two parties derive a shared secret over an untrusted channel without relying on a pre-shared symmetric key. The code explicitly presents an illustrative in-browser model with reduced dimensions and helper logic for clarity, so it explains the construction and message flow but is not a production HQC implementation. It also compares HQC against BIKE and ML-KEM to show where the code-based design sits in the broader PQ KEM landscape.

## When to Use It

- Studying code-based post-quantum KEMs alongside lattice-based alternatives. HQC gives a different hardness family than ML-KEM, and this demo makes that algorithmic-diversity tradeoff explicit.
- Teaching how a KEM+DEM workflow fits together. The app lets you derive a shared secret with HQC and then use that secret with AES-256-GCM to encrypt and decrypt a message in the browser.
- Exploring parameter-set tradeoffs across HQC-128, HQC-192, and HQC-256. The UI exposes those exact parameter families so you can inspect how the demo maps level changes to sizes and flow.
- Not for production cryptography. The repository labels itself as illustrative, uses an educational helper path, and does not claim to be a constant-time or standards-conformant HQC deployment.

## Live Demo

Live demo: https://systemslibrarian.github.io/crypto-lab-hqc-vault/

The demo lets you choose HQC-128, HQC-192, or HQC-256, generate an illustrative keypair, and run encapsulation plus decapsulation in the browser. It also supports encrypting and decrypting a message with AES-256-GCM after the shared secret is derived, so the KEM+DEM flow is visible end to end. A separate Comparison level control updates the HQC vs BIKE vs ML-KEM table and size bars.

## What Can Go Wrong

- Side-channel leakage in sparse-vector arithmetic or decoding code. HQC implementations manipulate secret sparse supports and decoder-related state, so variable-time behavior can leak structure that should stay secret.
- Parameter-set mismatch between peers. HQC-128, HQC-192, and HQC-256 use different n, w, w_e, and w_r values, so mixing levels breaks decapsulation and shared-secret agreement.
- Protocol breakage from large artifacts. The published HQC public-key and ciphertext sizes shown in this demo are materially larger than ML-KEM reference sizes, which can stress handshake framing, MTU assumptions, or storage formats.
- Treating an educational helper path as if it were the specified scheme. This repository reduces dimensions in-browser and uses illustrative helper logic, so its correctness and security properties are not a substitute for a full HQC implementation.
- Assuming HQC is the default deployment choice today. The project itself positions HQC as a diversity-track alternative beside ML-KEM, so using it where policy or interoperability expects the current default KEM can create operational problems.

## Real-World Usage

- NIST post-quantum backup KEM standardization track. HQC was selected by NIST in 2025 for standardization as a code-based alternative, so its most important current real-world use is in standards work rather than broad default deployment.
- liboqs. The Open Quantum Safe library includes HQC parameter sets so engineers can benchmark, test, and integrate HQC in post-quantum evaluation environments.
- oqs-provider for OpenSSL 3. This provider exposes liboqs algorithms, including HQC when enabled, so applications and TLS stacks can run interoperability experiments with HQC-backed KEMs.
- PQClean. PQClean carries clean HQC implementations that downstream projects use for portability, comparison, and implementation review.
- SUPERCOP/eBACS benchmarking. The benchmarking suite includes HQC implementations so implementers can measure key generation, encapsulation, and decapsulation costs across platforms.

## Related Demos

- https://systemslibrarian.github.io/crypto-lab-kyber-vault/
- https://systemslibrarian.github.io/crypto-lab-bike-vault/
- https://systemslibrarian.github.io/crypto-lab-mceliece-gate/
- https://systemslibrarian.github.io/crypto-compare/?category=kem
- https://systemslibrarian.github.io/crypto-lab/

> *"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*