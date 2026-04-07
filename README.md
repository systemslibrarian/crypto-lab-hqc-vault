# crypto-lab-hqc-vault

Live demo: https://systemslibrarian.github.io/crypto-lab-hqc-vault/

HQC · Quasi-Cyclic · Reed-Muller · AES-256-GCM · Code-Based

## Overview

crypto-lab-hqc-vault is a browser-based interactive demo for HQC (Hamming Quasi-Cyclic), a code-based post-quantum KEM in NIST Round 4 discussions and follow-on standardization work.

The app explains how quasi-cyclic binary arithmetic, syndrome-decoding hardness, and concatenated Reed-Muller/Reed-Solomon coding fit into an HQC-style KEM flow. It also compares HQC against BIKE and ML-KEM using published submission/reference figures.

Important: this repository uses an explicitly labeled illustrative model in-browser for educational clarity. It is not a production HQC implementation.

## What You Can Explore

- Panel 1: HQC construction primer, quasi-cyclic structure, DSD/QCSD assumption, and Reed-Muller + Reed-Solomon decoder layers
- Panel 2: Illustrative HQC key generation with exact Round-4 parameter constants shown
- Panel 3: Encapsulation/decapsulation walkthrough with shared-secret match and AES-256-GCM message wrapping
- Panel 4: HQC vs BIKE vs ML-KEM comparison table and size chart
- Panel 5: Algorithmic diversity perspective and migration urgency in the PQ era

## Primitives Used

- HQC concepts (code-based KEM, quasi-cyclic arithmetic over GF(2))
- Reed-Muller + Reed-Solomon concatenated code visualization
- SHA-256 (WebCrypto) for key derivation in the demo flow
- AES-256-GCM (WebCrypto) as DEM layer for message encryption

## Running Locally

1. Install dependencies:

	npm install

2. Start the dev server:

	npm run dev

3. Build for production:

	npm run build

4. Deploy to GitHub Pages:

	npm run deploy

## Security Notes

- This demo is educational and includes an illustrative helper path. It is clearly marked: Illustrative - not production HQC.
- HQC is not yet finalized as a completed NIST FIPS KEM standard. Track NIST Round 4 and post-Round-4 publications (including NIST IR 8545 context and updates).
- For production deployments today, prefer ML-KEM in accordance with current NIST standardization guidance.
- Do not use this demo code directly in production cryptographic systems.

## Accessibility

This project targets WCAG 2.1 AA practices:

- Keyboard navigation throughout all interactive controls
- Visible focus indicators in dark and light modes
- ARIA labels/live regions for dynamic status and errors
- Associated labels for all form controls
- Reduced-motion support via prefers-reduced-motion
- Responsive layout designed mobile-first (320px baseline)

## Why This Matters

Algorithmic diversity is a security resilience strategy. HQC contributes a code-based alternative to lattice-based ML-KEM, with a distinct structure and security assumptions. For high-assurance planning, understanding both dominant and alternate families helps reduce single-family systemic risk.

## Related Demos

- https://systemslibrarian.github.io/crypto-lab-kyber-vault/
- https://systemslibrarian.github.io/crypto-lab-bike-vault/
- https://systemslibrarian.github.io/crypto-lab-mceliece-gate/
- https://systemslibrarian.github.io/crypto-compare/?category=kem
- https://systemslibrarian.github.io/crypto-lab/

So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31