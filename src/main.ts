import "../styles/main.css";
import { buildBarChartRows, buildComparisonRows, buildSourcesList } from "./compare";
import { CODEWORD_BITS, SEED_BYTES, concatenatedCodeLayers } from "./codes";
import { GLOSSARY } from "./glossary";
import {
  HQC_PARAMS,
  ILLUSTRATIVE_PARAMS,
  bitsToBytes,
  decapsulateIllustrative,
  decryptWithSharedSecret,
  encapsulateIllustrative,
  encryptWithSharedSecret,
  flipCiphertextBit,
  flipRandomBits,
  fullHex,
  generateIllustrativeKeyPair,
  shortHex,
  type HqcEncapsulation,
  type HqcKeyPair,
  type HqcLevel
} from "./hqc";
import { mountConcatVisualizer } from "./concatViz";
import { mountQcVisualizer } from "./qcViz";
import { renderSideChannelChart, runSideChannelDemo } from "./sideChannel";
import {
  announce,
  escapeHtml,
  setupCopyButtons,
  setupGlossary,
  setupLevelSelector,
  setupToc,
  withGlossary
} from "./ui";
import { renderVerifierResults, runVerifier } from "./verifier";

const app = document.querySelector<HTMLDivElement>("#app");
if (!app) throw new Error("Missing app root");

app.innerHTML = `
<div class="page" aria-label="HQC Vault interactive demo">
  <header class="hero" aria-label="Demo header" id="top">
    <span class="chip category" aria-label="Category chip">Post-Quantum KEM</span>
    <button id="theme-toggle" class="theme-toggle" type="button" aria-label="Switch to light mode"></button>
    <div class="cl-hero">
      <div class="cl-hero-main">
        <h1 class="cl-hero-title">HQC Vault</h1>
        <p class="cl-hero-sub">Code-Based PQ KEM · Quasi-Cyclic Syndrome Decoding · FO Transform</p>
        <p class="cl-hero-desc">Build an HQC keypair, then encapsulate and decapsulate through the full quasi-cyclic KEM — Reed-Muller + Reed-Solomon decoding and the FO re-encryption check — and wrap a message end-to-end with the derived AES-256-GCM DEM.</p>
      </div>
      <aside class="cl-hero-why" aria-label="Why it matters">
        <span class="cl-hero-why-label">WHY IT MATTERS</span>
        <p class="cl-hero-why-text">A quantum computer would break today's RSA and ECC key exchange. NIST is standardizing HQC as a code-based backup to lattice schemes, so a single mathematical break can't compromise every deployed handshake at once.</p>
      </aside>
    </div>
    <div class="chip-row" aria-label="Primitive chips">
      <span class="chip">HQC</span>
      <span class="chip">Quasi-Cyclic</span>
      <span class="chip">Reed-Muller</span>
      <span class="chip">Reed-Solomon</span>
      <span class="chip">AES-256-GCM</span>
    </div>
    <p class="warning" role="note">
      Illustrative — not production HQC. This demo uses real quasi-cyclic binary arithmetic,
      a real Berlekamp-Massey + Reed-Muller concatenated decoder, and a real Fujisaki-Okamoto
      verification step — but with toy parameter sizes so it runs in the browser.
    </p>
  </header>

  <nav id="toc" class="toc" aria-label="Section navigation"></nav>

  <main class="panels" id="main-content" aria-label="Interactive HQC panels">

    <section class="panel" id="panel-threat" aria-labelledby="panel-threat-title">
      <h2 id="panel-threat-title">1. Why post-quantum, why now</h2>
      <p>
        ${withGlossary("A working cryptographically-relevant quantum computer would break the RSA and elliptic-curve key exchanges that protect today's TLS, SSH, and VPN traffic. The pragmatic threat is [[harvest-now-decrypt-later]]: every encrypted session captured today can be decrypted later, the moment that computer arrives.")}
      </p>
      <p>
        ${withGlossary("NIST's response is a portfolio. [[ML-KEM]] (the lattice-based standard) is the default, but a second standard — HQC — is being added for algorithmic diversity. If a single hardness family fell to a future attack, the world should still have a fallback that does not share the same assumption.")}
      </p>
      <ul class="threat-list">
        <li>
          <strong>HTTPS for long-lived secrets</strong> — bank records, medical data, contracts —
          should already migrate to PQ-hybrid TLS.
        </li>
        <li>
          <strong>Software signing roots and CA hierarchies</strong> change every decade or longer;
          waiting for the breach is too late.
        </li>
        <li>
          <strong>Diversity is insurance</strong>. Lattice and code-based hardness assumptions are
          independent. A break in one does not implicate the other.
        </li>
      </ul>
    </section>

    <section class="panel" id="panel-construction" aria-labelledby="panel-construction-title">
      <h2 id="panel-construction-title">2. How HQC is built</h2>
      <p class="lede">Start with one line, then add one idea at a time.</p>
      <ol class="build-steps">
        <li>The public key is a single noisy sum: <code>s = x + h·y</code>.</li>
        <li>Here <code>h</code> is a big public random value, and <code>x</code> and <code>y</code> are the private key — two vectors that are almost all zeros (only a few bits set, so they are called <em>sparse</em>).</li>
        <li>Anyone can see <code>s</code> and <code>h</code>. The whole security bet is that recovering the sparse <code>x</code> and <code>y</code> from that sum is hard. That's it — that one recovery problem is what a quantum computer is believed unable to shortcut.</li>
        <li>To send a secret, the sender adds their own fresh noise on top of <code>s</code>. The receiver, who knows <code>y</code>, can subtract most of it back off — but a little leftover noise remains, so we need a way to clean it up.</li>
        <li>That cleanup is an <strong>error-correcting code</strong>: a stack of two layers that together scrub the leftover noise so both sides land on the exact same secret. You will watch those two layers work in panel 2b below.</li>
      </ol>
      <details class="aside">
        <summary>Formal names for what you just read</summary>
        <div>
          <p class="small">${withGlossary("The 'recovering sparse x, y from s = x + h·y is hard' bet is the [[DSD]] assumption; because <code>h</code> is built from [[circulant]] blocks (the [[quasi-cyclic]] structure that shrinks the keys), HQC's exact assumption is [[QCSD]]. This is the same family of syndrome-decoding hardness that has resisted attack for 45 years since [[McEliece]] (1978).")}</p>
          <p class="small">${withGlossary("Turning a one-shot secret into a reusable primitive makes it a [[KEM]]. The two cleanup layers are an inner [[Reed-Muller]] code (fixes stray bits) wrapped by an outer [[Reed-Solomon]] code (fixes whole broken blocks).")}</p>
        </div>
      </details>
      <div class="viz-grid" role="list" aria-label="Code construction layers">
        ${concatenatedCodeLayers
          .map(
            (layer) => `
          <article class="mini-card" role="listitem">
            <h3>${escapeHtml(layer.title)}</h3>
            <p>${escapeHtml(layer.detail)}</p>
          </article>`
          )
          .join("")}
      </div>

      <h3>Quasi-cyclic arithmetic — click to play</h3>
      <p class="small">
        ${withGlossary("A [[circulant]] is fully described by its first row; multiplying it against a sparse vector reduces to XOR-ing a few rotations. That is the whole reason HQC keys fit in kilobytes instead of megabytes.")}
      </p>
      <div id="qc-viz"></div>
    </section>

    <section class="panel" id="panel-concat" aria-labelledby="panel-concat-title">
      <h2 id="panel-concat-title">2b. The two-layer error-correcting code — click to break it</h2>
      <p>
        When the receiver subtracts <code>y·u</code> from <code>v</code>, they get the sender's codeword
        <em>plus a little leftover noise</em>. HQC scrubs that noise with two stacked codes. Watch them
        work: flip bits below and the counters and per-block badges update from the real decoder.
      </p>
      <ul class="two-layer-key">
        <li><strong>Inner — Reed-Muller:</strong> inside every 8-bit block it takes a majority vote and fixes one stray bit.</li>
        <li><strong>Outer — Reed-Solomon:</strong> if a block takes too much noise and flips to the wrong symbol, RS treats that whole block as one symbol error and rebuilds it (up to 5 of the 15 blocks).</li>
      </ul>
      <div id="concat-viz"></div>
    </section>

    <section class="panel" id="panel-keygen" aria-labelledby="panel-keygen-title">
      <h2 id="panel-keygen-title">3. Key generation</h2>
      <div class="controls-row">
        <label for="hqc-level">HQC parameter set</label>
        <select id="hqc-level" aria-label="HQC parameter set selector">
          <option value="hqc-128">HQC-128 (Level 1)</option>
          <option value="hqc-192">HQC-192 (Level 3)</option>
          <option value="hqc-256">HQC-256 (Level 5)</option>
        </select>
        <button id="keygen-btn" class="btn">Generate keypair</button>
        <span class="chip status">NIST Round 4 selection (2025) — diversity track</span>
      </div>
      <p>
        ${withGlossary("Private key: two sparse vectors (x, y) of low Hamming weight. Public key: (h, s) with h uniformly random and s = x + h·y over [[GF(2)]] using quasi-cyclic arithmetic. The hard part — recovering (x, y) from s — is the [[QCSD]] assumption.")}
      </p>
      <div id="sizing-table" class="sizing-table" aria-live="polite"></div>
      <div id="keygen-output" class="output" aria-live="polite"></div>
    </section>

    <section class="panel" id="panel-encap" aria-labelledby="panel-encap-title">
      <h2 id="panel-encap-title">4. Encapsulation and decapsulation</h2>
      <div class="controls-row">
        <button id="encap-btn" class="btn">Run encap and decap</button>
        <button id="step-toggle" class="btn secondary" aria-pressed="false">Show step-by-step</button>
      </div>
      <p class="small">
        ${withGlossary("Encap chooses a random message seed, encodes it via the concatenated code, and ships u = r1 + h·r2 + e and v = codeword + s·r2 + ε. Decap computes v − y·u — which equals codeword plus a small noise term — and runs the decoder. The helper value d is the [[FO]] verification tag that lifts the scheme from CPA to [[CCA]].")}
      </p>
      <div id="kem-output" class="output" aria-live="polite"></div>
      <div id="kem-steps" class="kem-steps" hidden></div>
    </section>

    <section class="panel" id="panel-aes" aria-labelledby="panel-aes-title">
      <h2 id="panel-aes-title">5. KEM + DEM: encrypt a message</h2>
      <p>
        ${withGlossary("A [[KEM]] only derives a shared secret. To encrypt a payload you pair it with a symmetric [[DEM]] — here AES-256-GCM, using the first 32 bytes of HQC's 64-byte shared secret as the key.")}
      </p>
      <form id="aes-form" class="aes-form">
        <label for="message-input">Message to encrypt with AES-256-GCM</label>
        <textarea id="message-input" rows="3" placeholder="Type a message">Harvest-now decrypt-later risk is why PQ migration is urgent.</textarea>
        <button type="submit" class="btn">Encrypt and decrypt</button>
      </form>
      <div id="aes-output" class="output" aria-live="polite"></div>
    </section>

    <section class="panel" id="panel-bitflip" aria-labelledby="panel-bitflip-title">
      <h2 id="panel-bitflip-title">6. Bit-flip lab — watch the error budget at work</h2>
      <p>
        Inject random bit flips into the ciphertext component <code>v</code> and watch how the
        concatenated decoder copes. Below the code's error budget, the message seed is
        recovered exactly. Above it, the seed flips into nonsense — and any change at all
        also makes the FO check reject. This is the difference between the code's correctness
        property and the KEM's CCA security.
      </p>
      <div class="controls-row">
        <label for="flip-slider">Bits to flip in v: <strong id="flip-count">0</strong></label>
        <input id="flip-slider" type="range" min="0" max="40" value="0" aria-label="Bits to flip in ciphertext v" />
        <button id="flip-run" class="btn">Run with these flips</button>
      </div>
      <div id="flip-output" class="output" aria-live="polite">Generate a keypair and run encap first.</div>
    </section>

    <section class="panel" id="panel-tamper" aria-labelledby="panel-tamper-title">
      <h2 id="panel-tamper-title">7. Tamper lab — IND-CCA in one click</h2>
      <p>
        ${withGlossary("Flip a single bit in u, v, or d. The decoder may still recover the seed (because the inner+outer code absorbs noise), but [[FO]] verification re-derives d from the recovered seed and compares it byte-for-byte against the ciphertext's d. Any mismatch — even one bit — triggers implicit rejection and the shared secret diverges.")}
      </p>
      <div class="controls-row">
        <label for="tamper-field">Tamper field:</label>
        <select id="tamper-field">
          <option value="u">u (ciphertext)</option>
          <option value="v">v (codeword carrier)</option>
          <option value="d">d (FO verification tag)</option>
        </select>
        <label for="tamper-bit">Bit index:</label>
        <input id="tamper-bit" type="number" min="0" value="0" aria-label="Bit index to flip" />
        <button id="tamper-run" class="btn">Flip one bit and decap</button>
      </div>
      <div id="tamper-output" class="output" aria-live="polite">Generate a keypair and run encap first.</div>
    </section>

    <section class="panel" id="panel-sidechannel" aria-labelledby="panel-sidechannel-title">
      <h2 id="panel-sidechannel-title">8. Side-channel timing toy</h2>
      <p>
        ${withGlossary("Production HQC implementations care obsessively about constant-time code. The reason is that any variable-time access pattern over a secret leaks information through a [[side-channel]] — timing, cache state, branch prediction. Here is the toy version of that leak.")}
      </p>
      <div class="controls-row">
        <button id="sc-run" class="btn">Measure timings</button>
      </div>
      <div id="sc-output" class="output" aria-live="polite"></div>
    </section>

    <section class="panel" id="panel-verify" aria-labelledby="panel-verify-title">
      <h2 id="panel-verify-title">9. Empirical correctness verifier</h2>
      <p>
        Run many independent keypairs and ciphertexts through the full encap/decap loop.
        The clean rate measures whether perfect correctness actually holds on the chosen
        illustrative parameters; the flip table measures the code's error budget without
        the FO check rejecting first.
      </p>
      <div class="controls-row">
        <label for="verify-trials">Trials per condition:</label>
        <select id="verify-trials">
          <option value="20">20 (fast)</option>
          <option value="50" selected>50</option>
          <option value="100">100 (slow)</option>
        </select>
        <button id="verify-run" class="btn">Run verifier</button>
        <span id="verify-progress" class="small"></span>
      </div>
      <div id="verify-output" class="output" aria-live="polite"></div>
    </section>

    <section class="panel" id="panel-compare" aria-labelledby="panel-compare-title">
      <h2 id="panel-compare-title">10. HQC vs BIKE vs ML-KEM</h2>
      <div class="controls-row">
        <label for="compare-level">Comparison level</label>
        <select id="compare-level" aria-label="Select security level for bar chart">
          <option value="L1">Level 1 / 128-bit</option>
          <option value="L3">Level 3 / 192-bit</option>
          <option value="L5">Level 5 / 256-bit</option>
        </select>
      </div>
      <div class="table-wrap" aria-label="Three-way KEM comparison table">
        <table>
          <caption>Published values from HQC and BIKE Round-4 submissions plus Kyber/ML-KEM reference tables</caption>
          <thead>
            <tr>
              <th>Variant</th><th>PK (B)</th><th>CT (B)</th><th>SS (B)</th>
              <th>Keygen</th><th>Encap</th><th>Decap</th>
              <th>Assumption</th><th>Correctness / DFR</th>
            </tr>
          </thead>
          <tbody id="compare-rows">${buildComparisonRows()}</tbody>
        </table>
      </div>
      <div id="size-bars" class="bars" role="list" aria-label="Key plus ciphertext size bars"></div>
      <div class="callouts">
        <span class="chip status">ML-KEM: recommended default</span>
        <span class="chip status">HQC: acceptable for diversity</span>
        <span class="chip status">BIKE: acceptable for diversity, non-zero DFR design</span>
      </div>
      <ul class="sources" aria-label="Benchmark and table sources">${buildSourcesList()}</ul>
    </section>

    <section class="panel" id="panel-diversity" aria-labelledby="panel-diversity-title">
      <h2 id="panel-diversity-title">11. Algorithmic diversity and the PQ landscape</h2>
      <p>
        Relying on a single hardness family is strategically risky. Code-based cryptography
        provides diversity beyond lattice assumptions: McEliece (1978) → BIKE → HQC. That
        family line has accumulated over four decades of cryptanalytic scrutiny.
      </p>
      <p>
        NIST status: ML-KEM is the deployed default; HQC was selected in 2025 for ongoing
        standardization work (NIST IR 8545 context), reinforcing the code-based diversity track.
      </p>
      <div class="links" aria-label="Related demos">
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noreferrer">crypto-lab-kyber-vault</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noreferrer">crypto-lab-bike-vault</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-mceliece-gate/" target="_blank" rel="noreferrer">crypto-lab-mceliece-gate</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer">crypto-lab-dilithium-seal</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-compare/?category=kem" target="_blank" rel="noreferrer">crypto-compare kem</a>
      </div>
    </section>

    <section class="panel" id="panel-glossary" aria-labelledby="panel-glossary-title">
      <h2 id="panel-glossary-title">12. Glossary</h2>
      <p class="small">Every term in green is also clickable inline throughout the demo.</p>
      <dl class="glossary-list">
        ${Object.entries(GLOSSARY)
          .map(
            ([key, term]) => `
            <dt><button type="button" class="gloss" data-term="${escapeHtml(key)}">${escapeHtml(term.short)}</button></dt>
            <dd>${escapeHtml(term.long)}</dd>`
          )
          .join("")}
      </dl>
    </section>

    <section class="panel" id="panel-export" aria-labelledby="panel-export-title">
      <h2 id="panel-export-title">13. Export this session</h2>
      <p class="small">Downloads the current keypair, ciphertext, shared secrets, and AES envelope as a JSON file so you can take the transcript away or paste it into a notebook.</p>
      <div class="controls-row">
        <button id="export-btn" class="btn">Download run as JSON</button>
      </div>
    </section>

  </main>

  <footer class="footer" aria-label="Footer">
    <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-hqc-vault" target="_blank" rel="noreferrer">github.com/systemslibrarian/crypto-lab-hqc-vault</a>
    <p class="related-demos">Related demos:
      <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noreferrer">crypto-lab-kyber-vault</a>
      <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noreferrer">crypto-lab-bike-vault</a>
      <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-mceliece-gate/" target="_blank" rel="noreferrer">crypto-lab-mceliece-gate</a>
      <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-hqc-timing/" target="_blank" rel="noreferrer">crypto-lab-hqc-timing</a>
      <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-syndrome-drain/" target="_blank" rel="noreferrer">crypto-lab-syndrome-drain</a>
    </p>
    <p>So whether you eat or drink or whatever you do, do it all for the glory of God. — 1 Corinthians 10:31</p>
  </footer>

  <div id="live-region" class="sr-only" aria-live="assertive" aria-atomic="true"></div>
</div>
`;

// ---------- shared state ----------

let currentKeyPair: HqcKeyPair | null = null;
let currentEncap: HqcEncapsulation | null = null;
let stepMode = false;

// ---------- theme ----------

(function setupThemeToggle() {
  const root = document.documentElement;
  const btn = document.querySelector<HTMLButtonElement>("#theme-toggle");
  if (!btn) return;
  const apply = (t: "dark" | "light") => {
    root.dataset.theme = t;
    btn.textContent = t === "dark" ? "🌙" : "☀️";
    btn.setAttribute("aria-label", t === "dark" ? "Switch to light mode" : "Switch to dark mode");
  };
  apply(root.dataset.theme === "light" ? "light" : "dark");
  btn.addEventListener("click", () => {
    const next = root.dataset.theme === "dark" ? "light" : "dark";
    apply(next);
    localStorage.setItem("theme", next);
  });
})();

// ---------- TOC, glossary, copy ----------

setupToc([
  { id: "panel-threat", label: "1. Why PQ" },
  { id: "panel-construction", label: "2. How HQC is built" },
  { id: "panel-concat", label: "2b. Two-layer code" },
  { id: "panel-keygen", label: "3. Keygen" },
  { id: "panel-encap", label: "4. Encap / decap" },
  { id: "panel-aes", label: "5. AES" },
  { id: "panel-bitflip", label: "6. Bit-flip lab" },
  { id: "panel-tamper", label: "7. Tamper lab" },
  { id: "panel-sidechannel", label: "8. Side-channel" },
  { id: "panel-verify", label: "9. Verifier" },
  { id: "panel-compare", label: "10. Compare" },
  { id: "panel-diversity", label: "11. Diversity" },
  { id: "panel-glossary", label: "12. Glossary" }
]);
setupGlossary(GLOSSARY);
setupCopyButtons();
mountQcVisualizer();
mountConcatVisualizer();

// ---------- comparison bars ----------

const bars = document.querySelector<HTMLDivElement>("#size-bars");
function renderBars(level: "L1" | "L3" | "L5") {
  if (bars) bars.innerHTML = buildBarChartRows(level);
}
setupLevelSelector(renderBars);

// ---------- sizing table ----------

function renderSizingTable(level: HqcLevel) {
  const target = document.querySelector<HTMLDivElement>("#sizing-table");
  if (!target) return;
  const spec = HQC_PARAMS[level];
  const ill = ILLUSTRATIVE_PARAMS[level];
  target.innerHTML = `
    <table>
      <caption>Spec sizes vs the toy sizes used in this browser</caption>
      <thead>
        <tr><th></th><th>Real HQC spec</th><th>Illustrative (this demo)</th></tr>
      </thead>
      <tbody>
        <tr><td>Quasi-cyclic dimension n</td><td>${spec.n.toLocaleString()}</td><td>${ill.n}</td></tr>
        <tr><td>Sparse weight w (private key)</td><td>${spec.w}</td><td>${ill.w}</td></tr>
        <tr><td>Encap noise weight w_e</td><td>${spec.w_e}</td><td>${ill.w_e}</td></tr>
        <tr><td>Encap noise weight w_r</td><td>${spec.w_r}</td><td>${ill.w_r}</td></tr>
        <tr><td>Public key size</td><td>${spec.pkBytes.toLocaleString()} B</td><td>≈ ${ill.pkBytes} B</td></tr>
        <tr><td>Ciphertext size</td><td>${spec.ctBytes.toLocaleString()} B</td><td>≈ ${ill.ctBytes} B</td></tr>
        <tr><td>Shared secret size</td><td>${spec.ssBytes} B</td><td>32 B (post-SHA-256)</td></tr>
      </tbody>
    </table>
    <p class="small">
      The illustrative dimension is roughly <strong>${(ill.n / spec.n * 100).toFixed(2)}%</strong> of the spec.
      Weights are kept tiny so the noise term inside v − y·u always lands inside the concatenated
      code's error budget, letting decap succeed reliably enough to teach with.
    </p>
  `;
}

// ---------- keygen ----------

const keygenOutput = document.querySelector<HTMLDivElement>("#keygen-output");
const keygenBtn = document.querySelector<HTMLButtonElement>("#keygen-btn");
const levelSelector = document.querySelector<HTMLSelectElement>("#hqc-level");

if (levelSelector) {
  renderSizingTable(levelSelector.value as HqcLevel);
  levelSelector.addEventListener("change", () => renderSizingTable(levelSelector.value as HqcLevel));
}

if (keygenBtn && keygenOutput && levelSelector) {
  keygenBtn.addEventListener("click", async () => {
    try {
      keygenBtn.disabled = true;
      keygenOutput.textContent = "Generating keypair...";
      announce("Generating illustrative HQC key pair.");

      const level = levelSelector.value as HqcLevel;
      const kp = await generateIllustrativeKeyPair(level);
      currentKeyPair = kp;
      currentEncap = null;

      const hPacked = bitsToBytes(kp.publicKey.h);
      const sPacked = bitsToBytes(kp.publicKey.s);
      keygenOutput.innerHTML = `
        <p><strong>${escapeHtml(kp.params.label)}</strong></p>
        <p>Illustrative n = ${kp.illustrative.n} (vs spec ${kp.params.n.toLocaleString()})</p>
        <p>private x supports (weight ${kp.privateKey.x.length}) = <code>${Array.from(kp.privateKey.x).join(", ")}</code></p>
        <p>private y supports (weight ${kp.privateKey.y.length}) = <code>${Array.from(kp.privateKey.y).join(", ")}</code></p>
        <p>public h (packed hex, ${hPacked.length} B)
          <button class="copy-btn" type="button" data-copy-target="#kp-h">copy</button>
          = <code id="kp-h" class="hex">${fullHex(hPacked)}</code></p>
        <p>public s (packed hex, ${sPacked.length} B)
          <button class="copy-btn" type="button" data-copy-target="#kp-s">copy</button>
          = <code id="kp-s" class="hex">${fullHex(sPacked)}</code></p>
      `;
      announce("Key generation complete.");
    } catch {
      keygenOutput.innerHTML = '<p class="error">Key generation failed. Try again.</p>';
      announce("Error while generating keys.");
    } finally {
      keygenBtn.disabled = false;
    }
  });
}

// ---------- step-through toggle ----------

const stepToggle = document.querySelector<HTMLButtonElement>("#step-toggle");
const stepContainer = document.querySelector<HTMLDivElement>("#kem-steps");
stepToggle?.addEventListener("click", () => {
  stepMode = !stepMode;
  stepToggle.setAttribute("aria-pressed", stepMode ? "true" : "false");
  stepToggle.textContent = stepMode ? "Hide step-by-step" : "Show step-by-step";
  if (stepContainer) stepContainer.hidden = !stepMode;
});

function renderSteps(enc: HqcEncapsulation, dec: { rmBitErrors: number; rsSymbolErrors: number; decoded: boolean; verified: boolean }) {
  if (!stepContainer) return;
  const steps = [
    {
      title: "1. Pick a random message seed (16 bits)",
      detail: `messageSeed = <code class="hex">${fullHex(enc.trace.messageSeed)}</code> &nbsp;(${SEED_BYTES} bytes, ${SEED_BYTES * 8} bits)`
    },
    {
      title: "2. Encode it with RS(15,4) + RM(1,3)",
      detail: `codeword bits (${CODEWORD_BITS} total): <code class="hex">${Array.from(enc.trace.codewordBits).join("")}</code>`
    },
    {
      title: "3. Sample sparse randomness (r1, r2, e, ε)",
      detail: `r1 supports = [${Array.from(enc.trace.r1).slice(0, 12).join(", ")}${enc.trace.r1.length > 12 ? ", …" : ""}]<br>r2 supports = [${Array.from(enc.trace.r2).slice(0, 12).join(", ")}${enc.trace.r2.length > 12 ? ", …" : ""}]`
    },
    {
      title: "4. Compute u = r1 + h·r2 + e",
      detail: `u (hex) = <code class="hex">${shortHex(enc.ciphertext.u)}</code>`
    },
    {
      title: "5. Compute v = codeword + s·r2 + ε",
      detail: `v (hex) = <code class="hex">${shortHex(enc.ciphertext.v)}</code>`
    },
    {
      title: "6. Compute FO verification tag d = SHA-256(m, u, v, s)",
      detail: `d = <code class="hex">${shortHex(enc.ciphertext.d)}</code>`
    },
    {
      title: "7. Derive shared secret K = SHA-256(m, u, v, d)",
      detail: `K = <code class="hex">${shortHex(enc.sharedSecret)}</code>`
    },
    {
      title: "8. Decap: compute v − y·u → noisy codeword",
      detail: `Reed-Muller corrected ${dec.rmBitErrors} bit errors across 15 blocks. ${dec.rsSymbolErrors >= 0 ? `Reed-Solomon then corrected ${dec.rsSymbolErrors} symbol errors.` : "Reed-Solomon could not decode."}`
    },
    {
      title: "9. FO verify: recompute d′ and compare",
      detail: dec.verified ? "<strong>d′ = d</strong> → accept, derive K from the recovered seed." : "<strong>d′ ≠ d</strong> → implicit rejection, derive a synthetic K."
    }
  ];
  stepContainer.innerHTML = `${foDiagramHtml()}${steps
    .map(
      (s, i) => `
      <details class="step" ${i === 0 ? "open" : ""}>
        <summary>${escapeHtml(s.title)}</summary>
        <div>${s.detail}</div>
      </details>`
    )
    .join("")}`;
}

// A tiny wiring diagram of the FO transform: which inputs feed the tag d versus the
// shared secret K. Seeing that d and K share m,u,v but differ (s vs d) is what makes
// the "re-derive d and compare byte-for-byte" rejection idea click.
function foDiagramHtml(): string {
  return `
    <figure class="fo-diagram" aria-label="Dependency diagram: which inputs feed the FO tag d versus the shared secret K">
      <figcaption>How <code>d</code> and <code>K</code> are wired</figcaption>
      <div class="fo-wire">
        <div class="fo-inputs" aria-hidden="true">
          <span class="fo-node">m</span><span class="fo-node">u</span><span class="fo-node">v</span>
          <span class="fo-node fo-s">s</span><span class="fo-node fo-d">d</span>
        </div>
        <div class="fo-eqs">
          <p class="fo-eq"><span class="fo-out">d</span> = SHA-256( <span class="fo-shared">m, u, v</span>, <span class="fo-s-in">s</span> )</p>
          <p class="fo-eq"><span class="fo-out">K</span> = SHA-256( <span class="fo-shared">m, u, v</span>, <span class="fo-d-in">d</span> )</p>
        </div>
      </div>
      <p class="small fo-note">
        Both hashes bind the same <span class="fo-shared-txt">m, u, v</span>. The tag <code>d</code> also
        folds in the public <code>s</code>; the secret <code>K</code> folds in <code>d</code> itself. On decap
        the receiver re-derives <code>d</code> from the <em>recovered</em> <code>m</code> and compares it
        byte-for-byte. Tamper with <code>u</code>, <code>v</code>, or <code>d</code> and the recomputed
        <code>d</code> no longer matches — so <code>K</code> can never collide with the honest one.
      </p>
    </figure>`;
}

// ---------- ciphertext component bars (visual, not just hex) ----------
// Render u, v, d as labeled bars that show each component's SHAPE, using the real
// encapsulation trace. v shows its codeword region vs noise region with the actual
// epsilon noise bits tinted; u is masked randomness; d is a fixed-size tag.

function componentBarsHtml(enc: HqcEncapsulation): string {
  const n = enc.trace.vBits.length;
  const codewordLen = Math.min(CODEWORD_BITS, n);

  // v: split into codeword region (first codewordLen bits) and the rest. Tint the
  // actual epsilon noise positions that fall inside the codeword region.
  const epsInCodeword = Array.from(enc.trace.epsilon).filter((p) => p < codewordLen);
  const epsMarks = epsInCodeword
    .map((p) => `<span class="cb-tick" style="left:${((p + 0.5) / n) * 100}%" aria-hidden="true"></span>`)
    .join("");
  const codewordPct = (codewordLen / n) * 100;

  const vBar = `
    <div class="cb-row">
      <span class="cb-label"><code>v</code><small>codeword + noise</small></span>
      <div class="cb-track" role="img" aria-label="v is a ${n}-bit vector: the first ${codewordLen} bits carry the error-corrected codeword, the remaining bits are masking; ${epsInCodeword.length} tinted ticks mark injected epsilon noise bits inside the codeword region">
        <div class="cb-seg cb-codeword" style="width:${codewordPct}%"><span>codeword region</span></div>
        <div class="cb-seg cb-mask" style="width:${100 - codewordPct}%"><span>masking</span></div>
        ${epsMarks}
      </div>
    </div>`;

  const uBar = `
    <div class="cb-row">
      <span class="cb-label"><code>u</code><small>masked randomness</small></span>
      <div class="cb-track" role="img" aria-label="u is a ${n}-bit vector of masked randomness (r1 + h times r2 + e); it carries no readable structure by design">
        <div class="cb-seg cb-rand" style="width:100%"><span>uniform-looking mask</span></div>
      </div>
    </div>`;

  const dBar = `
    <div class="cb-row">
      <span class="cb-label"><code>d</code><small>FO tag</small></span>
      <div class="cb-track" role="img" aria-label="d is a fixed 32-byte SHA-256 verification tag; its whole job is a byte-for-byte equality check">
        <div class="cb-seg cb-tag" style="width:100%"><span>32-byte fixed tag</span></div>
      </div>
    </div>`;

  return `<div class="cb-bars" aria-label="Ciphertext component shapes">${vBar}${uBar}${dBar}</div>`;
}

// ---------- encap / decap ----------

const kemOutput = document.querySelector<HTMLDivElement>("#kem-output");
const encapBtn = document.querySelector<HTMLButtonElement>("#encap-btn");

if (encapBtn && kemOutput) {
  encapBtn.addEventListener("click", async () => {
    if (!currentKeyPair) {
      kemOutput.innerHTML = '<p class="error">Generate a keypair first.</p>';
      return;
    }
    try {
      encapBtn.disabled = true;
      kemOutput.textContent = "Running encapsulation and decapsulation...";
      const enc = await encapsulateIllustrative(currentKeyPair);
      currentEncap = enc;
      const dec = await decapsulateIllustrative(currentKeyPair, enc.ciphertext);
      const match = fullHex(enc.sharedSecret) === fullHex(dec.sharedSecret);

      kemOutput.innerHTML = `
        <p>Alice K = <code id="alice-k" class="hex">${fullHex(enc.sharedSecret)}</code>
           <button class="copy-btn" type="button" data-copy-target="#alice-k">copy</button></p>
        <p>Bob   K = <code id="bob-k" class="hex">${fullHex(dec.sharedSecret)}</code>
           <button class="copy-btn" type="button" data-copy-target="#bob-k">copy</button></p>
        <p>Result: <strong class="${match ? "ok" : "bad"}">${match ? "MATCH" : "MISMATCH"}</strong>
           &nbsp;FO verified: <strong class="${dec.verified ? "ok" : "bad"}">${dec.verified}</strong>
           &nbsp;RM bit errors corrected: <strong>${dec.trace.rmBitErrors}</strong>
           &nbsp;RS symbol errors corrected: <strong>${dec.trace.rsSymbolErrors >= 0 ? dec.trace.rsSymbolErrors : "—"}</strong></p>
        ${componentBarsHtml(enc)}
        <details class="aside">
          <summary>Show the raw hex for u, v, d</summary>
          <div>
            <p>u = <code class="hex">${shortHex(enc.ciphertext.u)}</code></p>
            <p>v = <code class="hex">${shortHex(enc.ciphertext.v)}</code></p>
            <p>d = <code class="hex">${shortHex(enc.ciphertext.d)}</code></p>
          </div>
        </details>
      `;
      renderSteps(enc, {
        rmBitErrors: dec.trace.rmBitErrors,
        rsSymbolErrors: dec.trace.rsSymbolErrors,
        decoded: dec.trace.decoded,
        verified: dec.verified
      });
      announce(match ? "Encap and decap match." : "Mismatch detected.");
    } catch (err) {
      kemOutput.innerHTML = `<p class="error">Encap/decap failed: ${escapeHtml(String(err))}</p>`;
    } finally {
      encapBtn.disabled = false;
    }
  });
}

// ---------- AES ----------

const aesForm = document.querySelector<HTMLFormElement>("#aes-form");
const aesOutput = document.querySelector<HTMLDivElement>("#aes-output");
const messageInput = document.querySelector<HTMLTextAreaElement>("#message-input");

if (aesForm && aesOutput && messageInput) {
  aesForm.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    if (!currentEncap || !currentKeyPair) {
      aesOutput.innerHTML = '<p class="error">Run encap first to derive a shared secret.</p>';
      return;
    }
    try {
      const message = messageInput.value.trim();
      if (!message) {
        aesOutput.innerHTML = '<p class="error">Please enter a message.</p>';
        return;
      }
      const dec = await decapsulateIllustrative(currentKeyPair, currentEncap.ciphertext);
      const envelope = await encryptWithSharedSecret(dec.sharedSecret, message);
      const plaintext = await decryptWithSharedSecret(dec.sharedSecret, envelope);
      aesOutput.innerHTML = `
        <p>IV = <code class="hex">${fullHex(envelope.iv)}</code></p>
        <p>AES-256-GCM ciphertext = <code id="aes-ct" class="hex">${fullHex(envelope.ciphertext)}</code>
           <button class="copy-btn" type="button" data-copy-target="#aes-ct">copy</button></p>
        <p>Decrypted plaintext = <strong>${escapeHtml(plaintext)}</strong></p>
      `;
    } catch {
      aesOutput.innerHTML = '<p class="error">AES operation failed.</p>';
    }
  });
}

// ---------- bit-flip lab ----------

const flipSlider = document.querySelector<HTMLInputElement>("#flip-slider");
const flipCount = document.querySelector<HTMLSpanElement>("#flip-count");
const flipRun = document.querySelector<HTMLButtonElement>("#flip-run");
const flipOutput = document.querySelector<HTMLDivElement>("#flip-output");

flipSlider?.addEventListener("input", () => {
  if (flipCount) flipCount.textContent = flipSlider.value;
});

flipRun?.addEventListener("click", async () => {
  if (!currentKeyPair || !currentEncap || !flipSlider || !flipOutput) {
    if (flipOutput) flipOutput.innerHTML = '<p class="error">Generate a keypair and run encap first.</p>';
    return;
  }
  const flips = Number(flipSlider.value);
  const tampered = flipRandomBits(currentEncap.ciphertext, "v", flips);
  const dec = await decapsulateIllustrative(currentKeyPair, tampered.ciphertext);
  const seedMatches = fullHex(dec.recoveredSeed) === fullHex(currentEncap.messageSeed);
  flipOutput.innerHTML = `
    <p>Flipped <strong>${flips}</strong> bits at positions [${tampered.positions.slice(0, 16).join(", ")}${tampered.positions.length > 16 ? ", …" : ""}]</p>
    <p>RM corrected ${dec.trace.rmBitErrors} bit errors. RS ${dec.trace.rsSymbolErrors >= 0 ? `corrected ${dec.trace.rsSymbolErrors} symbol errors` : "could not decode"}.</p>
    <p>Seed pre-FO recovered exactly? <strong class="${seedMatches ? "ok" : "bad"}">${seedMatches ? "YES" : "NO"}</strong> &nbsp; FO check accepted? <strong class="${dec.verified ? "ok" : "bad"}">${dec.verified ? "YES" : "NO"}</strong></p>
    <p>Original seed = <code class="hex">${fullHex(currentEncap.messageSeed)}</code></p>
    <p>Recovered seed = <code class="hex">${fullHex(dec.recoveredSeed)}</code></p>
    <p class="small">
      Up to roughly 15 random flips, the concatenated code recovers the seed reliably.
      Beyond that, the seed flips into nonsense. Either way the FO check rejects, because
      <em>any</em> change to v changes the expected d.
    </p>
  `;
});

// ---------- tamper lab ----------

const tamperField = document.querySelector<HTMLSelectElement>("#tamper-field");
const tamperBit = document.querySelector<HTMLInputElement>("#tamper-bit");
const tamperRun = document.querySelector<HTMLButtonElement>("#tamper-run");
const tamperOutput = document.querySelector<HTMLDivElement>("#tamper-output");

tamperRun?.addEventListener("click", async () => {
  if (!currentKeyPair || !currentEncap || !tamperField || !tamperBit || !tamperOutput) {
    if (tamperOutput) tamperOutput.innerHTML = '<p class="error">Generate a keypair and run encap first.</p>';
    return;
  }
  const field = tamperField.value as "u" | "v" | "d";
  const bit = Math.max(0, Number(tamperBit.value));
  const tampered = flipCiphertextBit(currentEncap.ciphertext, field, bit);
  const dec = await decapsulateIllustrative(currentKeyPair, tampered);
  const cleanShared = fullHex(currentEncap.sharedSecret);
  const tamperedShared = fullHex(dec.sharedSecret);
  const sameK = cleanShared === tamperedShared;
  tamperOutput.innerHTML = `
    <p>Flipped bit <strong>${bit}</strong> of <strong>${field}</strong>.</p>
    <p>FO verification: <strong class="${dec.verified ? "ok" : "bad"}">${dec.verified ? "accepted" : "REJECTED — implicit rejection"}</strong></p>
    <p>K matches clean run: <strong class="${sameK ? "ok" : "bad"}">${sameK ? "yes" : "no — divergent K"}</strong></p>
    <p>Clean K     = <code class="hex">${cleanShared}</code></p>
    <p>Tampered K  = <code class="hex">${tamperedShared}</code></p>
    <p class="small">
      The CCA story: even a one-bit change cannot produce a colliding K, so an attacker
      using a decap oracle on tampered ciphertexts learns nothing about the original key.
    </p>
  `;
});

// ---------- side-channel ----------

const scBtn = document.querySelector<HTMLButtonElement>("#sc-run");
const scOutput = document.querySelector<HTMLDivElement>("#sc-output");

scBtn?.addEventListener("click", () => {
  if (!scOutput) return;
  scOutput.textContent = "Measuring...";
  scBtn.disabled = true;
  setTimeout(() => {
    try {
      const result = runSideChannelDemo();
      renderSideChannelChart(scOutput, result);
    } catch (err) {
      scOutput.innerHTML = `<p class="error">${escapeHtml(String(err))}</p>`;
    } finally {
      scBtn.disabled = false;
    }
  }, 10);
});

// ---------- verifier ----------

const verifyBtn = document.querySelector<HTMLButtonElement>("#verify-run");
const verifyTrials = document.querySelector<HTMLSelectElement>("#verify-trials");
const verifyProgress = document.querySelector<HTMLSpanElement>("#verify-progress");
const verifyOutput = document.querySelector<HTMLDivElement>("#verify-output");

verifyBtn?.addEventListener("click", async () => {
  if (!verifyTrials || !verifyProgress || !verifyOutput || !levelSelector) return;
  const level = levelSelector.value as HqcLevel;
  const trials = Number(verifyTrials.value);
  verifyBtn.disabled = true;
  verifyOutput.textContent = "Running...";
  try {
    const final = await runVerifier(level, trials, (p) => {
      verifyProgress.textContent = `${p.done}/${p.total} trials, clean ${p.cleanOk} ok / ${p.cleanFail} fail`;
    });
    renderVerifierResults(verifyOutput, final);
    verifyProgress.textContent = "Done.";
  } catch (err) {
    verifyOutput.innerHTML = `<p class="error">${escapeHtml(String(err))}</p>`;
  } finally {
    verifyBtn.disabled = false;
  }
});

// ---------- export ----------

const exportBtn = document.querySelector<HTMLButtonElement>("#export-btn");
exportBtn?.addEventListener("click", () => {
  if (!currentKeyPair) {
    alert("Generate a keypair first.");
    return;
  }
  const payload = {
    level: currentKeyPair.params.id,
    spec: currentKeyPair.params,
    illustrative: currentKeyPair.illustrative,
    publicKey: {
      h: fullHex(currentKeyPair.publicKey.h),
      s: fullHex(currentKeyPair.publicKey.s)
    },
    privateKey: {
      x: Array.from(currentKeyPair.privateKey.x),
      y: Array.from(currentKeyPair.privateKey.y)
    },
    encap: currentEncap
      ? {
          messageSeed: fullHex(currentEncap.messageSeed),
          sharedSecret: fullHex(currentEncap.sharedSecret),
          ciphertext: {
            u: fullHex(currentEncap.ciphertext.u),
            v: fullHex(currentEncap.ciphertext.v),
            d: fullHex(currentEncap.ciphertext.d)
          }
        }
      : null,
    note: "Illustrative HQC demo output — NOT a production keypair."
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `hqc-vault-${currentKeyPair.params.id}-${Date.now()}.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  announce("Exported run as JSON.");
});
