import "../styles/main.css";
import { buildBarChartRows, buildComparisonRows, buildSourcesList } from "./compare";
import { concatenatedCodeLayers } from "./codes";
import {
  HQC_PARAMS,
  decapsulateIllustrative,
  decryptWithSharedSecret,
  encapsulateIllustrative,
  encryptWithSharedSecret,
  fullHex,
  generateIllustrativeKeyPair,
  shortHex,
  type HqcEncapsulation,
  type HqcKeyPair
} from "./hqc";
import { announce, setupLevelSelector, setupThemeToggle } from "./ui";

const app = document.querySelector<HTMLDivElement>("#app");

if (!app) {
  throw new Error("Missing app root");
}

app.innerHTML = `
<div class="page" aria-label="HQC Vault interactive demo">
  <header class="hero" aria-label="Demo header">
    <div class="header-row">
      <span class="chip category" aria-label="Category chip">Post-Quantum KEM</span>
      <button id="theme-toggle" class="btn secondary" aria-label="Toggle dark and light theme"></button>
    </div>
    <h1>HQC Vault</h1>
    <p class="subtitle">Code-based post-quantum KEM demo focused on Hamming Quasi-Cyclic construction, perfect correctness, and algorithmic diversity.</p>
    <div class="chip-row" aria-label="Primitive chips">
      <span class="chip">HQC</span>
      <span class="chip">Quasi-Cyclic</span>
      <span class="chip">Reed-Muller</span>
      <span class="chip">AES-256-GCM</span>
      <span class="chip">Code-Based</span>
    </div>
    <p class="warning" role="note" aria-label="Simulation disclosure">
      Illustrative - not production HQC. This demo uses real quasi-cyclic binary arithmetic and an educational decoder helper path, not the full constant-time standardized implementation.
    </p>
  </header>

  <main id="main-content" class="panels" aria-label="Interactive HQC panels">
    <section class="panel" aria-labelledby="panel1-title">
      <h2 id="panel1-title">Panel 1 - HQC Construction Primer</h2>
      <p>
        HQC uses quasi-cyclic binary codes, while BIKE uses QC-MDPC decoding. HQC security is based on the Decisional Syndrome Decoding problem (DSD/QCSD setting).
      </p>
      <p>
        HQC concatenates an inner Reed-Muller code with an outer Reed-Solomon code, enabling perfect correctness in the scheme design, unlike BIKE where non-zero DFR is a core design concern.
      </p>
      <div class="viz-grid" role="list" aria-label="Code construction layers">
        ${concatenatedCodeLayers
          .map(
            (layer) => `
          <article class="mini-card" role="listitem" aria-label="${layer.title}">
            <h3>${layer.title}</h3>
            <p>${layer.detail}</p>
          </article>
        `
          )
          .join("")}
      </div>
      <p class="bridge">HQC uses this structure to build a KEM with perfect correctness - unlike BIKE.</p>
      <div class="qc-schematic" aria-label="Quasi-cyclic vector and noise schematic">
        <pre>[x0 x1 ... x(n-1)]
rotate -> circulant product h * y
add sparse noise e
decode via RM then RS layers</pre>
      </div>
    </section>

    <section class="panel" aria-labelledby="panel2-title">
      <h2 id="panel2-title">Panel 2 - HQC Key Generation</h2>
      <div class="controls-row">
        <label for="hqc-level">Choose HQC parameter set</label>
        <select id="hqc-level" aria-label="HQC parameter set selector">
          <option value="hqc-128">HQC-128 (Level 1)</option>
          <option value="hqc-192">HQC-192 (Level 3)</option>
          <option value="hqc-256">HQC-256 (Level 5)</option>
        </select>
        <button id="keygen-btn" class="btn" aria-label="Generate illustrative HQC key pair">Generate keypair</button>
        <span class="chip status" aria-label="NIST status">NIST Round 4 Selection (2025) / Diversity Track</span>
      </div>
      <p class="small">Private key: sparse vectors (x, y). Public key: (h, s) with s = x + h*y + noise over GF(2) using quasi-cyclic arithmetic.</p>
      <div id="keygen-output" class="output" aria-live="polite" aria-label="Key generation output"></div>
    </section>

    <section class="panel" aria-labelledby="panel3-title">
      <h2 id="panel3-title">Panel 3 - Encapsulation and Decapsulation</h2>
      <div class="controls-row">
        <button id="encap-btn" class="btn" aria-label="Run encapsulation and decapsulation">Run encap and decap</button>
      </div>
      <p>
        Encapsulation view: u = r1 + h*r2 + e and v = m*G + s*r2 + epsilon. Decapsulation applies decoder layers and helper check data d. This demo keeps perfect correctness in its illustrative flow.
      </p>
      <div id="kem-output" class="output" aria-live="polite" aria-label="KEM output values"></div>

      <form id="aes-form" class="aes-form" aria-label="AES message form">
        <label for="message-input">Message to encrypt with AES-256-GCM</label>
        <textarea
          id="message-input"
          rows="3"
          aria-label="Plaintext message"
          placeholder="Type a message to wrap with the shared secret"
        >Harvest-now decrypt-later risk is why PQ migration is urgent.</textarea>
        <button type="submit" class="btn" aria-label="Encrypt and decrypt message with shared secret">Encrypt and decrypt</button>
      </form>
      <div id="aes-output" class="output" aria-live="polite" aria-label="AES encryption output"></div>
      <p class="small strong">Perfect correctness demo outcome: K_Alice equals K_Bob on every run in this illustrative educational model.</p>
    </section>

    <section class="panel" aria-labelledby="panel4-title">
      <h2 id="panel4-title">Panel 4 - HQC vs BIKE vs ML-KEM</h2>
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
              <th>Variant</th>
              <th>PK (B)</th>
              <th>CT (B)</th>
              <th>SS (B)</th>
              <th>Keygen</th>
              <th>Encap</th>
              <th>Decap</th>
              <th>Assumption</th>
              <th>Correctness / DFR</th>
            </tr>
          </thead>
          <tbody id="compare-rows">${buildComparisonRows()}</tbody>
        </table>
      </div>

      <div id="size-bars" class="bars" role="list" aria-label="Key plus ciphertext size bars"></div>
      <div class="callouts" aria-label="Status callouts">
        <span class="chip status">ML-KEM: Recommended Default</span>
        <span class="chip status">HQC: Acceptable for diversity</span>
        <span class="chip status">BIKE: Acceptable for diversity, non-zero DFR design</span>
      </div>
      <ul class="sources" aria-label="Benchmark and table sources">
        ${buildSourcesList()}
      </ul>
    </section>

    <section class="panel" aria-labelledby="panel5-title">
      <h2 id="panel5-title">Panel 5 - Algorithmic Diversity and PQ Landscape</h2>
      <p>
        Relying on only one hardness family is strategically risky. Code-based cryptography provides diversity beyond lattice assumptions.
      </p>
      <p>
        Family line: McEliece (1978) -> BIKE -> HQC. This gives over four decades of cryptanalytic scrutiny in the code-based world.
      </p>
      <p>
        NIST status: ML-KEM is deployed now; HQC was selected in 2025 for ongoing standardization work (NIST IR 8545 context), reinforcing code-based diversity.
      </p>
      <p class="why">
        Why this matters: HQC offers perfect correctness and code-based security, making it a compelling alternative when high-assurance environments require algorithmic diversity beside ML-KEM.
      </p>
      <div class="links" aria-label="Related demos">
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-kyber-vault/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-kyber-vault">crypto-lab-kyber-vault</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-bike-vault/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-bike-vault">crypto-lab-bike-vault</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-mceliece-gate/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-mceliece-gate">crypto-lab-mceliece-gate</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-lab-dilithium-seal/" target="_blank" rel="noreferrer" aria-label="Open crypto-lab-dilithium-seal">crypto-lab-dilithium-seal</a>
        <a class="badge" href="https://systemslibrarian.github.io/crypto-compare/?category=kem" target="_blank" rel="noreferrer" aria-label="Open crypto-compare KEM category">crypto-compare kem</a>
      </div>
    </section>
  </main>

  <footer class="footer" aria-label="Footer">
    <a class="badge" href="https://github.com/systemslibrarian/crypto-lab-hqc-vault" target="_blank" rel="noreferrer" aria-label="Open GitHub repository">github.com/systemslibrarian/crypto-lab-hqc-vault</a>
    <p>So whether you eat or drink or whatever you do, do it all for the glory of God. - 1 Corinthians 10:31</p>
  </footer>

  <div id="live-region" class="sr-only" aria-live="assertive" aria-atomic="true"></div>
</div>
`;

setupThemeToggle();

const bars = document.querySelector<HTMLDivElement>("#size-bars");
const keygenOutput = document.querySelector<HTMLDivElement>("#keygen-output");
const kemOutput = document.querySelector<HTMLDivElement>("#kem-output");
const aesOutput = document.querySelector<HTMLDivElement>("#aes-output");
const keygenBtn = document.querySelector<HTMLButtonElement>("#keygen-btn");
const encapBtn = document.querySelector<HTMLButtonElement>("#encap-btn");
const levelSelector = document.querySelector<HTMLSelectElement>("#hqc-level");
const aesForm = document.querySelector<HTMLFormElement>("#aes-form");
const messageInput = document.querySelector<HTMLTextAreaElement>("#message-input");

let currentKeyPair: HqcKeyPair | null = null;
let currentEncapsulation: HqcEncapsulation | null = null;

function renderBars(level: "L1" | "L3" | "L5"): void {
  if (!bars) return;
  bars.innerHTML = buildBarChartRows(level);
}

setupLevelSelector(renderBars);

if (keygenBtn && keygenOutput && levelSelector) {
  keygenBtn.addEventListener("click", async () => {
    try {
      keygenBtn.disabled = true;
      keygenOutput.textContent = "Generating keypair...";
      announce("Generating illustrative HQC key pair.");

      const level = levelSelector.value as "hqc-128" | "hqc-192" | "hqc-256";
      const kp = await generateIllustrativeKeyPair(level);
      currentKeyPair = kp;
      currentEncapsulation = null;

      keygenOutput.innerHTML = `
        <p><strong>${kp.params.label}</strong></p>
        <p>Exact round-4 parameters: n=${HQC_PARAMS[level].n}, w=${HQC_PARAMS[level].w}, w_e=${HQC_PARAMS[level].w_e}, w_r=${HQC_PARAMS[level].w_r}</p>
        <p>Illustrative simulation dimension used in-browser: n=${kp.publicKey.h.length}</p>
        <p>private x (weight ${kp.privateKey.x.length}) = <code>${Array.from(kp.privateKey.x).slice(0, 24).join(", ")}${kp.privateKey.x.length > 24 ? ", ..." : ""}</code></p>
        <p>private y (weight ${kp.privateKey.y.length}) = <code>${Array.from(kp.privateKey.y).slice(0, 24).join(", ")}${kp.privateKey.y.length > 24 ? ", ..." : ""}</code></p>
        <p>public h (hex preview) = <code class="hex">${shortHex(kp.publicKey.h)}</code></p>
        <p>public s (hex preview) = <code class="hex">${shortHex(kp.publicKey.s)}</code></p>
        <p>Security basis: Decisional Syndrome Decoding over quasi-cyclic binary codes.</p>
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

if (encapBtn && kemOutput) {
  encapBtn.addEventListener("click", async () => {
    if (!currentKeyPair) {
      kemOutput.innerHTML = '<p class="error">Generate a keypair first.</p>';
      announce("You need to generate a keypair before encapsulation.");
      return;
    }

    try {
      encapBtn.disabled = true;
      kemOutput.textContent = "Running encapsulation and decapsulation...";

      const encapsulated = await encapsulateIllustrative(currentKeyPair);
      currentEncapsulation = encapsulated;
      const decapsulated = await decapsulateIllustrative(currentKeyPair, encapsulated.ciphertext);

      const matches = fullHex(encapsulated.sharedSecret) === fullHex(decapsulated.sharedSecret);
      const matchText = matches ? "MATCH" : "MISMATCH";

      kemOutput.innerHTML = `
        <p>Alice shared secret = <code class="hex">${fullHex(encapsulated.sharedSecret)}</code></p>
        <p>Bob shared secret = <code class="hex">${fullHex(decapsulated.sharedSecret)}</code></p>
        <p>Result: <strong>${matchText}</strong> (${matches ? "perfect correctness demonstrated" : "check implementation"})</p>
        <p>ciphertext u = <code class="hex">${shortHex(encapsulated.ciphertext.u)}</code></p>
        <p>ciphertext v = <code class="hex">${shortHex(encapsulated.ciphertext.v)}</code></p>
        <p>ciphertext d = <code class="hex">${shortHex(encapsulated.ciphertext.d)}</code></p>
        <p>Recovered message seed (hex) = <code class="hex">${fullHex(decapsulated.recoveredSeed)}</code></p>
      `;

      announce(matches ? "Encapsulation and decapsulation completed with matching keys." : "Key mismatch detected.");
    } catch {
      kemOutput.innerHTML = '<p class="error">Encapsulation/decapsulation failed.</p>';
      announce("Error during encapsulation and decapsulation.");
    } finally {
      encapBtn.disabled = false;
    }
  });
}

if (aesForm && aesOutput && messageInput) {
  aesForm.addEventListener("submit", async (event) => {
    event.preventDefault();

    if (!currentEncapsulation || !currentKeyPair) {
      aesOutput.innerHTML = '<p class="error">Run encapsulation first to derive a shared secret.</p>';
      announce("Run encapsulation first.");
      return;
    }

    try {
      const message = messageInput.value.trim();
      if (!message) {
        aesOutput.innerHTML = '<p class="error">Please enter a message.</p>';
        announce("Message is required.");
        return;
      }

      const decap = await decapsulateIllustrative(currentKeyPair, currentEncapsulation.ciphertext);
      const envelope = await encryptWithSharedSecret(decap.sharedSecret, message);
      const plaintext = await decryptWithSharedSecret(decap.sharedSecret, envelope);

      const escaped = plaintext
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#x27;");
      aesOutput.innerHTML = `
        <p>IV = <code class="hex">${fullHex(envelope.iv)}</code></p>
        <p>AES-256-GCM ciphertext = <code class="hex">${fullHex(envelope.ciphertext)}</code></p>
        <p>Decrypted plaintext = <strong>${escaped}</strong></p>
        <p class="small">KEM + DEM flow complete using WebCrypto AES-256-GCM.</p>
      `;
      announce("AES encryption and decryption succeeded.");
    } catch {
      aesOutput.innerHTML = '<p class="error">AES operation failed.</p>';
      announce("AES operation failed.");
    }
  });
}
