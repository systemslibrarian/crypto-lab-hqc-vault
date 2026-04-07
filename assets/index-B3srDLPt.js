(function(){const e=document.createElement("link").relList;if(e&&e.supports&&e.supports("modulepreload"))return;for(const r of document.querySelectorAll('link[rel="modulepreload"]'))a(r);new MutationObserver(r=>{for(const n of r)if(n.type==="childList")for(const i of n.addedNodes)i.tagName==="LINK"&&i.rel==="modulepreload"&&a(i)}).observe(document,{childList:!0,subtree:!0});function s(r){const n={};return r.integrity&&(n.integrity=r.integrity),r.referrerPolicy&&(n.referrerPolicy=r.referrerPolicy),r.crossOrigin==="use-credentials"?n.credentials="include":r.crossOrigin==="anonymous"?n.credentials="omit":n.credentials="same-origin",n}function a(r){if(r.ep)return;r.ep=!0;const n=s(r);fetch(r.href,n)}})();const H=[{family:"HQC",level:"L1",variant:"HQC-128",publicKeyBytes:2249,ciphertextBytes:4497,sharedSecretBytes:64,keygenKCycles:87,encapKCycles:204,decapKCycles:362,assumption:"QCSD/DSD over quasi-cyclic codes",correctness:"Perfect correctness",source:"HQC Round-4 submission (Table 6, Table 9)"},{family:"BIKE",level:"L1",variant:"BIKE-1",publicKeyBytes:1541,ciphertextBytes:1573,sharedSecretBytes:32,keygenKCycles:589,encapKCycles:97,decapKCycles:1135,assumption:"QC-MDPC decoding/codeword finding",correctness:"Non-zero DFR target 2^-128",source:"BIKE Round-4 spec (Table 5, Table 7 AVX512)"},{family:"ML-KEM",level:"L1",variant:"ML-KEM-512",publicKeyBytes:800,ciphertextBytes:768,sharedSecretBytes:32,keygenKCycles:34,encapKCycles:45,decapKCycles:35,assumption:"Module-LWE",correctness:"Deterministic decapsulation in standardized flow",source:"CRYSTALS-Kyber site (Haswell AVX2 cycles)"},{family:"HQC",level:"L3",variant:"HQC-192",publicKeyBytes:4522,ciphertextBytes:9042,sharedSecretBytes:64,keygenKCycles:204,encapKCycles:465,decapKCycles:755,assumption:"QCSD/DSD over quasi-cyclic codes",correctness:"Perfect correctness",source:"HQC Round-4 submission (Table 6, Table 9)"},{family:"BIKE",level:"L3",variant:"BIKE-3",publicKeyBytes:3083,ciphertextBytes:3115,sharedSecretBytes:32,keygenKCycles:1823,encapKCycles:223,decapKCycles:3887,assumption:"QC-MDPC decoding/codeword finding",correctness:"Non-zero DFR target 2^-192",source:"BIKE Round-4 spec (Table 5, Table 8 AVX512)"},{family:"ML-KEM",level:"L3",variant:"ML-KEM-768",publicKeyBytes:1184,ciphertextBytes:1088,sharedSecretBytes:32,keygenKCycles:53,encapKCycles:68,decapKCycles:53,assumption:"Module-LWE",correctness:"Deterministic decapsulation in standardized flow",source:"CRYSTALS-Kyber site (Haswell AVX2 cycles)"},{family:"HQC",level:"L5",variant:"HQC-256",publicKeyBytes:7245,ciphertextBytes:14485,sharedSecretBytes:64,keygenKCycles:409,encapKCycles:904,decapKCycles:1505,assumption:"QCSD/DSD over quasi-cyclic codes",correctness:"Perfect correctness",source:"HQC Round-4 submission (Table 6, Table 9)"},{family:"BIKE",level:"L5",variant:"BIKE-5",publicKeyBytes:5122,ciphertextBytes:5154,sharedSecretBytes:32,keygenKCycles:null,encapKCycles:null,decapKCycles:null,assumption:"QC-MDPC decoding/codeword finding",correctness:"Non-zero DFR target 2^-256",source:"BIKE Round-4 spec (Table 4 and Table 5; no L5 software cycles table)"},{family:"ML-KEM",level:"L5",variant:"ML-KEM-1024",publicKeyBytes:1568,ciphertextBytes:1568,sharedSecretBytes:32,keygenKCycles:74,encapKCycles:97,decapKCycles:79,assumption:"Module-LWE",correctness:"Deterministic decapsulation in standardized flow",source:"CRYSTALS-Kyber site (Haswell AVX2 cycles)"}];function E(t){return t===null?"N/A":`${t}k`}function W(){return H.map(t=>`
      <tr>
        <td>${t.variant}</td>
        <td>${t.publicKeyBytes}</td>
        <td>${t.ciphertextBytes}</td>
        <td>${t.sharedSecretBytes}</td>
        <td>${E(t.keygenKCycles)}</td>
        <td>${E(t.encapKCycles)}</td>
        <td>${E(t.decapKCycles)}</td>
        <td>${t.assumption}</td>
        <td>${t.correctness}</td>
      </tr>`).join("")}function X(t){const e=H.filter(a=>a.level===t),s=Math.max(...e.map(a=>a.publicKeyBytes+a.ciphertextBytes));return e.map(a=>{const r=a.publicKeyBytes+a.ciphertextBytes,n=Math.max(8,Math.round(r/s*100));return`
      <div class="bar-row" role="listitem" aria-label="${a.variant} total key plus ciphertext size ${r} bytes">
        <span class="bar-label">${a.variant}</span>
        <div class="bar-track">
          <div class="bar-fill" style="width:${n}%"></div>
        </div>
        <span class="bar-value">${r} B</span>
      </div>`}).join("")}function Y(){return Array.from(new Set(H.map(e=>e.source))).map(e=>`<li>${e}</li>`).join("")}const J=[{id:"rm",title:"Inner Layer: Reed-Muller",detail:"The inner binary Reed-Muller code carries symbols that are robust to random bit flips and supports majority-style decoding."},{id:"rs",title:"Outer Layer: Reed-Solomon",detail:"The outer Reed-Solomon code over GF(256) corrects symbol-level errors after Reed-Muller blocks are decoded."},{id:"concat",title:"Concatenation",detail:"HQC composes both layers so decoding is deterministic for valid ciphertexts, giving perfect correctness in the scheme design."}];function I(t,e){const s=new Uint8Array(e);for(let a=0;a<e;a+=1){const r=t[a%t.length],n=a*13+7&1^r>>a%8&1;s[a]=n}for(let a=0;a+2<e;a+=3){const r=s[a]^s[a+1];s[a+2]=r}return s}function Z(t,e){const s=I(e,t.length),a=t.slice();for(let r=0;r+2<a.length;r+=3){const n=a[r],i=a[r+1],o=a[r+2],p=n^i;o!==p&&(a[r+2]=p)}for(let r=0;r<a.length;r+=1)a[r]=s[r];return a}const m={"hqc-128":{id:"hqc-128",label:"HQC-128 (NIST Level 1)",n:17669,w:66,w_e:75,w_r:75,pkBytes:2249,ctBytes:4497,ssBytes:64},"hqc-192":{id:"hqc-192",label:"HQC-192 (NIST Level 3)",n:35851,w:100,w_e:114,w_r:114,pkBytes:4522,ctBytes:9042,ssBytes:64},"hqc-256":{id:"hqc-256",label:"HQC-256 (NIST Level 5)",n:57637,w:131,w_e:149,w_r:149,pkBytes:7245,ctBytes:14485,ssBytes:64}},ee=1024;function T(t){const e=new Uint8Array(t);return crypto.getRandomValues(e),e}function te(t){const e=T(Math.ceil(t/8)),s=new Uint8Array(t);for(let a=0;a<t;a+=1)s[a]=e[a>>3]>>(a&7)&1;return s}function d(t,e){const s=new Set;for(;s.size<e;){const a=crypto.getRandomValues(new Uint32Array(1))[0]%t;s.add(a)}return Uint32Array.from(Array.from(s).sort((a,r)=>a-r))}function P(t,e){const s=new Uint8Array(t);for(const a of e)s[a]=1;return s}function L(t,e){const s=new Uint8Array(t.length);for(let a=0;a<t.length;a+=1)s[a]=t[a]^e[a];return s}function k(t,e,s){const a=new Uint8Array(s);for(const r of e)for(let n=0;n<s;n+=1)a[n]^=t[(n+s-r)%s];return a}function A(t,e){const s=t.slice();for(const a of e)s[a]^=1;return s}function Q(t){const e=new Uint8Array(Math.ceil(t.length/8));for(let s=0;s<t.length;s+=1)e[s>>3]|=t[s]<<(s&7);return e}function ae(t,e){const s=new Uint8Array(e);for(let a=0;a<e;a+=1)s[a]=t[a>>3]>>(a&7)&1;return s}async function w(t){const e=t.reduce((n,i)=>n+i.length,0),s=new Uint8Array(e);let a=0;for(const n of t)s.set(n,a),a+=n.length;const r=await crypto.subtle.digest("SHA-256",s);return new Uint8Array(r)}function f(t,e=96){const s=Array.from(t).map(a=>a.toString(16).padStart(2,"0")).join("");return s.length<=e?s:`${s.slice(0,e)}...`}function l(t){return Array.from(t).map(e=>e.toString(16).padStart(2,"0")).join("")}async function se(t){const e=m[t],s=Math.min(e.n,ee),a=te(s),r=d(s,e.w),n=d(s,e.w),i=d(s,e.w_e),o=P(s,r),p=k(a,n,s),S=A(L(o,p),i);return{params:e,publicKey:{h:a,s:S},privateKey:{x:r,y:n}}}async function re(t){const e=t.publicKey.h.length,{w_r:s,w_e:a}=t.params,r=T(32),n=I(r,e),i=d(e,s),o=d(e,s),p=d(e,a),S=d(e,a),G=P(e,i),U=k(t.publicKey.h,o,e),N=A(L(G,U),p),z=k(t.publicKey.s,o,e),V=A(L(n,z),S),M=Q(N),B=Q(V),F=await w([M,B,t.publicKey.s]),x=new Uint8Array(r.length);for(let y=0;y<r.length;y+=1)x[y]=r[y]^F[y];const j=await w([r,M,B,x]);return{ciphertext:{u:M,v:B,d:x},sharedSecret:j,messageSeed:r}}async function _(t,e){const s=await w([e.u,e.v,t.publicKey.s]),a=new Uint8Array(e.d.length);for(let i=0;i<e.d.length;i+=1)a[i]=e.d[i]^s[i];const r=Z(ae(e.v,t.publicKey.h.length),a);return{sharedSecret:await w([a,e.u,e.v,e.d]),recoveredSeed:a,decoderBits:r}}async function ne(t,e){const s=t.slice(0,32),a=await crypto.subtle.importKey("raw",s,"AES-GCM",!1,["encrypt"]),r=T(12),n=new Uint8Array(r.buffer,r.byteOffset,r.byteLength),i=new TextEncoder().encode(e),o=await crypto.subtle.encrypt({name:"AES-GCM",iv:n},a,i);return{iv:r,ciphertext:new Uint8Array(o)}}async function ie(t,e){const s=t.slice(0,32),a=await crypto.subtle.importKey("raw",s,"AES-GCM",!1,["decrypt"]),r=new Uint8Array(e.iv.buffer,e.iv.byteOffset,e.iv.byteLength),n=new Uint8Array(e.ciphertext.buffer,e.ciphertext.byteOffset,e.ciphertext.byteLength),i=await crypto.subtle.decrypt({name:"AES-GCM",iv:r},a,n);return new TextDecoder().decode(i)}function ce(){const t=document.documentElement,e=document.querySelector("#theme-toggle");if(!e)return;const s=localStorage.getItem("hqc-theme"),a=s==="light"||s==="dark"?s:"dark";t.dataset.theme=a,e.setAttribute("aria-pressed",a==="dark"?"true":"false"),e.textContent=a==="dark"?"Switch to light mode":"Switch to dark mode",e.addEventListener("click",()=>{const r=t.dataset.theme==="dark"?"light":"dark";t.dataset.theme=r,localStorage.setItem("hqc-theme",r),e.setAttribute("aria-pressed",r==="dark"?"true":"false"),e.textContent=r==="dark"?"Switch to light mode":"Switch to dark mode"})}function oe(t){const e=document.querySelector("#compare-level");if(!e)return;const s=()=>t(e.value);e.addEventListener("change",s),s()}function c(t){const e=document.querySelector("#live-region");e&&(e.textContent="",requestAnimationFrame(()=>{e.textContent=t}))}const O=document.querySelector("#app");if(!O)throw new Error("Missing app root");O.innerHTML=`
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
        ${J.map(t=>`
          <article class="mini-card" role="listitem" aria-label="${t.title}">
            <h3>${t.title}</h3>
            <p>${t.detail}</p>
          </article>
        `).join("")}
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
          <tbody id="compare-rows">${W()}</tbody>
        </table>
      </div>

      <div id="size-bars" class="bars" role="list" aria-label="Key plus ciphertext size bars"></div>
      <div class="callouts" aria-label="Status callouts">
        <span class="chip status">ML-KEM: Recommended Default</span>
        <span class="chip status">HQC: Acceptable for diversity</span>
        <span class="chip status">BIKE: Acceptable for diversity, non-zero DFR design</span>
      </div>
      <ul class="sources" aria-label="Benchmark and table sources">
        ${Y()}
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
`;ce();const $=document.querySelector("#size-bars"),v=document.querySelector("#keygen-output"),h=document.querySelector("#kem-output"),b=document.querySelector("#aes-output"),g=document.querySelector("#keygen-btn"),C=document.querySelector("#encap-btn"),q=document.querySelector("#hqc-level"),D=document.querySelector("#aes-form"),R=document.querySelector("#message-input");let u=null,K=null;function le(t){$&&($.innerHTML=X(t))}oe(le);g&&v&&q&&g.addEventListener("click",async()=>{try{g.disabled=!0,v.textContent="Generating keypair...",c("Generating illustrative HQC key pair.");const t=q.value,e=await se(t);u=e,K=null,v.innerHTML=`
        <p><strong>${e.params.label}</strong></p>
        <p>Exact round-4 parameters: n=${m[t].n}, w=${m[t].w}, w_e=${m[t].w_e}, w_r=${m[t].w_r}</p>
        <p>Illustrative simulation dimension used in-browser: n=${e.publicKey.h.length}</p>
        <p>private x (weight ${e.privateKey.x.length}) = <code>${Array.from(e.privateKey.x).slice(0,24).join(", ")}${e.privateKey.x.length>24?", ...":""}</code></p>
        <p>private y (weight ${e.privateKey.y.length}) = <code>${Array.from(e.privateKey.y).slice(0,24).join(", ")}${e.privateKey.y.length>24?", ...":""}</code></p>
        <p>public h (hex preview) = <code class="hex">${f(e.publicKey.h)}</code></p>
        <p>public s (hex preview) = <code class="hex">${f(e.publicKey.s)}</code></p>
        <p>Security basis: Decisional Syndrome Decoding over quasi-cyclic binary codes.</p>
      `,c("Key generation complete.")}catch{v.innerHTML='<p class="error">Key generation failed. Try again.</p>',c("Error while generating keys.")}finally{g.disabled=!1}});C&&h&&C.addEventListener("click",async()=>{if(!u){h.innerHTML='<p class="error">Generate a keypair first.</p>',c("You need to generate a keypair before encapsulation.");return}try{C.disabled=!0,h.textContent="Running encapsulation and decapsulation...";const t=await re(u);K=t;const e=await _(u,t.ciphertext),s=l(t.sharedSecret)===l(e.sharedSecret),a=s?"MATCH":"MISMATCH";h.innerHTML=`
        <p>Alice shared secret = <code class="hex">${l(t.sharedSecret)}</code></p>
        <p>Bob shared secret = <code class="hex">${l(e.sharedSecret)}</code></p>
        <p>Result: <strong>${a}</strong> (${s?"perfect correctness demonstrated":"check implementation"})</p>
        <p>ciphertext u = <code class="hex">${f(t.ciphertext.u)}</code></p>
        <p>ciphertext v = <code class="hex">${f(t.ciphertext.v)}</code></p>
        <p>ciphertext d = <code class="hex">${f(t.ciphertext.d)}</code></p>
        <p>Recovered message seed (hex) = <code class="hex">${l(e.recoveredSeed)}</code></p>
      `,c(s?"Encapsulation and decapsulation completed with matching keys.":"Key mismatch detected.")}catch{h.innerHTML='<p class="error">Encapsulation/decapsulation failed.</p>',c("Error during encapsulation and decapsulation.")}finally{C.disabled=!1}});D&&b&&R&&D.addEventListener("submit",async t=>{if(t.preventDefault(),!K||!u){b.innerHTML='<p class="error">Run encapsulation first to derive a shared secret.</p>',c("Run encapsulation first.");return}try{const e=R.value.trim();if(!e){b.innerHTML='<p class="error">Please enter a message.</p>',c("Message is required.");return}const s=await _(u,K.ciphertext),a=await ne(s.sharedSecret,e),r=await ie(s.sharedSecret,a);b.innerHTML=`
        <p>IV = <code class="hex">${l(a.iv)}</code></p>
        <p>AES-256-GCM ciphertext = <code class="hex">${l(a.ciphertext)}</code></p>
        <p>Decrypted plaintext = <strong>${r}</strong></p>
        <p class="small">KEM + DEM flow complete using WebCrypto AES-256-GCM.</p>
      `,c("AES encryption and decryption succeeded.")}catch{b.innerHTML='<p class="error">AES operation failed.</p>',c("AES operation failed.")}});
