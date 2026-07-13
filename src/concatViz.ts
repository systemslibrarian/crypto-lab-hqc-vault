// Two-layer error-correction visualizer.
// Shows the SAME concatenated code decap uses: 15 blocks of 8 bits (RS(15,4) over
// GF(16) outer + RM(1,3) inner). The learner injects bit errors, then watches:
//   - Reed-Muller fix a single stray bit inside a block (majority vote), or
//   - a block whose errors exceed RM's budget flip to the wrong symbol — a whole
//     block failure that Reed-Solomon then repairs as one symbol error.
// Every number shown comes from the real decoders in codes.ts, never a mock-up.

import { RM_N, RS_N, encodeDemoStrip, traceConcatenated } from "./codes";
import { escapeHtml } from "./ui";

// A fixed, human-friendly seed so the clean codeword is stable across reloads.
const DEMO_SEED = Uint8Array.of(0x4b, 0x9c);

let cleanBits: Uint8Array = encodeDemoStrip(DEMO_SEED);
let injected = new Set<number>(); // bit indices (0..CODEWORD_BITS-1) the user flipped

function currentReceived(): Uint8Array {
  const out = cleanBits.slice();
  for (const idx of injected) out[idx] ^= 1;
  return out;
}

function stripHtml(): string {
  const received = currentReceived();
  let cells = "";
  for (let b = 0; b < RS_N; b += 1) {
    let block = "";
    for (let j = 0; j < RM_N; j += 1) {
      const idx = b * RM_N + j;
      const bit = received[idx];
      const flipped = injected.has(idx);
      const cls = `cc-bit${bit ? " on" : ""}${flipped ? " flipped" : ""}`;
      const label = flipped
        ? `Block ${b} bit ${j}: flipped to ${bit}, click to restore`
        : `Block ${b} bit ${j}: value ${bit}, click to inject an error`;
      block += `<button type="button" class="${cls}" data-idx="${idx}" aria-pressed="${flipped ? "true" : "false"}" aria-label="${label}">${bit}</button>`;
    }
    cells += `<div class="cc-block" data-block="${b}"><span class="cc-block-num">${b}</span><div class="cc-block-bits">${block}</div></div>`;
  }
  return cells;
}

function resultHtml(): string {
  const received = currentReceived();
  const trace = traceConcatenated(received);

  // Blocks whose RM output symbol differs from the clean codeword's symbol = whole-block failures.
  const cleanTrace = traceConcatenated(cleanBits);
  const failedBlocks = trace.blocks
    .map((blk, i) => (blk.symbol !== cleanTrace.rsInput[i] ? i : -1))
    .filter((i) => i >= 0);
  const failedSet = new Set(failedBlocks);

  // Count RM-corrected bits only from blocks RM decoded to the CORRECT symbol. A block
  // that flipped to a wrong symbol is a failure, not a fix — its differing bits are RS's job.
  const totalRmFixed = trace.blocks.reduce(
    (a, blk, i) => a + (failedSet.has(i) ? 0 : blk.rmFixed),
    0
  );

  const rsFixed = trace.rsErrorPositions.length;
  const rsErrorSet = new Set(trace.rsErrorPositions);

  // Per-block status badges (icon + text + color, never color alone).
  const badges = trace.blocks
    .map((blk, i) => {
      const failed = blk.symbol !== cleanTrace.rsInput[i];
      const rsRepaired = rsErrorSet.has(i);
      let cls: string;
      let icon: string;
      let text: string;
      if (failed && rsRepaired) {
        cls = "rsfix";
        icon = "◆";
        text = `RS repaired block ${i}`;
      } else if (failed && !rsRepaired) {
        cls = "fail";
        icon = "✕";
        text = `block ${i} failed`;
      } else if (blk.rmFixed > 0) {
        cls = "rmfix";
        icon = "✓";
        text = `RM fixed ${blk.rmFixed} bit${blk.rmFixed > 1 ? "s" : ""} in block ${i}`;
      } else {
        return "";
      }
      return `<li class="cc-badge ${cls}"><span aria-hidden="true">${icon}</span> ${escapeHtml(text)}</li>`;
    })
    .filter(Boolean)
    .join("");

  const recovered = trace.rsDecoded && failedBlocks.every((i) => rsErrorSet.has(i));
  const clean = injected.size === 0;

  let verdictCls: string;
  let verdictIcon: string;
  let verdictText: string;
  if (clean) {
    verdictCls = "ok";
    verdictIcon = "○";
    verdictText = "No errors injected — clean codeword.";
  } else if (recovered) {
    verdictCls = "ok";
    verdictIcon = "✓";
    verdictText = "Seed recovered exactly. Both layers absorbed the noise.";
  } else {
    verdictCls = "bad";
    verdictIcon = "✕";
    verdictText = "Errors exceeded the budget — decode failed. (In the real KEM, the FO check would then reject.)";
  }

  return `
    <div class="cc-counters" aria-label="Error-correction counters">
      <span class="cc-counter"><strong>${totalRmFixed}</strong> stray bit${totalRmFixed === 1 ? "" : "s"} fixed by Reed-Muller</span>
      <span class="cc-counter"><strong>${failedBlocks.length}</strong> whole block${failedBlocks.length === 1 ? "" : "s"} failed (exceeded RM's 1-bit budget)</span>
      <span class="cc-counter"><strong>${rsFixed}</strong> failed block${rsFixed === 1 ? "" : "s"} repaired by Reed-Solomon (of 5 it can fix)</span>
    </div>
    ${badges ? `<ul class="cc-badges" aria-label="Per-block correction outcomes">${badges}</ul>` : ""}
    <p class="cc-verdict ${verdictCls}"><span aria-hidden="true">${verdictIcon}</span> ${escapeHtml(verdictText)}</p>
  `;
}

function highlightFailures(root: HTMLElement): void {
  const received = currentReceived();
  const trace = traceConcatenated(received);
  const cleanTrace = traceConcatenated(cleanBits);
  const rsErrorSet = new Set(trace.rsErrorPositions);
  root.querySelectorAll<HTMLElement>(".cc-block").forEach((el) => {
    const b = Number(el.dataset.block);
    const blk = trace.blocks[b];
    el.classList.remove("failed", "rsrepaired", "rmfixed");
    if (blk.symbol !== cleanTrace.rsInput[b]) {
      el.classList.add(rsErrorSet.has(b) ? "rsrepaired" : "failed");
    } else if (blk.rmFixed > 0) {
      el.classList.add("rmfixed");
    }
  });
}

function render(): void {
  const root = document.querySelector<HTMLDivElement>("#concat-viz");
  if (!root) return;
  root.innerHTML = `
    <div class="cc-block-wrap">
      <p class="cc-caption">
        This is one real 120-bit codeword: <strong>15 blocks × 8 bits</strong>. Each block carries one
        4-bit symbol. Click any bit to flip it, then watch the two layers react. Reed-Muller votes
        inside each block to fix a single stray bit; if a block takes too much noise it flips to the
        wrong symbol, and Reed-Solomon repairs that whole block as one symbol error.
      </p>
      <div class="cc-strip" role="group" aria-label="15 code blocks of 8 bits each">${stripHtml()}</div>
      <div class="cc-legend" aria-hidden="true">
        <span><span class="cc-swatch on"></span> bit = 1</span>
        <span><span class="cc-swatch flipped"></span> you flipped it</span>
        <span><span class="cc-swatch rmfixed"></span> RM fixed the block</span>
        <span><span class="cc-swatch rsrepaired"></span> RS repaired the block</span>
        <span><span class="cc-swatch failed"></span> block lost</span>
      </div>
      <div class="controls-row cc-controls">
        <button type="button" class="btn secondary" id="cc-reset">Reset to clean codeword</button>
        <button type="button" class="btn secondary" id="cc-two">Break one block (inject 2 bits)</button>
      </div>
      <div id="cc-result" class="cc-result" aria-live="polite">${resultHtml()}</div>
    </div>
  `;

  root.querySelectorAll<HTMLButtonElement>(".cc-bit").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.idx);
      if (injected.has(idx)) injected.delete(idx);
      else injected.add(idx);
      const result = root.querySelector<HTMLDivElement>("#cc-result");
      if (result) result.innerHTML = resultHtml();
      // Update just the toggled bit's appearance + block highlight without full re-render.
      const received = currentReceived();
      btn.textContent = String(received[idx]);
      btn.classList.toggle("on", received[idx] === 1);
      btn.classList.toggle("flipped", injected.has(idx));
      btn.setAttribute("aria-pressed", injected.has(idx) ? "true" : "false");
      highlightFailures(root);
    });
  });

  root.querySelector<HTMLButtonElement>("#cc-reset")?.addEventListener("click", () => {
    injected = new Set();
    render();
  });
  root.querySelector<HTMLButtonElement>("#cc-two")?.addEventListener("click", () => {
    // Inject 2 bit errors into a single block (block 3) so RM's 1-bit budget is
    // exceeded and the learner sees Reed-Solomon step in. Real decode, real repair.
    injected = new Set([3 * RM_N + 1, 3 * RM_N + 4]);
    render();
  });

  highlightFailures(root);
}

export function mountConcatVisualizer(): void {
  render();
}
