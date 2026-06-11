// Interactive quasi-cyclic visualizer: small n (default 16), sparse vector toggled by clicks,
// shows circulant rotation accumulating via XOR into an output row.

const VIZ_N = 16;

interface VizState {
  sparse: Set<number>;
  h: number[];
}

let state: VizState = {
  sparse: new Set<number>([0, 5]),
  h: defaultH(VIZ_N)
};

function defaultH(n: number): number[] {
  // deterministic pseudo-random h vector so the viz is stable across reloads
  const out = new Array<number>(n);
  let s = 1234567;
  for (let i = 0; i < n; i += 1) {
    s = (s * 1103515245 + 12345) & 0x7fffffff;
    out[i] = (s >> 16) & 1;
  }
  return out;
}

function rotateRight(h: number[], k: number, n: number): number[] {
  const out = new Array<number>(n);
  for (let i = 0; i < n; i += 1) out[i] = h[(i + n - k) % n];
  return out;
}

function xorAccumulate(rows: number[][], n: number): number[] {
  const out = new Array<number>(n).fill(0);
  for (const row of rows) {
    for (let i = 0; i < n; i += 1) out[i] ^= row[i];
  }
  return out;
}

function rowHtml(bits: number[], label: string, opts: { dim?: boolean; highlightShift?: number } = {}): string {
  const cells = bits
    .map((b, i) => {
      const cls = b ? "cell on" : "cell";
      const star = opts.highlightShift === i ? " marked" : "";
      return `<span class="${cls}${star}">${b}</span>`;
    })
    .join("");
  const dim = opts.dim ? " dim" : "";
  return `<div class="qc-row${dim}"><span class="qc-label">${label}</span><div class="qc-cells">${cells}</div></div>`;
}

function render(): void {
  const root = document.querySelector<HTMLDivElement>("#qc-viz");
  if (!root) return;

  const shifts = Array.from(state.sparse).sort((a, b) => a - b);
  const rotations = shifts.map((k) => rotateRight(state.h, k, VIZ_N));
  const accumulated = xorAccumulate(rotations, VIZ_N);

  const sparseHtml = Array.from({ length: VIZ_N }, (_, i) => {
    const set = state.sparse.has(i);
    return `<button type="button" class="qc-bit${set ? " on" : ""}" data-idx="${i}" aria-pressed="${set ? "true" : "false"}" aria-label="Toggle sparse bit ${i}">${set ? 1 : 0}</button>`;
  }).join("");

  const weight = shifts.length;
  const rotationRows = shifts
    .map((k, idx) => rowHtml(rotations[idx], `h &lt;&lt; ${k}`, { highlightShift: k }))
    .join("");

  root.innerHTML = `
    <div class="qc-block">
      <p class="qc-caption">Click bits in the sparse vector <code>y</code> below (weight=${weight}). Each set bit triggers one rotation of <code>h</code>; the rotations XOR together to produce the product <code>h·y</code>.</p>
      <div class="qc-sparse" role="group" aria-label="Sparse vector y bits">${sparseHtml}</div>
      ${rowHtml(state.h, "h", { dim: true })}
      <div class="qc-rotations" aria-label="Active rotations of h">${rotationRows || '<p class="small">No bits set — pick at least one.</p>'}</div>
      ${rowHtml(accumulated, "h·y", {})}
    </div>
  `;

  root.querySelectorAll<HTMLButtonElement>(".qc-bit").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = Number(btn.dataset.idx);
      if (state.sparse.has(idx)) state.sparse.delete(idx);
      else state.sparse.add(idx);
      render();
    });
  });
}

export function mountQcVisualizer(): void {
  render();
}
