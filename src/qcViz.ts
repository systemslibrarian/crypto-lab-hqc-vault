// Interactive quasi-cyclic visualizer: small n (default 16), sparse vector toggled by clicks,
// shows circulant rotation accumulating via XOR into an output row.
//
// Optional matrix overlay reveals the punchline: "XOR of rotations" IS the matrix-times-vector
// product M·y, where M is the full circulant of h. Selecting bit j of y selects column j of M;
// the product is the XOR of the selected columns. Storing only h's first row (instead of the whole
// n×n matrix M) is exactly why HQC keys are kilobytes, not megabytes.

const VIZ_N = 16;

interface VizState {
  sparse: Set<number>;
  h: number[];
  showMatrix: boolean;
}

let state: VizState = {
  sparse: new Set<number>([0, 5]),
  h: defaultH(VIZ_N),
  showMatrix: false
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

// Column j of the circulant M of h. M[i][j] = h[(i - j) mod n], so column j equals
// h rotated right by j — identical to rotateRight(h, j).
function circulantColumn(h: number[], j: number, n: number): number[] {
  return rotateRight(h, j, n);
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

function matrixHtml(): string {
  const n = VIZ_N;
  const selected = state.sparse;
  // Build the full circulant M: M[i][j] = h[(i - j) mod n].
  let head = '<th scope="col" class="qc-m-corner"><span class="sr-only">row index</span></th>';
  for (let j = 0; j < n; j += 1) {
    const sel = selected.has(j) ? " sel" : "";
    head += `<th scope="col" class="qc-m-col${sel}">${j}</th>`;
  }
  let body = "";
  for (let i = 0; i < n; i += 1) {
    let cells = `<th scope="row" class="qc-m-rowlab">${i}</th>`;
    for (let j = 0; j < n; j += 1) {
      const bit = state.h[(i - j + n * n) % n];
      const sel = selected.has(j) ? " sel" : "";
      const on = bit ? " on" : "";
      cells += `<td class="qc-m-cell${on}${sel}">${bit}</td>`;
    }
    body += `<tr>${cells}</tr>`;
  }
  return `
    <div class="qc-matrix-wrap" tabindex="0" role="region" aria-label="Full circulant matrix M of h; highlighted columns are selected by the set bits of y">
      <table class="qc-matrix">
        <caption class="sr-only">Circulant matrix M built from h. Column j is h rotated by j. Highlighted columns correspond to the set bits of y.</caption>
        <thead><tr>${head}</tr></thead>
        <tbody>${body}</tbody>
      </table>
    </div>
    <p class="qc-matrix-note small">
      Each highlighted column above is one rotation of <code>h</code> — and the product
      <code>h·y</code> is just the XOR of the highlighted columns. <strong>This is a matrix multiply
      M·y in disguise.</strong> Storing only <code>h</code>'s first row instead of the whole
      ${n}×${n} matrix <code>M</code> is why HQC keys are kilobytes, not megabytes.
    </p>
  `;
}

function render(): void {
  const root = document.querySelector<HTMLDivElement>("#qc-viz");
  if (!root) return;

  const shifts = Array.from(state.sparse).sort((a, b) => a - b);
  const rotations = shifts.map((k) => circulantColumn(state.h, k, VIZ_N));
  const accumulated = xorAccumulate(rotations, VIZ_N);

  const sparseHtml = Array.from({ length: VIZ_N }, (_, i) => {
    const set = state.sparse.has(i);
    return `<button type="button" class="qc-bit${set ? " on" : ""}" data-idx="${i}" aria-pressed="${set ? "true" : "false"}" aria-label="Toggle sparse bit ${i}">${set ? 1 : 0}</button>`;
  }).join("");

  const weight = shifts.length;
  const rotationRows = shifts
    .map((k, idx) => rowHtml(rotations[idx], `col ${k} (h &lt;&lt; ${k})`, { highlightShift: k }))
    .join("");

  root.innerHTML = `
    <div class="qc-block">
      <p class="qc-caption">Click bits in the sparse vector <code>y</code> below (weight=${weight}). Each set bit selects one column of the circulant matrix of <code>h</code> (equivalently, one rotation of <code>h</code>); those columns XOR together to produce the product <code>h·y</code>.</p>
      <div class="qc-sparse" role="group" aria-label="Sparse vector y bits">${sparseHtml}</div>
      <div class="controls-row qc-controls">
        <button type="button" class="btn secondary" id="qc-matrix-toggle" aria-pressed="${state.showMatrix ? "true" : "false"}">${state.showMatrix ? "Hide" : "Show"} full circulant matrix</button>
      </div>
      ${state.showMatrix ? matrixHtml() : ""}
      ${rowHtml(state.h, "h (first row)", { dim: true })}
      <div class="qc-rotations" aria-label="Selected columns of the circulant">${rotationRows || '<p class="small">No bits set — pick at least one.</p>'}</div>
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

  root.querySelector<HTMLButtonElement>("#qc-matrix-toggle")?.addEventListener("click", () => {
    state.showMatrix = !state.showMatrix;
    render();
  });
}

export function mountQcVisualizer(): void {
  render();
}
