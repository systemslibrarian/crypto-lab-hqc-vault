// Side-channel timing toy: compare a secret-dependent naive lookup
// against a constant-time scan. Demonstrates that variable-time code
// leaks the sparse vector's structure.

const SIZE = 4096;
const ROUNDS = 2000;
const REPS = 5;
const MARKER = 0xa5;

function buildSparseLookup(target: number): Uint8Array {
  const arr = new Uint8Array(SIZE);
  // Place the secret at a chosen index; surround it with random filler drawn from
  // the 255 values that are NOT the marker.
  //
  // The exclusion is load-bearing, not fussiness. Uniform filler over all 256 values
  // plants a spurious 0xa5 every ~256 bytes, so `naiveLookup` returns at the first
  // accidental collision (measured mean stop index ~280) instead of at `target`. With
  // that bug the marker beyond ~256 was never actually reached — 0 of 200 trials at
  // positions 2048/3072/4086 — and the "time grows with the secret's position" claim
  // this panel makes was flat noise above 256, i.e. the chart said the same thing
  // whether or not the lookup depended on the secret. Excluding the marker from the
  // filler makes the leak the panel describes the leak it actually measures.
  for (let i = 0; i < SIZE; i += 1) {
    const b = Math.floor(Math.random() * 255);
    arr[i] = b >= MARKER ? b + 1 : b;
  }
  arr[target] = MARKER; // distinguishable marker, now the only one
  return arr;
}

function naiveLookup(arr: Uint8Array, marker: number): number {
  // Returns first index where arr[i] === marker. Time depends on position.
  for (let i = 0; i < arr.length; i += 1) {
    if (arr[i] === marker) return i;
  }
  return -1;
}

function constantTimeLookup(arr: Uint8Array, marker: number): number {
  // Scan the entire array using bit tricks so timing is independent of where the marker sits.
  let acc = -1;
  let mask = 0;
  for (let i = 0; i < arr.length; i += 1) {
    const hit = arr[i] === marker ? 1 : 0;
    const select = hit & ~mask;
    acc = (acc & ~(-select)) | (i & (-select));
    mask |= hit;
  }
  return acc;
}

// Warm the JIT, then take the FASTEST of REPS batches. Minimum, not mean: a batch can
// only be slowed by GC or scheduler preemption, never sped up, so the minimum is the
// cleanest estimate of the work the loop actually does. Without the warm-up the first
// position measured is penalised by compilation and the bars mis-order.
function timeOnce(fn: () => void): number {
  for (let r = 0; r < ROUNDS; r += 1) fn();
  let best = Infinity;
  for (let k = 0; k < REPS; k += 1) {
    const start = performance.now();
    for (let r = 0; r < ROUNDS; r += 1) fn();
    const elapsed = (performance.now() - start) / ROUNDS;
    if (elapsed < best) best = elapsed;
  }
  return best;
}

export interface SideChannelResult {
  positions: number[];
  naive: number[];
  constant: number[];
  /** True only if BOTH lookups returned the planted index at every position. If this is
   *  false the timings are not measuring what the panel claims, and the panel says so. */
  lookupsCorrect: boolean;
}

export function runSideChannelDemo(): SideChannelResult {
  const positions = [10, 256, 1024, 2048, 3072, SIZE - 10];
  let lookupsCorrect = true;

  const naive = positions.map((pos) => {
    const arr = buildSparseLookup(pos);
    // Check the lookup actually lands on the secret before timing it, so a bad
    // array cannot masquerade as a timing result.
    if (naiveLookup(arr, MARKER) !== pos) lookupsCorrect = false;
    return timeOnce(() => {
      naiveLookup(arr, MARKER);
    });
  });

  const constant = positions.map((pos) => {
    const arr = buildSparseLookup(pos);
    if (constantTimeLookup(arr, MARKER) !== pos) lookupsCorrect = false;
    return timeOnce(() => {
      constantTimeLookup(arr, MARKER);
    });
  });

  return { positions, naive, constant, lookupsCorrect };
}

export function renderSideChannelChart(target: HTMLElement, result: SideChannelResult): void {
  const allTimes = [...result.naive, ...result.constant];
  const max = Math.max(...allTimes);
  const rows = result.positions
    .map((pos, i) => {
      const naiveWidth = Math.max(2, Math.round((result.naive[i] / max) * 100));
      const ctWidth = Math.max(2, Math.round((result.constant[i] / max) * 100));
      return `
        <div class="sc-row" role="listitem">
          <span class="sc-label">marker @ ${pos}</span>
          <div class="sc-bars">
            <div class="sc-bar naive" style="width:${naiveWidth}%" title="naive: ${result.naive[i].toFixed(4)} ms">
              <span>naive ${result.naive[i].toFixed(3)} ms</span>
            </div>
            <div class="sc-bar constant" style="width:${ctWidth}%" title="constant-time: ${result.constant[i].toFixed(4)} ms">
              <span>const-time ${result.constant[i].toFixed(3)} ms</span>
            </div>
          </div>
        </div>`;
    })
    .join("");

  const naiveSpread = Math.max(...result.naive) / Math.max(Math.min(...result.naive), Number.MIN_VALUE);
  const constSpread = Math.max(...result.constant) / Math.max(Math.min(...result.constant), Number.MIN_VALUE);

  target.innerHTML = `
    <p class="small">
      <strong>What each row means:</strong> the y-axis label <em>"marker @ N"</em> is where a single
      secret bit sits — think of it as one set position in HQC's sparse private support (the demo uses
      an arbitrary array index here, but in the real scheme that index <em>is</em> a bit of the private
      key). The x-axis (bar length) is measured time: milliseconds per lookup, taken as the fastest of
      ${REPS} batches of ${ROUNDS} lookups after a warm-up batch. The naive scan returns early when it
      hits the marker, so its time grows with the secret's position — the bar length leaks the secret.
      The constant-time scan visits every byte regardless, so its bars stay flat.
    </p>
    ${
      result.lookupsCorrect
        ? ""
        : `<p class="error">Measurement invalid: at least one lookup did not return the planted
             index, so these bars are not timing what this panel describes. Re-run.</p>`
    }
    <div class="sc-axis" aria-hidden="true"><span>secret bit position ↓</span><span>time (ms) →</span></div>
    <div class="sc-chart" role="list" aria-label="Lookup time (milliseconds, longer bar = slower) by secret bit position">${rows}</div>
    <p class="small strong">
      Read the naive bars top-to-bottom: their growing length is the secret's position leaking out.
      On this run the naive timings span <strong>${naiveSpread.toFixed(0)}&times;</strong> from the
      lowest secret position to the highest, while the constant-time timings span only
      <strong>${constSpread.toFixed(2)}&times;</strong> — that gap, measured live on your machine
      rather than asserted, is the leak. A real HQC attacker measures exactly this across many
      encapsulations to reconstruct the sparse support of the private key. That is why production
      HQC decoders fold every branch and every table access through constant-time primitives.
    </p>
  `;
}
