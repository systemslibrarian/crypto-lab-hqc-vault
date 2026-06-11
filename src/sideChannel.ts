// Side-channel timing toy: compare a secret-dependent naive lookup
// against a constant-time scan. Demonstrates that variable-time code
// leaks the sparse vector's structure.

const SIZE = 4096;
const ROUNDS = 2000;

function buildSparseLookup(target: number): Uint8Array {
  const arr = new Uint8Array(SIZE);
  // Place the secret at a chosen index; surround with random.
  for (let i = 0; i < SIZE; i += 1) arr[i] = Math.floor(Math.random() * 256);
  arr[target] = 0xa5; // distinguishable marker
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

function timeOnce(fn: () => void): number {
  const start = performance.now();
  for (let r = 0; r < ROUNDS; r += 1) fn();
  return (performance.now() - start) / ROUNDS;
}

export interface SideChannelResult {
  positions: number[];
  naive: number[];
  constant: number[];
}

export function runSideChannelDemo(): SideChannelResult {
  const positions = [10, 256, 1024, 2048, 3072, SIZE - 10];
  const naive = positions.map((pos) => {
    const arr = buildSparseLookup(pos);
    return timeOnce(() => {
      naiveLookup(arr, 0xa5);
    });
  });
  const constant = positions.map((pos) => {
    const arr = buildSparseLookup(pos);
    return timeOnce(() => {
      constantTimeLookup(arr, 0xa5);
    });
  });
  return { positions, naive, constant };
}

export function renderSideChannelChart(target: HTMLElement, result: SideChannelResult): void {
  const allTimes = [...result.naive, ...result.constant];
  const max = Math.max(...allTimes);
  const rows = result.positions
    .map((pos, i) => {
      const naiveWidth = Math.max(2, Math.round((result.naive[i] / max) * 100));
      const ctWidth = Math.max(2, Math.round((result.constant[i] / max) * 100));
      return `
        <div class="sc-row">
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

  target.innerHTML = `
    <p class="small">
      Each row places a secret marker at a different index of a 4 KB array, then averages
      ${ROUNDS} lookups. The naive scan returns early when it hits the marker, so its timing
      grows linearly with the secret position. The constant-time scan visits every byte
      regardless of where the marker sits.
    </p>
    <div class="sc-chart" role="list" aria-label="Lookup timings by marker position">${rows}</div>
    <p class="small strong">
      A real HQC attacker measures this difference across many encapsulations to recover
      the support of the sparse secret. That is why production HQC decoders fold every
      branch and every table access through constant-time primitives.
    </p>
  `;
}
