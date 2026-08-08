import { CODEWORD_BITS } from "./codes";
import {
  type HqcKeyPair,
  decapsulateIllustrative,
  encapsulateIllustrative,
  flipRandomBits,
  fullHex
} from "./hqc";

/**
 * Live measurement of the concatenated code's error budget.
 *
 * The page used to quote a fixed table ("100% up to 13 flips, ~99% at 15, ~91% at
 * 17, ~62% at 20") measured offline and then asserted. Nothing on the page checked
 * it, and a learner had no way to falsify it. This sweep measures the same curve
 * from the keypair in front of them: for each flip count it draws fresh
 * encapsulations, aims every flip inside the CODEWORD_BITS-wide region the decoder
 * reads, decapsulates for real, and counts exact seed recoveries.
 */

export interface BudgetPoint {
  flips: number;
  recovered: number;
  trials: number;
  foAccepted: number;
}

export interface BudgetSweep {
  points: BudgetPoint[];
  codewordBits: number;
  trialsPerPoint: number;
  /** Largest swept flip count at which every trial still recovered the seed. */
  lastPerfect: number;
  /** Smallest swept flip count at which no trial recovered the seed, or null. */
  firstTotalFailure: number | null;
  /** Total decapsulations performed. */
  decapsulations: number;
}

export interface BudgetProgress {
  done: number;
  total: number;
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

export const BUDGET_FLIP_LEVELS: readonly number[] = [
  0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20, 24, 28, 32
];

export async function measureErrorBudget(
  keyPair: HqcKeyPair,
  trialsPerPoint: number,
  onProgress: (p: BudgetProgress) => void
): Promise<BudgetSweep> {
  const levels = BUDGET_FLIP_LEVELS.filter((k) => k <= CODEWORD_BITS);
  const total = levels.length * trialsPerPoint;
  let done = 0;
  const points: BudgetPoint[] = [];

  for (const flips of levels) {
    let recovered = 0;
    let foAccepted = 0;
    for (let i = 0; i < trialsPerPoint; i += 1) {
      const enc = await encapsulateIllustrative(keyPair);
      // Every flip is aimed inside the codeword region, so `flips` is the number of
      // errors the decoder actually has to survive — not a raw count that mostly
      // lands in the masking bits it never reads.
      const tampered = flipRandomBits(enc.ciphertext, "v", flips, CODEWORD_BITS);
      const dec = await decapsulateIllustrative(keyPair, tampered.ciphertext);
      if (fullHex(dec.recoveredSeed) === fullHex(enc.messageSeed)) recovered += 1;
      if (dec.verified) foAccepted += 1;
      done += 1;
      if (i % 5 === 0 || i === trialsPerPoint - 1) {
        onProgress({ done, total });
        await yieldToBrowser();
      }
    }
    points.push({ flips, recovered, trials: trialsPerPoint, foAccepted });
  }

  let lastPerfect = -1;
  for (const p of points) {
    if (p.recovered === p.trials) lastPerfect = p.flips;
    else break;
  }
  const firstFail = points.find((p) => p.recovered === 0);

  return {
    points,
    codewordBits: CODEWORD_BITS,
    trialsPerPoint,
    lastPerfect,
    firstTotalFailure: firstFail ? firstFail.flips : null,
    decapsulations: total
  };
}

export function renderBudgetSweep(target: HTMLElement, sweep: BudgetSweep): void {
  const rows = sweep.points
    .map((p) => {
      const pct = ((p.recovered / p.trials) * 100).toFixed(1);
      const width = Math.round((p.recovered / p.trials) * 100);
      return `
        <tr data-budget-flips="${p.flips}">
          <td>${p.flips}</td>
          <td>
            <div class="verif-bar"><div class="verif-fill" style="width:${width}%"></div></div>
            <span class="verif-pct">${p.recovered}/${p.trials} (${pct}%)</span>
          </td>
          <td>${p.foAccepted}/${p.trials}</td>
        </tr>`;
    })
    .join("");

  const perfectText =
    sweep.lastPerfect < 0
      ? `not even ${sweep.points[0].flips} flips recovered on every trial in this run`
      : `every one of the ${sweep.trialsPerPoint} trials recovered the seed exactly up to <strong>${sweep.lastPerfect}</strong> in-codeword flips`;
  const mutated = sweep.points.filter((p) => p.flips > 0);
  const mutatedTrials = mutated.reduce((sum, p) => sum + p.trials, 0);
  const mutatedAccepted = mutated.reduce((sum, p) => sum + p.foAccepted, 0);
  const failText =
    sweep.firstTotalFailure === null
      ? `no swept flip count wiped out recovery entirely in this run`
      : `recovery reached <strong>zero</strong> for the first time at <strong>${sweep.firstTotalFailure}</strong> in-codeword flips`;

  target.innerHTML = `
    <div class="table-wrap" role="region" tabindex="0" aria-label="Decoding budget sweep results">
      <table>
        <caption>
          Measured just now: ${sweep.decapsulations} real decapsulations against the keypair
          loaded above, ${sweep.trialsPerPoint} per row, every flip aimed inside the
          ${sweep.codewordBits}-bit codeword region.
        </caption>
        <thead>
          <tr>
            <th>In-codeword flips</th>
            <th>Seed recovered (pre-FO)</th>
            <th>FO accepted</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="small" id="budget-summary">
      In this run, ${perfectText}, and ${failText}. Those two numbers are counted from the
      table above, not quoted from an offline measurement — rerun the sweep and they will
      move with the sampling. The right-hand column is the separate lesson: across the
      <strong>${mutatedTrials}</strong> trials in this sweep that actually changed
      <code>v</code>, the FO check accepted <strong>${mutatedAccepted}</strong> of them —
      it rejects on any change at all, whether or not the code could still decode.
    </p>
  `;
}
