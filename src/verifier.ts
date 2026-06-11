import {
  type HqcLevel,
  decapsulateIllustrative,
  encapsulateIllustrative,
  flipRandomBits,
  fullHex,
  generateIllustrativeKeyPair
} from "./hqc";

export interface VerifierProgress {
  done: number;
  total: number;
  cleanOk: number;
  cleanFail: number;
}

export interface VerifierFinal {
  cleanOk: number;
  cleanTotal: number;
  bitFlip: Array<{ flips: number; seedOk: number; trials: number; foVerified: number }>;
}

export async function runVerifier(
  level: HqcLevel,
  trialsPerCondition: number,
  onProgress: (p: VerifierProgress) => void
): Promise<VerifierFinal> {
  const flipLevels = [0, 2, 4, 6, 8, 10, 12, 16, 20, 25, 30, 40];
  const total = trialsPerCondition + flipLevels.length * trialsPerCondition;

  let cleanOk = 0;
  let cleanFail = 0;
  let done = 0;

  const kp = await generateIllustrativeKeyPair(level);

  for (let i = 0; i < trialsPerCondition; i += 1) {
    const enc = await encapsulateIllustrative(kp);
    const dec = await decapsulateIllustrative(kp, enc.ciphertext);
    if (dec.verified && fullHex(enc.sharedSecret) === fullHex(dec.sharedSecret)) cleanOk += 1;
    else cleanFail += 1;
    done += 1;
    if (i % 5 === 0 || i === trialsPerCondition - 1) {
      onProgress({ done, total, cleanOk, cleanFail });
      await yieldToBrowser();
    }
  }

  const bitFlip: VerifierFinal["bitFlip"] = [];
  for (const flips of flipLevels) {
    let seedOk = 0;
    let verified = 0;
    for (let i = 0; i < trialsPerCondition; i += 1) {
      const enc = await encapsulateIllustrative(kp);
      const tampered = flipRandomBits(enc.ciphertext, "v", flips);
      const dec = await decapsulateIllustrative(kp, tampered.ciphertext);
      if (fullHex(dec.recoveredSeed) === fullHex(enc.messageSeed)) seedOk += 1;
      if (dec.verified) verified += 1;
      done += 1;
      if (i % 5 === 0 || i === trialsPerCondition - 1) {
        onProgress({ done, total, cleanOk, cleanFail });
        await yieldToBrowser();
      }
    }
    bitFlip.push({ flips, seedOk, trials: trialsPerCondition, foVerified: verified });
  }

  return { cleanOk, cleanTotal: trialsPerCondition, bitFlip };
}

function yieldToBrowser(): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, 0));
}

export function renderVerifierResults(target: HTMLElement, final: VerifierFinal): void {
  const cleanPct = ((final.cleanOk / final.cleanTotal) * 100).toFixed(1);
  const rows = final.bitFlip
    .map((row) => {
      const seedPct = ((row.seedOk / row.trials) * 100).toFixed(1);
      const verifiedPct = ((row.foVerified / row.trials) * 100).toFixed(1);
      const width = Math.round((row.seedOk / row.trials) * 100);
      return `
        <tr>
          <td>${row.flips}</td>
          <td>
            <div class="verif-bar"><div class="verif-fill" style="width:${width}%"></div></div>
            <span class="verif-pct">${row.seedOk}/${row.trials} (${seedPct}%)</span>
          </td>
          <td>${row.foVerified}/${row.trials} (${verifiedPct}%)</td>
        </tr>`;
    })
    .join("");

  target.innerHTML = `
    <p>
      <strong>Clean roundtrip:</strong> ${final.cleanOk}/${final.cleanTotal} (${cleanPct}%) — empirical
      check of the perfect-correctness claim on the chosen illustrative parameters.
    </p>
    <div class="table-wrap">
      <table>
        <caption>Seed recovery after random bit flips in ciphertext v</caption>
        <thead>
          <tr>
            <th>Flips</th>
            <th>Seed recovered (pre-FO)</th>
            <th>FO check verified</th>
          </tr>
        </thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
    <p class="small">
      The middle column is what the concatenated code achieves on its own. The right column
      shows how the Fujisaki-Okamoto verification rejects every tampered ciphertext — that is
      the chosen-ciphertext security guarantee in action.
    </p>
  `;
}
