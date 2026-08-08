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
  // Zero flips is already measured by the clean roundtrip above. Every row in
  // this table must actually mutate the ciphertext before being called tampered.
  const flipLevels = [1, 2, 4, 6, 8, 10, 12, 16, 20, 25, 30, 40];
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
  const tamperedTrials = final.bitFlip.reduce((sum, row) => sum + row.trials, 0);
  const tamperedAccepted = final.bitFlip.reduce((sum, row) => sum + row.foVerified, 0);
  const tamperedRejected = tamperedTrials - tamperedAccepted;
  const rows = final.bitFlip
    .map((row) => {
      const seedPct = ((row.seedOk / row.trials) * 100).toFixed(1);
      const verifiedPct = ((row.foVerified / row.trials) * 100).toFixed(1);
      const width = Math.round((row.seedOk / row.trials) * 100);
      return `
        <tr data-flips="${row.flips}">
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
      check of the decoding failure rate on the chosen illustrative parameters.
    </p>
    <div class="table-wrap" role="region" tabindex="0" aria-label="Seed recovery after random bit flips">
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
    <p class="small" id="fo-verifier-summary">
      The middle column is what the concatenated code achieves on its own. The right column
      records the measured FO result: this run rejected <strong>${tamperedRejected}/${tamperedTrials}</strong>
      ciphertexts after one or more bits were flipped${tamperedAccepted === 0 ? ", with no accepts" : `; ${tamperedAccepted} were unexpectedly accepted`}.
      This demo performs that check the
      Round-4 way, by recomputing the explicit tag <code>d</code>; current HQC instead
      re-encrypts and compares the whole ciphertext, and substitutes a pseudorandom key on
      mismatch. Same guarantee, no transmitted tag.
    </p>
  `;
}
