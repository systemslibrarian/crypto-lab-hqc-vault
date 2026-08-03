import { expect, test, type Page } from '@playwright/test';

async function prepareKem(page: Page): Promise<void> {
  await page.goto('.');
  await page.locator('#keygen-btn').click();
  await expect(page.locator('#keygen-output')).toContainText('public h', { timeout: 20_000 });
  await page.locator('#encap-btn').click();
  await expect(page.locator('#kem-output')).toContainText('MATCH', { timeout: 20_000 });
}

test('zero flips is a clean control and 40 flips report actual codeword hits', async ({ page }) => {
  await prepareKem(page);

  await page.locator('#flip-run').click();
  await expect(page.locator('#flip-output')).toContainText('unchanged clean control');
  await expect(page.locator('#flip-output')).toContainText('FO acceptance is expected');

  await page.locator('#flip-slider').fill('40');
  await page.locator('#flip-run').click();
  await expect(page.locator('#flip-output')).toContainText('landed inside the 120-bit codeword region');
  await expect(page.locator('#flip-output')).toContainText('Placement was anywhere in v');
  await expect(page.locator('#flip-output')).toContainText('This run did change v');
});

test('the page no longer quotes an offline error-budget table', async ({ page }) => {
  await page.goto('.');
  const body = await page.locator('body').innerText();
  expect(body).not.toContain('2000 trials');
  await expect(page.locator('#budget-output')).toContainText('not measured yet');
});

/**
 * The failure path. With placement left on "anywhere in v" a flip lands in the
 * 120-bit codeword region only 120 times in n, so the slider's maximum usually
 * still decodes — reaching a decode failure was a dice roll. Aiming every flip
 * inside the codeword region makes 40 errors land where the decoder reads, which
 * is far past what RM+RS can correct, so seed recovery must fail. If this ever
 * passes with "YES", the placement control is not aiming the flips.
 */
test('targeted flips reach a real decode failure, not just an FO rejection', async ({ page }) => {
  await prepareKem(page);

  await page.locator('#flip-placement').selectOption('codeword');
  await page.locator('#flip-slider').fill('40');
  await page.locator('#flip-run').click();

  const out = page.locator('#flip-output');
  // Every flip is in-region: the reported in-codeword count equals the slider.
  await expect(out).toContainText('Of those, 40 landed inside the 120-bit codeword region');
  await expect(out).toContainText('Placement was codeword region only');
  await expect(out).toContainText('exceeded what the code could correct');
  // Pre-FO seed recovery genuinely fails, and the FO check rejects too.
  await expect(out).toContainText('Seed pre-FO recovered exactly? NO');
  await expect(out).toContainText('FO check accepted? NO');

  const seeds = await out.locator('code.hex').allInnerTexts();
  expect(seeds).toHaveLength(2);
  expect(seeds[0]).not.toBe(seeds[1]);
});

/**
 * The error-budget curve is measured from the learner's own keypair rather than
 * quoted. Assertions are on the shape the measurement must have — a clean control
 * that recovers and a far-past-budget point that mostly does not — plus the fact
 * that the row count and decapsulation total are derived from the sweep.
 */
test('error-budget sweep is measured live from the loaded keypair', async ({ page }) => {
  test.setTimeout(120_000);
  await prepareKem(page);

  await page.locator('#budget-trials').selectOption('10');
  await page.locator('#budget-run').click();
  await expect(page.locator('#budget-progress')).toHaveText('Done.', { timeout: 100_000 });

  const rows = page.locator('#budget-output tr[data-budget-flips]');
  await expect(rows).toHaveCount(14);
  await expect(page.locator('#budget-output caption')).toContainText('140 real decapsulations');

  const readRate = async (flips: number): Promise<number> => {
    const text = await page
      .locator(`#budget-output tr[data-budget-flips="${flips}"] .verif-pct`)
      .innerText();
    const m = text.match(/^(\d+)\/(\d+)/);
    if (!m) throw new Error(`unparsable rate cell: ${text}`);
    return Number(m[1]) / Number(m[2]);
  };

  // Clean control decodes; 32 errors inside a 120-bit codeword is far past what
  // RS(15,4) over RM(1,3) can correct, so recovery has to collapse.
  expect(await readRate(0)).toBeGreaterThanOrEqual(0.9);
  expect(await readRate(32)).toBeLessThanOrEqual(0.5);
  expect(await readRate(0)).toBeGreaterThan(await readRate(32));

  // The FO column is measured, not asserted: no mutated trial may be accepted.
  await expect(page.locator('#budget-summary')).toContainText('the FO check accepted 0 of them');
  await expect(page.locator('#budget-summary')).toContainText('counted from the table above');
});

test('verifier labels only mutated ciphertexts and derives its FO total', async ({ page }) => {
  test.setTimeout(60_000);
  await page.goto('.');
  await page.locator('#verify-trials').selectOption('20');
  await page.locator('#verify-run').click();
  await expect(page.locator('#verify-progress')).toHaveText('Done.', { timeout: 50_000 });

  await expect(page.locator('#verify-output tr[data-flips="0"]')).toHaveCount(0);
  await expect(page.locator('#verify-output tr[data-flips="1"]')).toHaveCount(1);
  await expect(page.locator('#fo-verifier-summary')).toContainText(
    'this run rejected 240/240 ciphertexts after one or more bits were flipped, with no accepts',
  );
});

test('side-channel rows measure planted positions, not accidental markers', async ({ page }) => {
  await page.goto('.');
  await page.locator('#sc-run').click();
  await expect(page.locator('#sc-output .sc-chart')).toBeVisible({ timeout: 20_000 });
  await expect(page.locator('#sc-output')).not.toContainText('Measurement invalid');
  await expect(page.locator('#sc-output .sc-label')).toHaveText([
    'marker @ 10',
    'marker @ 256',
    'marker @ 1024',
    'marker @ 2048',
    'marker @ 3072',
    'marker @ 4086',
  ]);
});

test('HQC equation and DFR disclosures remain corrected', async ({ page }) => {
  await page.goto('.');
  await expect(page.locator('#panel-encap')).toContainText('u = r1 + h·r2');
  await expect(page.locator('#panel-encap')).not.toContainText('u = r1 + h·r2 + e');

  const hqcRows = page.locator('#compare-rows tr').filter({ hasText: /HQC-/ });
  await expect(hqcRows).toHaveCount(3);
  for (let i = 0; i < 3; i += 1) {
    await expect(hqcRows.nth(i)).toContainText('non-zero');
  }
});
