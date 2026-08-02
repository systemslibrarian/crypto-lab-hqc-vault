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
  await expect(page.locator('#flip-output')).toContainText('recovery gets less likely, it does not fall off a cliff');
  await expect(page.locator('#flip-output')).toContainText('This run did change v');
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
