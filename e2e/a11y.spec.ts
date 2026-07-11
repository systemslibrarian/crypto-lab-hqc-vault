import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Page } from '@playwright/test';

/**
 * WCAG regression gate. Scans the full page in both themes with every
 * collapsible / hidden region revealed.
 *
 * This lab reveals content several ways:
 *   - <details class="step"> generated inside #kem-steps (a [hidden] panel
 *     toggled by #step-toggle) only after an encapsulation runs.
 *   - aria-live output panels populated by clicking the exhibit buttons.
 * We drive the primary buttons so those panels have real content, enable
 * step-by-step mode, then reveal every hidden/collapsed region and open all
 * <details> before scanning. Animations/transitions are neutralized so nothing
 * is scanned mid-flight.
 */

const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

async function neutralizeMotion(page: Page): Promise<void> {
  await page.addStyleTag({
    content:
      '*, *::before, *::after { animation: none !important; transition: none !important; opacity: 1 !important; }',
  });
}

/** Best-effort click of the exhibit action buttons so live-region panels fill. */
async function driveExhibits(page: Page): Promise<void> {
  // Enable step-by-step so #kem-steps renders its <details> once encap runs.
  await page.locator('#step-toggle').click().catch(() => {});

  const clickIds = ['#keygen-btn', '#encap-btn', '#aes-btn', '#sc-run', '#verify-run'];
  for (const id of clickIds) {
    const el = page.locator(id).first();
    if (await el.count()) {
      await el.click().catch(() => {});
    }
  }
  // Let async crypto/UI settle so aria-live panels and #kem-steps are populated.
  await page.waitForTimeout(400);
}

async function revealAll(page: Page): Promise<void> {
  await page.evaluate(() => {
    // Open every <details> (includes the generated step-through blocks).
    for (const d of document.querySelectorAll('details')) {
      (d as HTMLDetailsElement).open = true;
    }
    // Un-hide any [hidden] panels (e.g. #kem-steps).
    for (const el of document.querySelectorAll<HTMLElement>('[hidden]')) {
      el.hidden = false;
    }
    // Clear inline display:none if any exhibit uses it.
    for (const el of document.querySelectorAll<HTMLElement>('[style*="display"]')) {
      if (el.style && el.style.display === 'none') el.style.display = '';
    }
  });
}

async function scan(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const summary = results.violations.map((v) => ({
    id: v.id,
    impact: v.impact,
    help: v.help,
    nodes: v.nodes.map((n) => n.target.join(' ')).slice(0, 5),
  }));
  expect(summary).toEqual([]);
}

async function runSuite(page: Page): Promise<void> {
  await driveExhibits(page);
  await revealAll(page);
  await neutralizeMotion(page);
  await scan(page);
}

test('no WCAG A/AA violations in dark theme', async ({ page }) => {
  await page.goto('.');
  await runSuite(page);
});

test('no WCAG A/AA violations in light theme', async ({ page }) => {
  await page.goto('.');
  await page.locator('#cl-theme-toggle').click();
  await expect(page.locator('html')).toHaveAttribute('data-theme', 'light');
  await runSuite(page);
});
