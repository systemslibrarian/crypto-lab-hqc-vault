import { defineConfig } from 'vitest/config';

// Unit tests only. The Playwright specs under e2e/ are *.spec.ts files that
// Vitest's default glob would otherwise try to collect (and fail on, since
// they import @playwright/test); keep e2e/ out of the Vitest run.
export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    exclude: ['e2e/**', 'node_modules/**', 'dist/**'],
  },
});
