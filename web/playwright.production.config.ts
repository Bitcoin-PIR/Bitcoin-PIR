import { defineConfig } from '@playwright/test';

const productionUrl = process.env.BPIR_WEB_URL ?? 'https://www.bitcoinpir.org/';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'strict-production.spec.ts',
  // A failing provider must not suppress the other independent backends, but
  // keep live production load bounded.
  fullyParallel: true,
  workers: 2,
  retries: 0,
  timeout: 12 * 60 * 1000,
  expect: {
    timeout: 30 * 1000,
  },
  outputDir: 'test-results/strict-production',
  reporter: [
    ['line'],
    ['html', { outputFolder: 'playwright-report', open: 'never' }],
  ],
  use: {
    baseURL: productionUrl,
    browserName: 'chromium',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
    video: 'retain-on-failure',
  },
});
