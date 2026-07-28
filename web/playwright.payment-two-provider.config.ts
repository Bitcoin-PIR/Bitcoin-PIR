import { defineConfig } from '@playwright/test';

const port = 4184;
process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_WEB_ORIGIN = `http://127.0.0.1:${port}`;
process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND = 'fake';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'payment-two-provider.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  // A clean runner compiles the optimized unified_server fixture before any
  // browser step. Keep individual scenarios tightly bounded while allowing
  // that one-time deterministic build to finish on slower CI hosts.
  globalTimeout: 2_700_000,
  expect: { timeout: 15_000 },
  outputDir: 'test-results/payment-two-provider',
  reporter: [['line']],
  globalSetup: './e2e/payment-two-provider.global-setup.ts',
  webServer: {
    command:
      `./node_modules/.bin/vite --config vite.payment-real-issuer.config.ts `
      + `--host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}/e2e/payment-two-provider.html`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    browserName: 'chromium',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
