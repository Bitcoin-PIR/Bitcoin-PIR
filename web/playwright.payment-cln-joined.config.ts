import { defineConfig } from '@playwright/test';

const port = 4185;
process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_WEB_ORIGIN = `http://127.0.0.1:${port}`;
process.env.BITCOINPIR_PAYMENT_TWO_PROVIDER_BACKEND = 'cln-regtest';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'payment-two-provider-cln-joined.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 180_000,
  // The opt-in runner can contend with a clean native fixture build before
  // browser execution; the outer script still owns and cleans every daemon.
  globalTimeout: 2_700_000,
  expect: { timeout: 30_000 },
  outputDir: 'test-results/payment-cln-joined',
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
    // The browser sees disposable invoices and claim material. Keep the joined
    // runner's failure path from persisting them as rich Playwright artifacts.
    screenshot: 'off',
    trace: 'off',
    video: 'off',
  },
});
