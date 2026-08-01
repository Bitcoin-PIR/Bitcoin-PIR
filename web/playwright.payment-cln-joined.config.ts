import { defineConfig } from '@playwright/test';

const configuredPort = process.env.BITCOINPIR_PAYMENT_CLN_JOINED_WEB_PORT;
const port = configuredPort === undefined ? 4185 : Number(configuredPort);
if (!Number.isInteger(port) || port < 20_000 || port > 65_535) {
  throw new Error('BITCOINPIR_PAYMENT_CLN_JOINED_WEB_PORT must be a high TCP port');
}
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
