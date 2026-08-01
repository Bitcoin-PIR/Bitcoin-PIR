import { defineConfig } from '@playwright/test';

const configuredPort = process.env.BITCOINPIR_PAYMENT_CLN_REGTEST_WEB_PORT;
const port = configuredPort === undefined ? 4183 : Number(configuredPort);
if (!Number.isInteger(port) || port < 20_000 || port > 65_535) {
  throw new Error('BITCOINPIR_PAYMENT_CLN_REGTEST_WEB_PORT must be a high TCP port');
}
process.env.BITCOINPIR_PAYMENT_REAL_WEB_ORIGIN = `http://127.0.0.1:${port}`;
process.env.BITCOINPIR_PAYMENT_REAL_BACKEND = 'cln-regtest';

export default defineConfig({
  testDir: './e2e',
  testMatch: 'payment-real-issuer.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 120_000,
  globalTimeout: 420_000,
  expect: { timeout: 20_000 },
  outputDir: 'test-results/payment-cln-regtest',
  reporter: [['line']],
  globalSetup: './e2e/payment-real-issuer.global-setup.ts',
  webServer: {
    command:
      `./node_modules/.bin/vite --config vite.payment-real-issuer.config.ts `
      + `--host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}/e2e/payment-real-issuer.html`,
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
