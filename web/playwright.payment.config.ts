import { defineConfig } from '@playwright/test';

const port = 4178;

export default defineConfig({
  testDir: './e2e',
  testMatch: 'payment-multitab.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  outputDir: 'test-results/payment-vault',
  reporter: [['line']],
  webServer: {
    command:
      `./node_modules/.bin/vite --config vite.payment-test.config.ts `
      + `--host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}/e2e/payment-vault.html`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    browserName: 'chromium',
    headless: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
});
