import { defineConfig } from '@playwright/test';

const port = 4184;

export default defineConfig({
  testDir: './e2e',
  testMatch: 'payment-cdk-cashu.spec.ts',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  globalTimeout: 120_000,
  expect: { timeout: 15_000 },
  outputDir: 'test-results/payment-cdk-cashu',
  reporter: [['line']],
  webServer: {
    command:
      `./node_modules/.bin/vite --config vite.payment-cdk-cashu.config.ts `
      + `--host 127.0.0.1 --port ${port} --strictPort`,
    url: `http://127.0.0.1:${port}/e2e/payment-cdk-cashu.html`,
    reuseExistingServer: false,
    timeout: 60_000,
  },
  use: {
    baseURL: `http://127.0.0.1:${port}`,
    browserName: 'chromium',
    headless: true,
    screenshot: 'off',
    trace: 'off',
    video: 'off',
  },
});
