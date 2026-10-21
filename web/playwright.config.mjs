import { defineConfig } from '@playwright/test';

// This suite deliberately attaches to an already running local Server. It
// never starts a target, creates an account, seeds records, or invents scope.
// The Make target requires LAB_ENV=isolated and explicit target variables.
export default defineConfig({
  testDir: './e2e',
  fullyParallel: false,
  timeout: 10 * 60 * 1000,
  expect: { timeout: 15 * 1000 },
  reporter: process.env.CI ? 'line' : [['list'], ['html', { open: 'never', outputFolder: 'e2e-report' }]],
  use: {
    baseURL: process.env.SCANNER_E2E_BASE_URL,
    channel: process.env.PW_CHANNEL || 'chrome',
    headless: process.env.PW_HEADLESS !== '0',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
});
