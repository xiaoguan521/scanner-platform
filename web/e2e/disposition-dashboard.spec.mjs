import { expect, test } from '@playwright/test';
import { authorizedScope, login } from './helpers.mjs';

test('dashboard down-drill reaches the real findings collection', async ({ page }) => {
  authorizedScope();
  await login(page);
  await page.goto('/#/');
  await expect(page.getByText('检测结果口径', { exact: true })).toBeVisible();
  await page.getByRole('link', { name: '查看漏洞列表', exact: true }).click();
  await expect(page).toHaveURL(/#\/findings/);
  await expect(page.getByText('漏洞发现与生命周期闭环看板', { exact: true })).toBeVisible();
  await expect(page.getByLabel('检测方式筛选', { exact: true })).toBeVisible();
});

test('finding detail can be opened without mutating the finding', async ({ page }) => {
  authorizedScope();
  const findingID = process.env.SCANNER_E2E_FINDING_ID?.trim();
  test.skip(!findingID, 'set SCANNER_E2E_FINDING_ID to inspect one existing authorized finding');
  await login(page);
  const response = await page.request.get('/api/v1/findings');
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  const finding = body.items?.find((item) => item.id === findingID);
  expect(finding, `finding ${findingID} was not returned by the authenticated Server`).toBeTruthy();
  await page.goto('/#/findings');
  await page.getByLabel('按目标、组件或 CVE 筛选', { exact: true }).fill(finding.title);
  const row = page.locator('tr').filter({ hasText: finding.title }).first();
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: `查看详情：${finding.title}`, exact: true }).click();
  const drawer = page.getByRole('dialog').filter({ hasText: '发现项详情' });
  await expect(drawer).toBeVisible();
  await expect(drawer).toContainText(finding.title);
  await expect(drawer).toContainText('风险处置');
});
