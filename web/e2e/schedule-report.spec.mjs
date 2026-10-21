import { expect, test } from '@playwright/test';
import { authorizedScope, login } from './helpers.mjs';

test('schedule and report pages expose the Server-backed lifecycle', async ({ page }) => {
  authorizedScope();
  await login(page);
  await page.goto('/#/tasks');
  await expect(page.getByText('定时任务', { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: '创建定时任务', exact: true })).toBeVisible();
  await page.getByText('报告中心', { exact: true }).click();
  await expect(page.getByText('生成安全报告', { exact: true })).toBeVisible();
  await expect(page.getByText('报告历史', { exact: true })).toBeVisible();
  await expect(page.getByText('每次生成冻结一份带版本的数据快照', { exact: false })).toBeVisible();
});

test('an existing task can be selected for a frozen report when explicitly supplied', async ({ page }) => {
  authorizedScope();
  const taskID = process.env.SCANNER_E2E_TASK_ID?.trim();
  test.skip(!taskID, 'set SCANNER_E2E_TASK_ID to generate a report from an existing completed task');
  await login(page);
  const response = await page.request.get('/api/v1/tasks?archived=all');
  expect(response.ok()).toBeTruthy();
  const body = await response.json();
  expect(body.items?.some((item) => item.id === taskID), `task ${taskID} was not returned by the authenticated Server`).toBeTruthy();
  await page.goto('/#/reports');
  await page.getByLabel('扫描任务', { exact: true }).click();
  await page.getByText(taskID, { exact: false }).last().click();
  await expect(page.getByLabel('扫描任务', { exact: true })).toContainText(taskID);
});
