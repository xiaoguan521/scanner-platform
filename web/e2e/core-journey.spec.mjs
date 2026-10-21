import net from 'node:net';
import { expect, test } from '@playwright/test';

const required = (name) => {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required; the browser test never invents credentials or scan scope`);
  return value;
};

function authorizedScope() {
  if (process.env.LAB_ENV !== 'isolated' || process.env.SCANNER_E2E_CONFIRM !== 'authorized') {
    throw new Error('Set LAB_ENV=isolated and SCANNER_E2E_CONFIRM=authorized before running the real-target browser journey');
  }
  const target = required('SCANNER_E2E_TARGET_IP');
  if (net.isIP(target) === 0) throw new Error('SCANNER_E2E_TARGET_IP must be one numeric IPv4/IPv6 address');
  const ranges = required('SCANNER_E2E_PORT_RANGES');
  const ports = new Set();
  for (const part of ranges.split(',').map((value) => value.trim())) {
    const match = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(part);
    if (!match) throw new Error(`invalid SCANNER_E2E_PORT_RANGES item: ${part}`);
    const start = Number(match[1]);
    const end = Number(match[2] ?? match[1]);
    if (start < 1 || end > 65535 || start > end) throw new Error(`port outside 1-65535: ${part}`);
    for (let port = start; port <= end && ports.size <= 65535; port += 1) ports.add(port);
  }
  if (ports.size === 0 || ports.size > 65535) throw new Error('SCANNER_E2E_PORT_RANGES must contain 1-65535 ports');
  return { target, ranges };
}

async function login(page) {
  await page.goto('/#/assets');
  const username = page.getByLabel('用户名', { exact: true });
  if (await username.isVisible().catch(() => false)) {
    await username.fill(required('SCANNER_E2E_USERNAME'));
    await page.getByLabel('密码', { exact: true }).fill(required('SCANNER_E2E_PASSWORD'));
    await page.getByRole('button', { name: '登录', exact: true }).click();
  }
  await expect(page.getByText('资产列表', { exact: true })).toBeVisible();
}

async function chooseSelect(dialog, label, option) {
  await dialog.getByLabel(label, { exact: true }).click();
  await dialog.page().getByText(option, { exact: false }).last().click();
}

test('authorized asset to automatic scan result journey', async ({ page }) => {
  const { target, ranges } = authorizedScope();
  await login(page);

  await page.getByText('资产列表', { exact: true }).click();
  await expect(page.getByText('资产登记台账', { exact: true })).toBeVisible();
  const existingAsset = page.locator('tr').filter({ hasText: target });
  if (await existingAsset.count() === 0) {
    await page.getByRole('button', { name: '登记资产', exact: true }).click();
    const dialog = page.getByRole('dialog', { name: '登记新资产' });
    await dialog.getByLabel('资产地址', { exact: true }).fill(target);
    await dialog.getByLabel('所属业务组', { exact: true }).fill('隔离浏览器验收');
    await dialog.getByLabel('责任人', { exact: true }).fill('隔离验收操作者');
    await dialog.getByRole('button', { name: 'OK', exact: true }).click();
    await expect(page.locator('tr').filter({ hasText: target })).toBeVisible();
  }

  await page.getByText('扫描任务与计划', { exact: true }).click();
  await expect(page.getByText('扫描任务', { exact: true })).toBeVisible();
  await page.getByRole('button', { name: '创建扫描任务', exact: true }).click();
  const dialog = page.getByRole('dialog').filter({ hasText: '创建自动综合扫描' });
  await chooseSelect(dialog, '已登记主机', target);
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await chooseSelect(dialog, '探测范围', '自定义范围');
  await dialog.getByLabel('自定义 TCP 端口范围', { exact: true }).fill(ranges);
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByRole('button', { name: '下一步', exact: true }).click();
  await dialog.getByText('我已获得运维对这台主机和所选 TCP 端口范围的探测授权，并已排除已知的 Nginx 四层转发端口', { exact: false }).click();

  const taskResponse = page.waitForResponse((response) => response.url().includes('/api/v1/tasks') && response.request().method() === 'POST');
  await dialog.getByRole('button', { name: '确认并创建', exact: true }).click();
  const response = await taskResponse;
  expect(response.ok()).toBeTruthy();
  const created = await response.json();

  await expect.poll(async () => {
    const list = await page.request.get('/api/v1/tasks?archived=false');
    const body = await list.json();
    return body.items.find((item) => item.id === created.id)?.status ?? 'MISSING';
  }, { timeout: 9 * 60 * 1000, intervals: [1000, 3000, 5000] }).toBe('COMPLETED');

  const list = await page.request.get('/api/v1/tasks?archived=false');
  const body = await list.json();
  const completed = body.items.find((item) => item.id === created.id);
  expect(completed.chunks[0].targets).toEqual([target]);
  expect(completed.portProbePorts.length).toBeGreaterThan(0);
  expect(completed.portProbeResults.length).toBeGreaterThan(0);

  await page.reload();
  const row = page.locator('tr').filter({ hasText: created.id });
  await expect(row).toBeVisible();
  await row.getByRole('button', { name: '详情', exact: true }).click();
  const detail = page.getByRole('dialog').filter({ hasText: `任务详情：${created.id}` });
  await expect(detail).toContainText('扫描结果');
  await expect(detail).toContainText('开放端口');
  await expect(detail).toContainText('只读任务日志');
});
