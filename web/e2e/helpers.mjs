import net from 'node:net';
import { expect } from '@playwright/test';

export function required(name) {
  const value = process.env[name]?.trim();
  if (!value) throw new Error(`${name} is required; the browser test never invents credentials or scan scope`);
  return value;
}

export function authorizedScope() {
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

export async function login(page) {
  await page.goto('/#/assets');
  const username = page.getByLabel('用户名', { exact: true });
  if (await username.isVisible().catch(() => false)) {
    await username.fill(required('SCANNER_E2E_USERNAME'));
    await page.getByLabel('密码', { exact: true }).fill(required('SCANNER_E2E_PASSWORD'));
    await page.getByRole('button', { name: '登录', exact: true }).click();
  }
  await expect(page.getByText('资产列表', { exact: true })).toBeVisible();
}

export async function chooseSelect(dialog, label, option) {
  await dialog.getByLabel(label, { exact: true }).click();
  await dialog.page().getByText(option, { exact: false }).last().click();
}
