import { readFileSync, writeFileSync } from 'node:fs';
import AxeBuilder from '@axe-core/playwright';
import { expect, test } from '@playwright/test';
import { login } from './helpers.mjs';

// Read-only accessibility baseline: it only opens pages, reads the DOM and
// sets the viewer's own theme preference in the browser, so
// it creates no records and starts no scans. Serious and critical axe findings
// are compared with the committed baseline; a new rule on a page fails the run.
// Refresh the baseline after fixing issues with SCANNER_E2E_A11Y_UPDATE=1.
const baselineFile = new URL('./a11y-baseline.json', import.meta.url);
const pages = [
  ['/#/', '态势总览'],
  ['/#/findings', '漏洞列表'],
  ['/#/tasks', '扫描任务'],
  ['/#/assets', '资产列表'],
  ['/#/scopes', '授权范围'],
  ['/#/reports', '报告中心'],
  ['/#/nodes', '节点与规则库'],
  ['/#/knowledge', '漏洞知识库'],
  ['/#/business-groups', '业务组'],
  ['/#/asset-import-history', '资产导入记录'],
  ['/#/users', '用户与角色'],
  ['/#/audit', '审计日志'],
  ['/#/settings', '系统设置'],
  ['/#/notifications', '通知中心'],
];

test('pages have no new serious accessibility violations', async ({ page }) => {
  await login(page);
  const baseline = JSON.parse(readFileSync(baselineFile, 'utf8'));
  const found = {};
  const added = [];
  // Both themes ship, so each page is scanned in dark (default) and light.
  for (const theme of ['dark', 'light']) for (const [route, heading] of pages) {
    const path = theme === 'dark' ? route : `${route} (浅色)`;
    await page.goto(route);
    // Hash routes do not reload the page, so apply the theme with a reload.
    if (await page.evaluate(() => localStorage.getItem('app_theme')) !== theme) {
      await page.evaluate(value => localStorage.setItem('app_theme', value), theme);
      await page.reload();
    }
    await expect(page.getByText(heading, { exact: true }).first()).toBeVisible();
    await page.waitForLoadState('networkidle');
    // Controls fade from disabled to enabled after data loads; scanning mid-fade reports false contrast failures.
    await page.waitForFunction(() => document.getAnimations().every(animation => animation.playState !== 'running'));
    const result = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa']).analyze();
    const rules = result.violations.filter(v => v.impact === 'serious' || v.impact === 'critical').map(v => v.id).sort();
    found[path] = rules;
    for (const rule of rules) {
      if (!(baseline[path] ?? []).includes(rule)) {
        const detail = result.violations.find(v => v.id === rule);
        added.push(`${path} ${rule}: ${detail?.help} (${detail?.nodes.length} 个元素，例如 ${detail?.nodes[0]?.target.join(' ')})`);
      }
    }
  }
  if (process.env.SCANNER_E2E_A11Y_UPDATE === '1') {
    writeFileSync(baselineFile, JSON.stringify(found, null, 2) + '\n');
    return;
  }
  expect(added, '新的无障碍问题').toEqual([]);
});
