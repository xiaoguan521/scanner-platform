import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('./navigation.ts', import.meta.url), 'utf8');

test('navigation defines the six product domains in order', () => {
  const labels = [...source.matchAll(/\{ key: '(overview|assets|scans|findings|reports)', label: '([^']+)'/g)].map(match => match[2]);
  assert.deepEqual([...labels, '系统'], ['总览', '资产', '扫描', '漏洞', '报告', '系统']);
  assert.match(source, /key: 'system',[\s\S]*label: '系统'/);
  assert.match(source, /export function visibleNavigation/);
  assert.match(source, /roles\.includes\(role\)/);
});

test('system settings is exposed only to administrators while notifications stay hidden', () => {
  assert.match(source, /key: '\/settings', label: '系统设置', roles: \['admin'\]/);
  assert.doesNotMatch(source, /key: '\/notifications'/);
});
