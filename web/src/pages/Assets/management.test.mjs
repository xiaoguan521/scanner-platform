import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');
const nav = fs.readFileSync(new URL('../../components/Layout/navigation.ts', import.meta.url), 'utf8');
const groups = fs.readFileSync(new URL('../BusinessGroups/index.tsx', import.meta.url), 'utf8');
const history = fs.readFileSync(new URL('../AssetImportHistory/index.tsx', import.meta.url), 'utf8');

test('asset management uses server resources and safe import summaries', () => {
  assert.match(client, /businessGroups\(\).*\/api\/v1\/business-groups/);
  assert.match(client, /createBusinessGroup\(name:string\).*business-groups.*POST/);
  assert.match(client, /assetImportHistory\(\).*\/api\/v1\/assets\/import-history/);
  assert.match(nav, /\/business-groups', label: '业务组'/);
  assert.match(nav, /\/asset-import-history', label: '导入记录'/);
  assert.match(groups, /apiClient\.createBusinessGroup/);
  assert.match(history, /apiClient\.assetImportHistory/);
  assert.match(history, /不保存 CSV 原文、目标地址或资产清单/);
});

console.log('asset management UI contracts passed');
