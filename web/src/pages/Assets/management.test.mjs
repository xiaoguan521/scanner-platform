import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');
const nav = fs.readFileSync(new URL('../../components/Layout/navigation.ts', import.meta.url), 'utf8');
const groups = fs.readFileSync(new URL('../BusinessGroups/index.tsx', import.meta.url), 'utf8');
const history = fs.readFileSync(new URL('../AssetImportHistory/index.tsx', import.meta.url), 'utf8');
const assetsPage = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');

test('asset management uses server resources and safe import summaries', () => {
  assert.match(client, /businessGroups\(\).*\/api\/v1\/business-groups/);
  assert.match(client, /createBusinessGroup\(name:string\).*business-groups.*POST/);
  assert.match(client, /assetImportHistory\(\).*\/api\/v1\/assets\/import-history/);
  assert.match(client, /businessGroupsPage\(page:number,pageSize:number/);
  assert.match(client, /assetImportHistoryPage\(page:number,pageSize:number/);
  assert.match(nav, /\/business-groups', label: '业务组'/);
  assert.match(nav, /\/asset-import-history', label: '导入记录'/);
  assert.match(groups, /apiClient\.createBusinessGroup/);
  assert.match(history, /apiClient\.assetImportHistory/);
  assert.match(groups, /businessGroupsPage|pageSize/);
  assert.match(history, /assetImportHistoryPage|pageSize/);
  assert.match(history, /不保存 CSV 原文、目标地址或资产清单/);
});

test('asset registry exposes scan history and active risk summaries', () => {
  assert.match(assetsPage, /useCollection\('findings'\)/);
  assert.match(assetsPage, /title:'最近扫描'/);
  assert.match(assetsPage, /title:'当前风险数'/);
  assert.match(assetsPage, /title="漏洞摘要"/);
  assert.match(assetsPage, /title="扫描历史"/);
  assert.match(assetsPage, /findingError.*未知/);
});

test('asset registry uses bounded Server pagination', () => {
  assert.match(client, /assetsPage\(page:number,pageSize:number,search:string/);
  assert.match(client, /page_size/);
  assert.match(assetsPage, /assetPageSize/);
  assert.match(assetsPage, /assetTotal/);
  assert.match(assetsPage, /showSizeChanger:true/);
});

console.log('asset management UI contracts passed');
