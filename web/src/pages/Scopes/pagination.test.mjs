import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const page = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');

test('approval ledgers use bounded server pagination and filters', () => {
  assert.match(client, /scopesPage\(page:number,pageSize:number/);
  assert.match(client, /portRequestsPage\(page:number,pageSize:number/);
  assert.match(client, /\/api\/v1\/scopes\?/);
  assert.match(client, /\/api\/v1\/port-requests\?/);
  assert.match(page, /scopePageSize/);
  assert.match(page, /portPageSize/);
  assert.match(page, /expiryFilter/);
  assert.match(page, /portStatus/);
  assert.match(page, /portSearch/);
  assert.match(page, /showSizeChanger: true/);
});

test('approval ledgers expose atomic approved-scope renewal', () => {
  assert.match(client, /renewScopes\(ids:string\[\],\s*expiresAt:string\)/);
  assert.match(client, /\/api\/v1\/scopes\/renew/);
  assert.match(page, /批量续期/);
  assert.match(page, /preserveSelectedRowKeys: true/);
  assert.match(page, /scopeStatus\(scope\) !== 'APPROVED'/);
  assert.match(page, /不会直接延长扫描执行权限/);
});

console.log('approval pagination UI contract passed');
