import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const page = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');

test('knowledge page uses bounded Server pagination and search', () => {
  assert.match(client, /knowledgePage\(page:number,pageSize:number/);
  assert.match(client, /\/api\/v1\/knowledge\?/);
  assert.match(page, /apiClient\.knowledgePage/);
  assert.match(page, /pageSize/);
  assert.match(page, /total/);
});

console.log('knowledge pagination UI contract passed');
