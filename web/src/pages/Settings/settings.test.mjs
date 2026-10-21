import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const page = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');

test('system settings page uses the authenticated Server API and keeps notifications explicit', () => {
  assert.match(page, /apiClient\.systemSettings\(\)/);
  assert.match(page, /apiClient\.saveSystemSettings\(values\)/);
  assert.match(page, /通知中心可查看平台内提醒/);
  assert.match(client, /'\/api\/v1\/system-settings'/);
});
