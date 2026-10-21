import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const page = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');

test('system settings page uses authenticated Server settings and optional Webhook delivery', () => {
  assert.match(page, /apiClient\.systemSettings\(\)/);
  assert.match(page, /apiClient\.saveSystemSettings\(values\)/);
  assert.match(page, /apiClient\.notificationSettings\(\)/);
  assert.match(page, /apiClient\.saveNotificationSettings\(values\)/);
  assert.match(page, /apiClient\.notificationDeliveries\(\)/);
  assert.match(page, /默认关闭，发送安全摘要/);
  assert.match(client, /'\/api\/v1\/system-settings'/);
  assert.match(client, /'\/api\/v1\/notification-settings'/);
  assert.match(client, /\/api\/v1\/notification-deliveries/);
});
