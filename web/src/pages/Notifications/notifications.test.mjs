import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const page = fs.readFileSync(new URL('./index.tsx', import.meta.url), 'utf8');
const client = fs.readFileSync(new URL('../../api/client.ts', import.meta.url), 'utf8');

test('notification center reads and updates server-backed notification state', () => {
  assert.match(page, /apiClient\.notifications\(\)/);
  assert.match(page, /apiClient\.markNotificationRead\(item\.id\)/);
  assert.match(page, /apiClient\.markAllNotificationsRead\(\)/);
  assert.match(client, /'\/api\/v1\/notifications/);
});
