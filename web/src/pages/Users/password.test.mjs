// Run from repository root: node web/src/pages/Users/password.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const client = await readFile(new URL('../../api/client.ts', import.meta.url), 'utf8');
const page = await readFile(new URL('./index.tsx', import.meta.url), 'utf8');
assert.match(client, /resetUserPassword\(id: string, password: string\)/);
assert.match(client, /password-reset/);
assert.match(page, /重置密码/);
assert.match(page, /旧会话已失效/);
assert.match(page, /两次输入的新密码不一致/);
console.log('user password reset contracts passed');
