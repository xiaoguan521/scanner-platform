import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

const client = await readFile(new URL('../../api/client.ts', import.meta.url), 'utf8');
const page = await readFile(new URL('./index.tsx', import.meta.url), 'utf8');

test('task registry uses bounded Server pagination and server filters', () => {
  assert.match(client, /tasksPage\(page:number,pageSize:number/);
  assert.match(client, /archived:options\.archived/);
  assert.match(client, /if\(options\.status/);
  assert.match(client, /if\(options\.engine/);
  assert.match(page, /taskPageSize/);
  assert.match(page, /taskTotal/);
  assert.match(page, /taskStatusCounts/);
  assert.match(page, /showSizeChanger:true/);
  assert.doesNotMatch(page, /const filteredTasks=/, 'task filtering must not fall back to the current browser page');
});

console.log('task list pagination contracts passed');
