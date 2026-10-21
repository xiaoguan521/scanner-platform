import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('./client.ts', import.meta.url), 'utf8');

test('server is the default frontend data channel', () => {
  assert.match(source, /VITE_DATA_MODE === 'demo' \? 'demo' : 'server'/);
  assert.doesNotMatch(source, /VITE_DATA_MODE === 'server' \? 'server' : 'demo'/);
});
