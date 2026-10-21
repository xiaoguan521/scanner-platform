import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('../e2e/core-journey.spec.mjs', import.meta.url), 'utf8');

test('real-target browser journey requires explicit isolated scope', () => {
  assert.match(source, /LAB_ENV !== 'isolated'/);
  assert.match(source, /SCANNER_E2E_CONFIRM/);
  assert.match(source, /SCANNER_E2E_TARGET_IP/);
  assert.match(source, /SCANNER_E2E_PORT_RANGES/);
  assert.match(source, /net\.isIP/);
  assert.doesNotMatch(source, /192\.0\.2\.|198\.51\.100\.|203\.0\.113\./);
  assert.doesNotMatch(source, /100\.97\.|192\.168\.|10\./);
});

console.log('real-target browser journey scope contract passed');
