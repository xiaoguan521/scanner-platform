import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const helper = fs.readFileSync(new URL('../e2e/helpers.mjs', import.meta.url), 'utf8');
const journeySources = ['core-journey.spec.mjs', 'disposition-dashboard.spec.mjs', 'schedule-report.spec.mjs']
  .map(name => fs.readFileSync(new URL(`../e2e/${name}`, import.meta.url), 'utf8'));

test('real-target browser journey requires explicit isolated scope', () => {
  assert.match(helper, /LAB_ENV !== 'isolated'/);
  assert.match(helper, /SCANNER_E2E_CONFIRM/);
  assert.match(helper, /SCANNER_E2E_TARGET_IP/);
  assert.match(helper, /SCANNER_E2E_PORT_RANGES/);
  assert.match(helper, /net\.isIP/);
  for (const source of [helper, ...journeySources]) {
    assert.doesNotMatch(source, /192\.0\.2\.|198\.51\.100\.|203\.0\.113\./);
    assert.doesNotMatch(source, /100\.97\.|192\.168\.|10\./);
  }
});

test('all browser journeys require the shared authorization gate', () => {
  for (const source of journeySources) {
    assert.match(source, /authorizedScope\(\)/);
    assert.match(source, /login\(page\)/);
  }
});

console.log('real-target browser journey scope contract passed');
