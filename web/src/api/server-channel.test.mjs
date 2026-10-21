import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const source = fs.readFileSync(new URL('./client.ts', import.meta.url), 'utf8');
const sourceRoot = new URL('../', import.meta.url);
function runtimeSources(directory) {
  return fs.readdirSync(directory, { withFileTypes: true }).flatMap(entry => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return runtimeSources(full);
    return /\.(ts|tsx)$/.test(entry.name) ? [full] : [];
  });
}

test('frontend has one server data channel', () => {
  assert.doesNotMatch(source, /VITE_DATA_MODE/);
  assert.doesNotMatch(source, /isDemoMode|dataMode/);
});

test('runtime pages do not import browser fixtures or demo switches', () => {
  const forbidden = /(?:from\s+['"][^'"]*mock|isDemoMode|VITE_DATA_MODE|dataMode)/;
  for (const file of runtimeSources(fileURLToPath(sourceRoot))) {
    assert.doesNotMatch(fs.readFileSync(file, 'utf8'), forbidden, file);
  }
});
