// Run from repository root: node web/src/ui-guards.test.mjs
import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import { join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('.', import.meta.url));
async function sources(dir) {
  const out = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...await sources(path));
    else if (/\.(ts|tsx)$/.test(entry.name)) out.push(path);
  }
  return out;
}

const files = await sources(root);
const colorViolations = [];
const pollingViolations = [];
const devTextViolations = [];
// Development-stage and storage-implementation wording must not reach operators.
const devText = /SQLite|Phase 0|PoC|早期开发|本地开发|本地框架|本地验证|尚未可用/;
for (const file of files) {
  const name = relative(root, file);
  const lines = (await readFile(file, 'utf8')).split('\n');
  lines.forEach((line, index) => {
    // Page colors must come from antd theme tokens so both themes stay readable.
    // ThemeContext defines the palette; explicit light/dark pairs are allowed.
    if (name !== join('context', 'ThemeContext.tsx') && /#[0-9a-fA-F]{3}(?:[0-9a-fA-F]{3})?\b/.test(line) && !line.includes('isDark')) {
      colorViolations.push(`${name}:${index + 1}`);
    }
    if (devText.test(line)) devTextViolations.push(`${name}:${index + 1}`);
    if (name !== join('api', 'polling.ts') && /\bsetInterval\s*\(/.test(line)) pollingViolations.push(`${name}:${index + 1}`);
  });
}
assert.deepEqual(colorViolations, [], 'use theme.useToken() instead of hard-coded colors');
assert.deepEqual(pollingViolations, [], 'use pollWhileVisible so hidden pages stop polling');
assert.deepEqual(devTextViolations, [], 'remove development-stage wording from the UI');
