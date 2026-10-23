// Run from repository root: node web/src/utils/time.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./time.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { formatTime, formatDate, setDisplayTimeZone, getDisplayTimeZone } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

const instant = '2026-10-22T16:30:05Z';
setDisplayTimeZone('Asia/Shanghai');
assert.equal(formatTime(instant), '2026/10/23 00:30:05', 'shown in the platform zone, not the browser zone');
assert.equal(formatDate(instant), '2026/10/23');
assert.equal(formatTime(instant, '—', { seconds: false }), '2026/10/23 00:30');
setDisplayTimeZone('UTC');
assert.equal(formatTime(instant), '2026/10/22 16:30:05');
assert.equal(formatDate(instant), '2026/10/22');

// Empty or invalid values never render "Invalid Date".
assert.equal(formatTime(undefined), '—');
assert.equal(formatTime(''), '—');
assert.equal(formatTime('not a time', '未知'), '未知');
assert.equal(formatDate(null, '未提供'), '未提供');

// An unknown zone falls back to the browser zone instead of throwing.
setDisplayTimeZone('Mars/Olympus');
assert.equal(getDisplayTimeZone(), undefined);
assert.match(formatTime(instant), /^2026\/10\/2[23] \d{2}:30:05$/);

console.log('time formatting tests passed');
