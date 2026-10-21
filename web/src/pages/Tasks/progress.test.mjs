// Run from repository root: node web/src/pages/Tasks/progress.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./progress.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { progressBands, progressPercent, progressPhases } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

assert.equal(progressPhases.application_scan, '应用依赖分析');
assert.deepEqual(progressBands.tcp_probe, [0, 55]);
assert.equal(progressPercent({ phase: 'tcp_probe', completed: 0, total: 100 }), 0);
assert.equal(progressPercent({ phase: 'tcp_probe', completed: 100, total: 100 }), 55);
assert.equal(progressPercent({ phase: 'application_scan', completed: 1, total: 2 }), 97);
assert.equal(progressPercent({ phase: 'http_scan', completed: 0, total: 0 }), 65);
assert.equal(progressPercent({ phase: 'unknown', completed: 10, total: 1 }), 100);
console.log('Task progress presentation: all checks passed');
