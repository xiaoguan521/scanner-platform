// Run from repository root: node web/src/pages/Tasks/targets.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./targets.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { taskTargetSummary } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

assert.deepEqual(taskTargetSummary({ engines: ['auto'], targetCount: 1, portProbePorts: [22, 80], chunks: [{ targets: ['192.0.2.10'] }] }),
  { primary: '192.0.2.10', detail: '1 台主机 / 2 端口' });
assert.deepEqual(taskTargetSummary({ engines: ['nuclei'], targetCount: 3, skippedTargets: ['192.0.2.12:8080'], chunks: [{ targets: ['192.0.2.10:80', '192.0.2.11:443'] }, { targets: ['192.0.2.10:80'] }] }),
  { primary: '192.0.2.10:80 等 2 个', detail: '3 个目标，跳过 1' });
assert.deepEqual(taskTargetSummary({ engines: ['trivy'], targetCount: 0, inputPath: 'lab-a/os', chunks: [] }),
  { primary: 'lab-a/os', detail: '离线输入' });
assert.deepEqual(taskTargetSummary({ engines: ['synthetic'], targetCount: 0 }),
  { primary: '—', detail: '0 个目标' });
console.log('task target summary: all checks passed');
