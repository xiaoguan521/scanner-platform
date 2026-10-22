// Run from repository root: node web/src/pages/Tasks/phases.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

// Bundle the three small modules into one data URL so relative imports resolve.
const load = async name => ts.transpileModule(await readFile(new URL(name, import.meta.url), 'utf8'), { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const strip = code => code.replace(/^import[^;]*;\n/gm, '').replace(/^export /gm, '');
const source = [await load('./progress.ts'), await load('./coverage.ts'), await load('./phases.ts')].map(strip).join('\n') + '\nexport { taskPhases, systemCoverage, applicationCoverage, isTerminalTask };';
const { taskPhases, systemCoverage, applicationCoverage, isTerminalTask } = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);

const states = task => taskPhases(task).map(phase => phase.state);
const base = { engines: ['auto'], portProbePorts: [22, 80, 443], portProbeResults: [{ port: 22 }, { port: 80 }], serviceResults: [{ port: 80, kind: 'HTTP' }], findingCount: 0 };

assert.deepEqual(taskPhases({ ...base, engines: ['trivy'], status: 'COMPLETED' }), [], 'only automatic scans have phases');
assert.deepEqual(states({ ...base, status: 'COMPLETED', systemScanCode: 'completed', systemScanStatus: '已通过', applicationScanStatus: 'not_configured' }),
  ['done', 'done', 'done', 'done', 'done', 'skipped']);
assert.deepEqual(states({ ...base, status: 'RUNNING', progress: { phase: 'http_scan', completed: 1, total: 2 } }),
  ['done', 'done', 'running', 'pending', 'pending', 'pending']);
assert.equal(taskPhases({ ...base, status: 'RUNNING', progress: { phase: 'http_scan', completed: 1, total: 2 } })[2].detail, '1 / 2');
assert.deepEqual(states({ ...base, status: 'FAILED', progress: { phase: 'ssh_collection', completed: 0, total: 1 }, systemScanCode: 'auth_failed', systemScanStatus: '未采集：SSH 公钥认证失败' }),
  ['done', 'done', 'done', 'failed', 'failed', 'pending']);
assert.deepEqual(states({ ...base, status: 'COMPLETED', systemScanCode: 'port_out_of_scope', systemScanStatus: '未采集：配置的 SSH 端口不在本次明确范围内', applicationScanStatus: 'completed' }),
  ['done', 'done', 'done', 'skipped', 'skipped', 'done']);
assert.equal(taskPhases({ ...base, status: 'COMPLETED' })[0].detail, '2 / 3 个端口开放');
assert.equal(taskPhases({ ...base, status: 'RUNNING', progress: { phase: 'http_scan', completed: 1, total: 2 } })[4].detail, '等待执行');

assert.equal(systemCoverage('已通过 SSH 临时采集并完成本地系统包检查').tone, 'ok', 'sentence fallback for older Servers');
assert.equal(systemCoverage('未完成：Trivy 系统包分析失败').tone, 'error');
assert.equal(systemCoverage('未采集：SSH 端口未探测为开放').label, 'SSH 端口未探测为开放');
assert.equal(systemCoverage('任意文字', 'auth_failed').label, 'SSH 认证失败', 'code wins over sentence');
assert.ok(systemCoverage(undefined, 'not_configured').hint);
assert.equal(systemCoverage().tone, 'neutral');
assert.equal(applicationCoverage('analysis_failed').tone, 'error');
assert.ok(applicationCoverage('not_configured').hint);
assert.equal(isTerminalTask('RUNNING'), false);
assert.equal(isTerminalTask('CANCELED'), true);
console.log('task phases and coverage: all checks passed');
