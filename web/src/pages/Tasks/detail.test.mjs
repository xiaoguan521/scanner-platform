// Run from repository root: node web/src/pages/Tasks/detail.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const runtime = await readFile(new URL('../../api/runtime.ts', import.meta.url), 'utf8');
const index = await readFile(new URL('./index.tsx', import.meta.url), 'utf8');
const detail = await readFile(new URL('./TaskDetail.tsx', import.meta.url), 'utf8');
const page = index + detail;

assert.match(runtime, /fetchTask\s*=.*\/tasks\/.*GET/);
assert.match(runtime, /fetchTaskLogs\s*=.*\/logs/);
assert.match(runtime, /exportTask\s*=.*\/export\?format=/);
assert.match(runtime, /pauseTask\s*=.*\/pause/);
assert.match(runtime, /resumeTask\s*=.*\/resume/);
assert.doesNotMatch(runtime.match(/exportTask[\s\S]*?(?=\nexport const saveSchedule)/)?.[0] ?? '', /fetch\(/, 'task API helpers must use the shared request client');
assert.match(page, /任务详情/);
assert.match(page, /只读任务日志/);
assert.match(page, /导出 JSON 结果/);
assert.match(page, /导出 CSV 结果/);
assert.match(page, /暂停任务/);
assert.match(page, /恢复任务/);
assert.match(page, /不显示原始引擎输出、凭据或请求响应/);
assert.match(index, /<TaskDetail\b/);
assert.match(index, /pollWhileVisible\(load,pollIntervals\.activeTask\)/, 'running tasks refresh while the detail is open');
assert.match(index, /detailTerminal\?undefined:/, 'finished tasks are not polled');
assert.match(detail, /\/findings\?taskId=/);
assert.match(detail, /扫描结果/);
assert.match(detail, /开放端口/);
console.log('Task detail drawer and export contracts passed');
