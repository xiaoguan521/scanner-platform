// Run from repository root: node web/src/pages/Tasks/scanplans.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const runtime = await readFile(new URL('../../api/runtime.ts', import.meta.url), 'utf8');
const page = await readFile(new URL('./index.tsx', import.meta.url), 'utf8')
  + await readFile(new URL('./ScanPlanEditor.tsx', import.meta.url), 'utf8')
  + await readFile(new URL('./TaskCreateModal.tsx', import.meta.url), 'utf8');
const types = await readFile(new URL('../../types/task.ts', import.meta.url), 'utf8');

for (const name of ['createScanPlan', 'updateScanPlan', 'deleteScanPlan']) {
  assert.match(runtime, new RegExp(`${name}\\s*=`), `${name} must use the shared API client`);
}
assert.match(page, /复制为自定义扫描方案/);
assert.match(page, /编辑自定义扫描方案/);
assert.match(page, /删除自定义扫描方案/);
assert.match(page, /plan\.kind==='CUSTOM'/);
assert.match(page, /setScanPlans\(prev=>/);
assert.match(types, /kind: 'PRESET' \| 'CUSTOM'/);
assert.match(types, /portPreset: ScanPlanPortPreset/);
assert.match(types, /interface ScanPlanInput/);
console.log('scan plan persistence UI contracts passed');
