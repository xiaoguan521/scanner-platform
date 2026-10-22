// Run from repository root: node web/src/search-hints.test.mjs
// Search placeholders must describe what the Server actually searches.
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const read = path => readFile(new URL(path, import.meta.url), 'utf8');
const cases = [
  { page: './pages/Findings/index.tsx', hint: '按目标、软件包、CVE 或标题筛选', server: '../../internal/repo/finding_pagination.go', fields: ["'$.target'", "'$.package'", "'$.templateOrCve'", "'$.title'"] },
  { page: './pages/Assets/index.tsx', hint: '搜索地址、名称、业务组或负责人', server: '../../internal/assets/pagination.go', fields: ['assets.address LIKE', 'assets.business_group LIKE', 'assets.owner LIKE', "'$.name'"] },
  { page: './pages/Tasks/index.tsx', hint: '搜索任务 ID、目标或输入路径', server: '../../internal/repo/runtime_pagination.go', fields: ['id LIKE', 'targets LIKE', "'$.input.inputPath'"] },
  { page: './pages/Nodes/index.tsx', hint: '搜索节点 ID、类型或主机 ID', server: '../../internal/repo/system_pagination.go', fields: ['id LIKE', "'$.kind'", "'$.hostId'"] },
  { page: './pages/Nodes/index.tsx', hint: '搜索记录 ID、类型、版本或说明', server: '../../internal/repo/rule_catalog_pagination.go', fields: ['id LIKE', "'$.kind'", "'$.version'", "'$.message'"] },
  { page: './pages/Reports/index.tsx', hint: '搜索报告 ID、名称、创建人或快照', server: '../../internal/repo/report_pagination.go', fields: ['id LIKE', "'$.name'", "'$.createdBy'", "'$.snapshotId'"] },
];
for (const item of cases) {
  assert.ok((await read(item.page)).includes(`placeholder="${item.hint}"`), `${item.page} must use placeholder ${item.hint}`);
  const server = await read(item.server);
  for (const field of item.fields) assert.ok(server.includes(field), `${item.server} no longer searches ${field}; update the hint "${item.hint}"`);
}
assert.ok(!(await read('./pages/Findings/index.tsx')).includes('服务器别名'), 'findings search does not cover server aliases');
console.log('search hint contracts passed');
