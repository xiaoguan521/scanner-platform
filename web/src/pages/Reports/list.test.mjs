import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [page, client] = await Promise.all([
  readFile(new URL('./index.tsx', import.meta.url), 'utf8'),
  readFile(new URL('../../api/client.ts', import.meta.url), 'utf8'),
]);
const errors = await readFile(new URL('../../api/errors.ts', import.meta.url), 'utf8');

assert.match(client, /reportsPage<T>\(page:number,pageSize:number/);
assert.match(client, /page_size:String\(pageSize\)/);
assert.match(errors, /invalid_report_list_query/);
assert.match(page, /apiClient\.reportsPage<ReportJob>\(reportPage, reportPageSize/);
assert.match(page, /aria-label="报告历史搜索"/);
assert.match(page, /aria-label="报告状态筛选"/);
assert.match(page, /aria-label="报告格式筛选"/);
assert.match(page, /current: reportPage/);
assert.match(page, /total: reportTotal/);
assert.match(page, /loading=\{reportLoading\}/);
console.log('report history pagination source contracts passed');
