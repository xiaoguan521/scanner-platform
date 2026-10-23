import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [page, client] = await Promise.all([
  readFile(new URL('./index.tsx', import.meta.url), 'utf8'),
  readFile(new URL('../../api/client.ts', import.meta.url), 'utf8'),
]);
const errors = await readFile(new URL('../../api/errors.ts', import.meta.url), 'utf8');

assert.match(client, /nodesPage<T>\(page:number,pageSize:number/);
assert.match(client, /registerNode\(input:Pick<NodeLifecycle/);
assert.match(client, /issueNodeCredential\(id:string\)/);
assert.match(client, /rotateNodeCredential\(id:string\)/);
assert.match(client, /nodeLifecycleEvents\(id:string/);
assert.match(client, /rulesPage<T>\(page:number,pageSize:number/);
assert.match(client, /ruleJobsPage<T>\(page:number,pageSize:number/);
assert.match(client, /customRulesPage<T>\(page:number,pageSize:number/);
assert.match(errors, /invalid_node_list_query/);
assert.match(errors, /invalid_rule_list_query/);
assert.match(page, /apiClient\.nodesPage<NodeInfo>\(nodePage,nodePageSize/);
assert.match(page, /登记节点/);
assert.match(page, /showNodeLifecycle/);
assert.match(page, /confirmNodeRevoke/);
assert.match(page, /签发令牌/);
assert.match(page, /轮换令牌/);
assert.match(page, /令牌只显示这一次/);
assert.match(page, /apiClient\.rulesPage<RuleBundle>\(rulePage,rulePageSize/);
assert.match(page, /apiClient\.ruleJobsPage<RuleJob>\(jobPage,jobPageSize/);
assert.match(page, /apiClient\.customRulesPage<CustomRule>\(customPage,customPageSize/);
assert.match(page, /aria-label="节点搜索"/);
assert.match(page, /aria-label="规则包搜索"/);
assert.match(page, /aria-label="规则操作记录搜索"/);
assert.match(page, /aria-label="自定义规则搜索"/);
assert.match(page, /total:nodeTotal/);
assert.match(page, /total:ruleTotal/);
assert.match(page, /loading=\{systemLoading\}/);
console.log('system catalog pagination source contracts passed');
