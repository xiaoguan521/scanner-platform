import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const [page, client] = await Promise.all([
  readFile(new URL('./index.tsx', import.meta.url), 'utf8'),
  readFile(new URL('../../api/client.ts', import.meta.url), 'utf8'),
]);

assert.match(client, /nodesPage<T>\(page:number,pageSize:number/);
assert.match(client, /rulesPage<T>\(page:number,pageSize:number/);
assert.match(client, /invalid_node_list_query/);
assert.match(client, /invalid_rule_list_query/);
assert.match(page, /apiClient\.nodesPage<NodeInfo>\(nodePage,nodePageSize/);
assert.match(page, /apiClient\.rulesPage<RuleBundle>\(rulePage,rulePageSize/);
assert.match(page, /aria-label="节点搜索"/);
assert.match(page, /aria-label="规则包搜索"/);
assert.match(page, /total:nodeTotal/);
assert.match(page, /total:ruleTotal/);
assert.match(page, /loading=\{systemLoading\}/);
console.log('node and rule list pagination source contracts passed');
