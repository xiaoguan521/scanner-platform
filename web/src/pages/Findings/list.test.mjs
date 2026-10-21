import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';

const page = await readFile(new URL('./index.tsx', import.meta.url), 'utf8');
const client = await readFile(new URL('../../api/client.ts', import.meta.url), 'utf8');

assert.match(client, /findingsPage\(page:number,pageSize:number/);
assert.ok(client.includes("return requestJSON<FindingPageResponse<Finding>>('/api/v1/findings?'+params.toString()"));
assert.match(page, /apiClient\.findingsPage\(findingPage,findingPageSize/);
assert.match(page, /setFindingTotal\(result\.total\)/);
assert.match(page, /findingCountsSummary\.vulnerabilities/);
assert.match(page, /pagination=\{\{current:findingPage,pageSize:findingPageSize,total:findingTotal/);
assert.match(page, /showSizeChanger:true/);
assert.doesNotMatch(page, /useCollection\(['"]findings/);
assert.doesNotMatch(page, /filteredFindings\s*=\s*findings\.filter/);

console.log('Findings list: Server pagination contract passed');
