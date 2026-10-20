import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./filters.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { buildAuditQuery, defaultAuditFilters } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
assert.equal(buildAuditQuery(defaultAuditFilters), '?limit=50&offset=0');
const query = buildAuditQuery({ actor: ' alice ', action: 'create_asset', objectType: 'asset', from: '2026-10-20T00:00:00.000Z', to: '', page: 3 }, 25);
assert.deepEqual([...new URLSearchParams(query)], [['actor', 'alice'], ['action', 'create_asset'], ['objectType', 'asset'], ['from', '2026-10-20T00:00:00.000Z'], ['limit', '25'], ['offset', '50']]);
console.log('audit filter query checks passed');
