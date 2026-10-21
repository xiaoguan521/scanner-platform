import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./expiry.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, {compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
const {scopeExpiryState, filterScopesByExpiry} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const now = Date.parse('2026-10-21T00:00:00Z');
const approved = (expiresAt) => ({status:'APPROVED', expiresAt});
assert.equal(scopeExpiryState(approved('2026-10-30T00:00:00Z'), now), 'ACTIVE');
assert.equal(scopeExpiryState(approved('2026-10-27T00:00:00Z'), now), 'EXPIRING');
assert.equal(scopeExpiryState(approved('2026-10-20T00:00:00Z'), now), 'EXPIRED');
assert.equal(scopeExpiryState({status:'PENDING', expiresAt:'2026-10-22T00:00:00Z'}, now), 'NOT_APPLICABLE');
const scopes = [approved('2026-10-27T00:00:00Z'), approved('2026-10-20T00:00:00Z'), approved('2026-10-30T00:00:00Z')];
assert.equal(filterScopesByExpiry(scopes, 'expiring', now).length, 1);
assert.equal(filterScopesByExpiry(scopes, 'expired', now).length, 1);
console.log('scope expiry checks passed');
