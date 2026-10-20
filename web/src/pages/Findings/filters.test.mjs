// Run from repository root: node web/src/pages/Findings/filters.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
const source = await readFile(new URL('./filters.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { readFindingFilters: read, writeFindingFilters: write } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const defaults = { severity: 'ALL', status: 'ALL', method: 'ALL', confidence: 'ALL', risk: 'ALL', onlyVerified: false, businessGroup: '', assetId: '' };
assert.deepEqual(read(new URLSearchParams()), defaults);
const allowed = {
  severity: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  status: ['OPEN', 'REOPENED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  method: ['principle', 'version', 'configuration', 'unknown'],
  confidence: ['high', 'medium', 'low', 'unknown'],
  risk: ['system', 'web', 'weak_credential', 'login_entry', 'unknown'],
};
for (const [key, values] of Object.entries(allowed)) {
  for (const value of values) {
    const expected = { ...defaults, [key]: value };
    assert.deepEqual(read(new URLSearchParams({ [key]: value })), expected, `${key}=${value}`);
    assert.deepEqual(read(write(new URLSearchParams(), expected)), expected, `round trip ${key}=${value}`);
  }
  for (const value of ['', 'all', 'unrecognized', '192.0.2.10', '<script>']) {
    const params = new URLSearchParams({ [key]: value });
    assert.deepEqual(read(params), defaults, `reject ${key}=${value}`);
    assert.equal(write(params, read(params)).toString(), '', 'invalid filters must be removed');
  }
  const duplicate = new URLSearchParams([[key, values[0]], [key, values[1]]]);
  assert.deepEqual(read(duplicate), defaults, 'duplicate filters are ambiguous');
  assert.equal(write(duplicate, read(duplicate)).toString(), '');
}
for (const value of ['', 'false', '1', 'TRUE', 'yes']) {
  const params = new URLSearchParams({ onlyVerified: value });
  assert.equal(read(params).onlyVerified, false);
  assert.equal(write(params, read(params)).toString(), '');
}
assert.equal(read(new URLSearchParams('onlyVerified=true')).onlyVerified, true);
assert.equal(read(new URLSearchParams('onlyVerified=true&onlyVerified=true')).onlyVerified, false);
const combined = { severity: 'HIGH', status: 'OPEN', method: 'version', confidence: 'high', risk: 'system', onlyVerified: true, businessGroup: '支付', assetId: 'asset-1' };
const params = new URLSearchParams('tab=review&tab=other&q=192.0.2.10&severity=ALL&status=bad');
const canonical = write(params, combined);
assert.deepEqual(read(canonical), combined, 'combined filters survive reload by parsing the same URL');
assert.deepEqual(canonical.getAll('tab'), ['review', 'other'], 'unrelated query keys and duplicates survive');
assert.equal(canonical.has('q'), false, 'free-text target search must not enter the canonical URL');
assert.equal(params.get('q'), '192.0.2.10', 'serializer must not mutate router input');
assert.equal(write(canonical, read(canonical)).toString(), canonical.toString(), 'canonicalization is idempotent');
assert.deepEqual(read(write(canonical, defaults)), defaults, 'reset removes every owned classification');
assert.equal(write(canonical, defaults).toString(), 'tab=review&tab=other');
assert.equal(read(new URLSearchParams('businessGroup=%E6%94%AF%E4%BB%98&assetId=asset-1')).businessGroup, '支付');
assert.equal(read(new URLSearchParams('businessGroup=x&businessGroup=y')).businessGroup, '');
// Back/forward locations are the only source of filter state; local searches are separate.
for (const location of ['severity=HIGH', 'status=FIXED&onlyVerified=true', 'severity=HIGH']) {
  const restored = read(new URLSearchParams(location));
  assert.equal(restored.severity, location.includes('severity') ? 'HIGH' : 'ALL');
  assert.equal(restored.status, location.includes('status') ? 'FIXED' : 'ALL');
}
console.log('Findings URL filters: all checks passed');
