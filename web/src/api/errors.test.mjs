import assert from 'node:assert/strict';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';

const read = name => readFile(new URL(name, import.meta.url), 'utf8');
const [client, runtime, auth] = await Promise.all([read('./client.ts'), read('./runtime.ts'), read('../auth/AuthProvider.tsx')]);

// Every failed request goes through one error builder, so uploads also raise
// the session-expired event and show the mapped Chinese messages.
assert.equal((client.match(/throw await toApiError\(response/g) ?? []).length, 3, 'requestJSON, requestBlob and the CSV preview share toApiError');
assert.match(runtime, /importRules[\s\S]*throw await toApiError\(response/);
assert.doesNotMatch(client, /const messages:Record<string,string>/, 'error codes live in api/errors.ts');

// Pages show messages through errorMessage() and read role checks from useAuth().
async function* sources(dir) {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) yield* sources(full);
    else if (/\.tsx?$/.test(entry.name)) yield full;
  }
}
const pagesDir = new URL('../pages/', import.meta.url).pathname;
for await (const file of sources(pagesDir)) {
  const text = await readFile(file, 'utf8');
  assert.doesNotMatch(text, /message\.error\(String\(/, `${file} must use errorMessage()`);
  assert.doesNotMatch(text, /instanceof Error\s*\?/, `${file} must use errorMessage()`);
  assert.doesNotMatch(text, /role\s*===?\s*'(admin|security_engineer|ops_approver)'\s*\|\|/, `${file} must use the permissions from useAuth()`);
}
assert.match(auth, /canWrite: role === 'admin' \|\| role === 'security_engineer'/);
assert.match(auth, /canReview: role === 'admin' \|\| role === 'ops_approver'/);

console.log('api error handling contract passed');
