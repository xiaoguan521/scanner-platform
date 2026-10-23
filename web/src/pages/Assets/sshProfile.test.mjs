// Run from repository root: node web/src/pages/Assets/sshProfile.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./sshProfile.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { buildSshConfig, validateSshConfig, canonicalIP, validLocalPath, validAppDirectory, keyscanCommands } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

const agent = { ip: '192.0.2.10', sshPort: 22, user: 'scanner_ro', auth: 'agent', apps: [{ alias: 'orders', directory: '/opt/example-orders', includeJava: true, includeGo: false }] };
const key = { ip: '192.0.2.11', sshPort: 2222, user: 'scanner_ro', auth: 'private-key', privateKeyFile: 'keys/scan_ed25519' };
const config = { knownHostsFile: 'known_hosts', targets: [agent, key] };

// The generated file matches the Worker schema and docs/ssh-collection.md.
assert.deepEqual(validateSshConfig(config), []);
assert.deepEqual(JSON.parse(buildSshConfig(config)), {
  knownHostsFile: 'known_hosts',
  targets: [
    { ip: '192.0.2.10', sshPort: 22, user: 'scanner_ro', auth: 'agent', apps: [{ alias: 'orders', directory: '/opt/example-orders', includeJava: true, includeGo: false }] },
    { ip: '192.0.2.11', sshPort: 2222, user: 'scanner_ro', auth: 'private-key', privateKeyFile: 'keys/scan_ed25519' },
  ],
});
// An agent profile never carries a key path, even if one was typed before switching.
assert.equal(JSON.parse(buildSshConfig({ knownHostsFile: 'known_hosts', targets: [{ ...agent, privateKeyFile: 'keys/old' }] })).targets[0].privateKeyFile, undefined);
// No password or key material field exists in the output.
assert.doesNotMatch(buildSshConfig(config), /password|passphrase|BEGIN .*PRIVATE KEY/i);

// Same rejections as the Worker.
assert.equal(canonicalIP('192.0.2.10'), true);
assert.equal(canonicalIP('192.000.2.10'), false, 'leading zeros are not canonical');
assert.equal(canonicalIP('example.test'), false);
assert.equal(canonicalIP('224.0.0.1'), false, 'multicast');
assert.equal(canonicalIP('0.0.0.0'), false);
assert.equal(canonicalIP('2001:db8::10'), true);
assert.equal(canonicalIP('2001:DB8::10'), false, 'IPv6 must be lowercase');
assert.equal(validLocalPath('keys/scan_ed25519'), true);
assert.equal(validLocalPath('/etc/secscan/known_hosts'), true);
assert.equal(validLocalPath('C:\\secscan\\known_hosts'), true);
assert.equal(validLocalPath('../keys/scan'), false, 'must stay under the config directory');
assert.equal(validLocalPath(''), false);
assert.equal(validAppDirectory('/srv/example-gateway'), true);
for (const bad of ['/opt', '/srv', '/var/lib', '/', '/tmp/app', '/proc/1', 'relative/app', '/opt/../etc', '/opt//app', '/opt/app/']) {
  assert.equal(validAppDirectory(bad), false, bad);
}

const problems = validateSshConfig({ knownHostsFile: '../known_hosts', targets: [
  { ip: '192.0.2.10', sshPort: 0, user: '1root', auth: 'private-key', privateKeyFile: '' },
  { ip: '192.0.2.10', sshPort: 22, user: 'ok', auth: 'agent', apps: [{ alias: '-x', directory: '/opt', includeJava: false, includeGo: false }] },
] });
for (const fragment of ['known_hosts', 'SSH 端口', '账号', '私钥文件', '同一 IP', '别名', 'Java 或 Go', '宽泛目录']) {
  assert.ok(problems.some(item => item.includes(fragment)), fragment);
}
assert.ok(validateSshConfig({ knownHostsFile: 'known_hosts', targets: [{ ...agent, apps: Array.from({ length: 9 }, (_, i) => ({ alias: `a${i}`, directory: `/srv/app${i}`, includeJava: true, includeGo: false })) }] }).some(item => item.includes('最多 8')));

assert.equal(keyscanCommands([agent, key]), 'ssh-keyscan -p 22 192.0.2.10\nssh-keyscan -p 2222 192.0.2.11');
// The generator stays in the browser: no upload path, no password or key-content input.
const modal = await readFile(new URL('./SshProfileModal.tsx', import.meta.url), 'utf8');
assert.doesNotMatch(modal, /apiClient\.(?!collection)|requestJSON|fetch\(|localStorage|sessionStorage/, 'SSH settings must not be sent or stored');
assert.doesNotMatch(modal, /Input\.Password|type="password"|TextArea/, 'no password or key-content field');
assert.match(modal, /不会上传到平台/);

// The Worker loads this exact file in internal/sshcollect/ui_config_test.go.
const fixture = await readFile(new URL('../../../../internal/sshcollect/testdata/ui-generated-ssh-config.json', import.meta.url), 'utf8');
assert.equal(buildSshConfig({ knownHostsFile: 'known_hosts', targets: [agent, { ...key, ip: '2001:db8::11' }] }), fixture);

console.log('SSH profile builder tests passed');
