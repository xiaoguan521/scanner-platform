// Run from repository root: node web/src/api/query.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

// query.ts imports React and the polling/errors modules; only startQuery is
// exercised here, so those imports are replaced with small stand-ins.
const source = (await readFile(new URL('./query.ts', import.meta.url), 'utf8'))
  .replace(/^import .*$/gm, '')
  .replace(/^export function use[\s\S]*$/m, '');
const prelude = `
const errorMessage = (cause, fallback) => cause instanceof Error && cause.message ? cause.message : fallback;
const pollWhileVisible = () => () => {};
`;
const js = ts.transpileModule(prelude + source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { startQuery } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

const tick = () => new Promise(resolve => setTimeout(resolve, 0));
function deferred() { let resolve, reject; const promise = new Promise((res, rej) => { resolve = res; reject = rej; }); return { promise, resolve, reject }; }

// Polls never overlap a request that is still running, and loading settles once.
{
  const pending = [];
  let poll;
  const events = [];
  const stop = startQuery({
    fetch: () => { const d = deferred(); pending.push(d); return d.promise; },
    onData: value => events.push(['data', value]),
    onError: message => events.push(['error', message]),
    onSettled: () => events.push(['settled']),
    errorFallback: '加载失败',
    pollMs: 1000,
    poll: load => { poll = load; return () => events.push(['stopped']); },
  });
  assert.equal(pending.length, 1);
  poll();
  assert.equal(pending.length, 1, 'a poll while the first request runs is skipped');
  pending[0].resolve('first');
  await tick();
  poll();
  assert.equal(pending.length, 2);
  pending[1].reject(new Error('Server 返回 500'));
  await tick();
  assert.deepEqual(events, [['data', 'first'], ['settled'], ['error', 'Server 返回 500']]);
  stop();
  assert.deepEqual(events.at(-1), ['stopped']);
}

// Nothing is reported after stop(), and the request is aborted.
{
  const d = deferred();
  let signal;
  const events = [];
  const stop = startQuery({
    fetch: s => { signal = s; return d.promise; },
    onData: () => events.push('data'),
    onError: () => events.push('error'),
    onSettled: () => events.push('settled'),
    errorFallback: '加载失败',
  });
  stop();
  assert.equal(signal.aborted, true);
  d.resolve('late');
  await tick();
  assert.deepEqual(events, []);
}

// Non-Error rejections fall back to the given message.
{
  const messages = [];
  startQuery({ fetch: () => Promise.reject('x'.repeat(0)), onData: () => {}, onError: m => messages.push(m), onSettled: () => {}, errorFallback: '任务加载失败' });
  await tick();
  assert.deepEqual(messages, ['任务加载失败']);
}

console.log('query loader tests passed');
