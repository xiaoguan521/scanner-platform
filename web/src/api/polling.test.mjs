// Run from repository root: node web/src/api/polling.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';

const source = await readFile(new URL('./polling.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { pollWhileVisible, pollIntervals } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);

function fakeEnv() {
  const listeners = new Set();
  const timers = new Map();
  let next = 1;
  return {
    document: { hidden: false, addEventListener: (_type, fn) => listeners.add(fn), removeEventListener: (_type, fn) => listeners.delete(fn) },
    setInterval: (fn, ms) => { timers.set(next, { fn, ms }); return next++; },
    clearInterval: id => timers.delete(id),
    tick() { for (const timer of timers.values()) timer.fn(); },
    fireVisibility(hidden) { this.document.hidden = hidden; for (const fn of listeners) fn(); },
    listeners, timers,
  };
}

const env = fakeEnv();
let calls = 0;
const stop = pollWhileVisible(() => { calls++; }, 3000, env);
assert.equal(calls, 0, 'the caller owns the initial load');
assert.equal([...env.timers.values()][0].ms, 3000);
env.tick();
assert.equal(calls, 1);
env.document.hidden = true;
env.tick();
assert.equal(calls, 1, 'hidden pages must not poll');
env.fireVisibility(true);
assert.equal(calls, 1, 'becoming hidden must not load');
env.fireVisibility(false);
assert.equal(calls, 2, 'becoming visible refreshes immediately');
stop();
assert.equal(env.timers.size, 0);
assert.equal(env.listeners.size, 0);
env.fireVisibility(false);
assert.equal(calls, 2, 'stopped polling must not load');

const noDocument = fakeEnv();
delete noDocument.document;
let headless = 0;
pollWhileVisible(() => { headless++; }, 1000, noDocument);
noDocument.tick();
assert.equal(headless, 1, 'without a document the poller still runs');

for (const [name, ms] of Object.entries(pollIntervals)) assert.ok(ms >= 3000, `${name} must not poll faster than 3s`);
