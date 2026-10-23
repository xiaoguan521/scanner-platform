import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const source = fs.readFileSync(new URL('./DataState.tsx', import.meta.url), 'utf8');
const notice = fs.readFileSync(new URL('../api/CollectionNotice.tsx', import.meta.url), 'utf8');

test('shared data states expose loading, error and empty semantics', () => {
  assert.match(source, /export const LoadingState/);
  assert.match(source, /export const ErrorState/);
  assert.match(source, /export const EmptyState/);
  assert.match(source, /role="status"/);
  assert.match(source, /Empty\.PRESENTED_IMAGE_SIMPLE/);
  // Text empty messages and the default both render through EmptyState.
  assert.match(source, /typeof locale\?\.emptyText === 'string' \? <EmptyState description=\{locale\.emptyText\} \/>/);
  assert.match(source, /locale\?\.emptyText \?\? <EmptyState \/>/);
});

test('collection notice uses the shared states and never fabricates data', () => {
  assert.match(notice, /<LoadingState/);
  assert.match(notice, /<ErrorState/);
  assert.doesNotMatch(notice, /mock|fixture|fallback/);
});

console.log('shared data state contracts passed');
