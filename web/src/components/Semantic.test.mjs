import assert from 'node:assert/strict';
import fs from 'node:fs';
import test from 'node:test';

const semantic = fs.readFileSync(new URL('./Semantic.tsx', import.meta.url), 'utf8');
const findings = fs.readFileSync(new URL('../pages/Findings/index.tsx', import.meta.url), 'utf8');
const dashboard = fs.readFileSync(new URL('../pages/Dashboard/index.tsx', import.meta.url), 'utf8');
const tasks = fs.readFileSync(new URL('../pages/Tasks/index.tsx', import.meta.url), 'utf8');

test('semantic components own the shared status vocabulary', () => {
  for (const token of ['severityMeta', 'findingStatusMeta', 'taskStatusMeta', 'SeverityTag', 'FindingStatusTag', 'TaskStatusTag', 'StatCard', 'LoadingSkeleton']) {
    assert.match(semantic, new RegExp(`\\b${token}\\b`), `missing shared semantic export: ${token}`);
  }
  for (const token of ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO', 'OPEN', 'REOPENED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE', 'ACCEPTED_RISK', 'PENDING', 'RUNNING', 'WAITING_WINDOW', 'PAUSED', 'PAUSED_WINDOW', 'COMPLETED', 'FAILED', 'CANCELED']) {
    assert.match(semantic, new RegExp(`\\b${token}\\b`), `missing status value: ${token}`);
  }
});

test('high traffic pages consume shared semantic tags', () => {
  assert.match(findings, /from ['"]\.\.\/\.\.\/components\/Semantic['"]/);
  assert.match(findings, /<SeverityTag\b/);
  assert.match(findings, /<FindingStatusTag\b/);
  assert.doesNotMatch(findings, /const getSeverityTag|const getStatusTag/);
  assert.match(dashboard, /from ['"]\.\.\/\.\.\/components\/Semantic['"]/);
  assert.match(dashboard, /<SeverityTag\b/);
  assert.match(dashboard, /<FindingStatusTag\b/);
  assert.match(dashboard, /<TaskStatusTag\b/);
  assert.match(tasks, /from ['"]\.\.\/\.\.\/components\/Semantic['"]/);
  assert.match(tasks, /<TaskStatusTag\b/);
  assert.match(tasks, /<ScheduleStatusTag\b/);
  assert.doesNotMatch(tasks, /const names:Record<string,string>/);
});
