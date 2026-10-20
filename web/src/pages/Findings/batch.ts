import type { Key } from 'react';
import type { Finding, FindingStatus } from '../../types';
export type FindingSelection = { id: string; expectedStatus: FindingStatus };
export function batchTransitionAllowed(from: FindingStatus, to: FindingStatus): boolean {
  if (from === 'FIXED' || from === to || to === 'FIXED' || to === 'REOPENED') return false;
  if (from === 'ACCEPTED_RISK') return to === 'OPEN';
  if (to === 'ACCEPTED_RISK') return ['OPEN', 'REOPENED', 'IN_PROGRESS'].includes(from);
  return ['OPEN', 'IN_PROGRESS', 'FALSE_POSITIVE'].includes(to);
}
export function batchSelectionChanged(selection: FindingSelection[], findings: Finding[]): boolean {
  return selection.some(item => !findings.some(f => f.id === item.id && f.status === item.expectedStatus));
}
export function updateBatchSelection(previous: FindingSelection[], keys: Key[], findings: Finding[]): FindingSelection[] {
  const byId = new Map(previous.map(item => [item.id, item]));
  const current = new Map(findings.map(f => [f.id, f]));
  return keys.map(String).filter(id => byId.has(id) || current.has(id)).slice(0, 100).map(id => byId.get(id) ?? { id, expectedStatus: current.get(id)!.status });
}
