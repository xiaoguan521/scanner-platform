import type { Key } from 'react';
import type { Finding, FindingStatus } from '../../types';
export type FindingSelection = { id: string; expectedStatus: FindingStatus; expectedAssigneeId?: string };
export function batchTransitionAllowed(from: FindingStatus, to: FindingStatus): boolean {
  if (from === 'FIXED' || from === to || to === 'FIXED' || to === 'REOPENED') return false;
  if (from === 'ACCEPTED_RISK') return to === 'OPEN';
  if (to === 'ACCEPTED_RISK') return ['OPEN', 'REOPENED', 'IN_PROGRESS'].includes(from);
  return ['OPEN', 'IN_PROGRESS', 'FALSE_POSITIVE'].includes(to);
}
export function batchSelectionChanged(selection: FindingSelection[], findings: Finding[], ignoreMissing = false): boolean {
	return selection.some(item => {
		const current = findings.find(f => f.id === item.id);
		return current ? current.status !== item.expectedStatus : !ignoreMissing;
	});
}
export function batchAssignmentSelectionChanged(selection: FindingSelection[], findings: Finding[], ignoreMissing = false): boolean {
	return selection.some(item => {
		const current = findings.find(f => f.id === item.id);
		return current ? (current.assigneeId ?? '') !== (item.expectedAssigneeId ?? '') : !ignoreMissing;
	});
}
export function updateBatchSelection(previous: FindingSelection[], keys: Key[], findings: Finding[]): FindingSelection[] {
  const byId = new Map(previous.map(item => [item.id, item]));
  const current = new Map(findings.map(f => [f.id, f]));
  return keys.map(String).filter(id => byId.has(id) || current.has(id)).slice(0, 100).map(id => byId.get(id) ?? { id, expectedStatus: current.get(id)!.status, expectedAssigneeId: current.get(id)!.assigneeId ?? '' });
}
