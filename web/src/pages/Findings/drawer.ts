import type { Finding } from '../../types';

// Return complete text; React handles escaping at the render boundary.
export function detailText(value: string | number | boolean | null | undefined): string {
  if (value === null || value === undefined || (typeof value === 'string' && !value.trim())) return '未提供';
  return String(value);
}

export function detailList(values?: string[]): string {
  return detailText(values?.map(value => detailText(value)).join('\n'));
}

export function detailIdentifiers(values?: Record<string, string[]>): string {
  return detailText(Object.entries(values ?? {}).map(([key, ids]) => `${key}: ${detailList(ids)}`).join('\n'));
}

// Only an ID is stored in component state. Refreshes and PATCH responses supply
// the latest object; a filtered out or removed finding has no open drawer.
export function selectedFindingForDrawer(findings: Finding[], visibleFindings: Finding[], id: string | null): Finding | undefined {
  if (!id || !visibleFindings.some(finding => finding.id === id)) return undefined;
  return findings.find(finding => finding.id === id);
}
