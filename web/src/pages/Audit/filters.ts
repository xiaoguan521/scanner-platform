export interface AuditFilters {
  actor: string;
  action: string;
  objectType: string;
  from: string;
  to: string;
  page: number;
}

export const defaultAuditFilters: AuditFilters = { actor: '', action: '', objectType: '', from: '', to: '', page: 1 };

export function buildAuditQuery(filters: AuditFilters, pageSize = 50): string {
  const params = new URLSearchParams();
  for (const [key, value] of [['actor', filters.actor], ['action', filters.action], ['objectType', filters.objectType], ['from', filters.from], ['to', filters.to]] as const) {
    const trimmed = value.trim();
    if (trimmed) params.set(key, trimmed);
  }
  params.set('limit', String(pageSize));
  params.set('offset', String(Math.max(0, filters.page - 1) * pageSize));
  return `?${params.toString()}`;
}
