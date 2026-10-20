// These values are shareable classification filters. Free-text target searches stay local.
const filterValues = {
  severity: ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  status: ['ALL', 'OPEN', 'REOPENED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  method: ['ALL', 'principle', 'version', 'configuration', 'unknown'],
  confidence: ['ALL', 'high', 'medium', 'low', 'unknown'],
  risk: ['ALL', 'system', 'web', 'weak_credential', 'login_entry', 'unknown'],
} as const;

type ClassificationKey = keyof typeof filterValues;
export type FindingFilters = { [K in ClassificationKey]: (typeof filterValues)[K][number] } & { onlyVerified: boolean };

export function readFindingFilters(params: URLSearchParams): FindingFilters {
  const classification = Object.fromEntries(Object.entries(filterValues).map(([key, allowed]) => {
    const values = params.getAll(key);
    return [key, values.length === 1 && (allowed as readonly string[]).includes(values[0]) ? values[0] : 'ALL'];
  })) as Pick<FindingFilters, ClassificationKey>;
  const verified = params.getAll('onlyVerified');
  return { ...classification, onlyVerified: verified.length === 1 && verified[0] === 'true' };
}

// Preserve route parameters owned by other features, but never persist free text.
// Rewriting emits one canonical value per owned key.
export function writeFindingFilters(params: URLSearchParams, filters: FindingFilters): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const key of Object.keys(filterValues) as ClassificationKey[]) {
    next.delete(key);
    if ((filterValues[key] as readonly string[]).includes(filters[key]) && filters[key] !== 'ALL') next.set(key, filters[key]);
  }
  next.delete('onlyVerified');
  if (filters.onlyVerified === true) next.set('onlyVerified', 'true');
  next.delete('q');
  return next;
}
