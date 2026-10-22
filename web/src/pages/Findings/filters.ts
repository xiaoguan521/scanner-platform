// These values are shareable classification filters. Free-text target searches stay local.
const filterValues = {
  severity: ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'],
  status: ['ALL', 'OPEN', 'REOPENED', 'IN_PROGRESS', 'FIXED', 'FALSE_POSITIVE', 'ACCEPTED_RISK'],
  method: ['ALL', 'principle', 'version', 'configuration', 'unknown'],
  confidence: ['ALL', 'high', 'medium', 'low', 'unknown'],
  risk: ['ALL', 'system', 'web', 'weak_credential', 'login_entry', 'unknown'],
  engine: ['ALL', 'trivy', 'nuclei', 'zap'],
} as const;

// View and sort are presentation state; the first value is the default and is
// left out of the URL.
const presentationValues = {
  view: ['flat', 'cve', 'package'],
  sort: ['-severity', 'severity', '-last_seen', 'last_seen', 'target', '-target', 'title', '-title'],
} as const;

type ClassificationKey = keyof typeof filterValues;
type PresentationKey = keyof typeof presentationValues;
export type FindingView = (typeof presentationValues)['view'][number];
export type FindingSort = (typeof presentationValues)['sort'][number];
export type FindingFilters = { [K in ClassificationKey]: (typeof filterValues)[K][number] }
  & { [K in PresentationKey]: (typeof presentationValues)[K][number] }
  & { onlyVerified: boolean; fixable: boolean; businessGroup: string; assetId: string; cve: string; package: string; taskId: string };

const textKeys = ['businessGroup', 'assetId', 'cve', 'package', 'taskId'] as const;
const flagKeys = ['onlyVerified', 'fixable'] as const;

export function readFindingFilters(params: URLSearchParams): FindingFilters {
  const pick = (key: string, allowed: readonly string[], fallback: string) => {
    const values = params.getAll(key);
    return values.length === 1 && allowed.includes(values[0]) ? values[0] : fallback;
  };
  const classification = Object.fromEntries(Object.entries(filterValues).map(([key, allowed]) => [key, pick(key, allowed, 'ALL')]));
  const presentation = Object.fromEntries(Object.entries(presentationValues).map(([key, allowed]) => [key, pick(key, allowed, allowed[0])]));
  const readText = (values: string[]) => values.length === 1 && values[0].trim().length <= 160 ? values[0].trim() : '';
  const text = Object.fromEntries(textKeys.map(key => [key, readText(params.getAll(key))]));
  const flags = Object.fromEntries(flagKeys.map(key => {
    const values = params.getAll(key);
    return [key, values.length === 1 && values[0] === 'true'];
  }));
  return { ...classification, ...presentation, ...text, ...flags } as FindingFilters;
}

// Preserve route parameters owned by other features, but never persist free text.
// Rewriting emits one canonical value per owned key.
export function writeFindingFilters(params: URLSearchParams, filters: FindingFilters): URLSearchParams {
  const next = new URLSearchParams(params);
  for (const key of Object.keys(filterValues) as ClassificationKey[]) {
    next.delete(key);
    if ((filterValues[key] as readonly string[]).includes(filters[key]) && filters[key] !== 'ALL') next.set(key, filters[key]);
  }
  for (const key of Object.keys(presentationValues) as PresentationKey[]) {
    const allowed = presentationValues[key] as readonly string[];
    next.delete(key);
    if (allowed.includes(filters[key]) && filters[key] !== allowed[0]) next.set(key, filters[key]);
  }
  for (const key of flagKeys) {
    next.delete(key);
    if (filters[key] === true) next.set(key, 'true');
  }
  for (const key of textKeys) {
    next.delete(key);
    const value = filters[key].trim();
    if (value && value.length <= 160) next.set(key, value);
  }
  next.delete('q');
  return next;
}

/** True when any server-side filter is narrower than the defaults. */
export function hasActiveFilters(filters: FindingFilters): boolean {
  return (Object.keys(filterValues) as ClassificationKey[]).some(key => filters[key] !== 'ALL')
    || flagKeys.some(key => filters[key]) || textKeys.some(key => filters[key] !== '');
}
