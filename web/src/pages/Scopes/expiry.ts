import type { AuthorizedScope } from '../../types';

export type ScopeExpiryFilter = 'all' | 'expiring' | 'expired';
export type ScopeExpiryState = 'NOT_APPLICABLE' | 'ACTIVE' | 'EXPIRING' | 'EXPIRED';

export function scopeExpiryState(scope: Pick<AuthorizedScope, 'status' | 'expiresAt' | 'expiryState'>, now = Date.now()): ScopeExpiryState {
  if (scope.status !== 'APPROVED') return 'NOT_APPLICABLE';
  const expires = Date.parse(scope.expiresAt);
  if (!Number.isFinite(expires) || expires <= now) return 'EXPIRED';
  return expires <= now + 7 * 24 * 60 * 60 * 1000 ? 'EXPIRING' : 'ACTIVE';
}

export const scopeExpiryLabel: Record<ScopeExpiryState, string> = {
  NOT_APPLICABLE: '不适用', ACTIVE: '有效', EXPIRING: '7 天内到期', EXPIRED: '已过期',
};

export function filterScopesByExpiry(scopes: AuthorizedScope[], filter: ScopeExpiryFilter, now = Date.now()) {
  if (filter === 'all') return scopes;
  const state = filter === 'expiring' ? 'EXPIRING' : 'EXPIRED';
  return scopes.filter(scope => scopeExpiryState(scope, now) === state);
}
