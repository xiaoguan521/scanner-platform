import type { Asset, AuthorizedScope, Finding, NodeInfo, PortQuarantine, RuleBundle, ScanTask, User } from '../types';

// The default is always an explicitly labelled demo. "server" never silently
// falls back to synthetic findings or scan status when its API is unavailable.
export const dataMode: 'demo' | 'server' = import.meta.env.VITE_DATA_MODE === 'server' ? 'server' : 'demo';
export const isDemoMode = dataMode === 'demo';

export interface SystemStatus {
  role: 'sec-server' | 'sec-portable';
  phase: string;
  state: 'SCAFFOLD';
  ready: boolean;
  enabled: string[];
  unavailable: string[];
}

export interface Capabilities {
  enabled: string[];
  unavailable: string[];
}

export interface ApiErrorBody {
  error: string;
  message: string;
}

export interface ListResponse<T> {
  items: T[];
  total: number;
}

export interface Resources {
  users: User;
  assets: Asset;
  'port-quarantines': PortQuarantine;
  scopes: AuthorizedScope;
  tasks: ScanTask;
  findings: Finding;
  nodes: NodeInfo;
  rules: RuleBundle;
}

export class ApiRequestError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

async function getJSON<T>(path: string, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method: 'GET',
    headers: { Accept: 'application/json' },
    credentials: 'same-origin',
    signal,
    cache: 'no-store',
  });
  if (!response.ok) {
    let description = response.statusText || 'Request failed';
    try {
      const body: ApiErrorBody = await response.json();
      if (typeof body.message === 'string') description = body.message;
    } catch { /* HTML/empty error responses do not change the failure mode. */ }
    throw new ApiRequestError(response.status, description);
  }
  return response.json() as Promise<T>;
}

export const apiClient = {
  systemStatus(signal?: AbortSignal) {
    return getJSON<SystemStatus>('/api/v1/system/status', signal);
  },
  capabilities(signal?: AbortSignal) {
    return getJSON<Capabilities>('/api/v1/system/capabilities', signal);
  },
  collection<K extends keyof Resources>(name: K, signal?: AbortSignal) {
    return getJSON<ListResponse<Resources[K]>>('/api/v1/' + name, signal);
  },
};

// Mutations intentionally have NO API client methods in Phase 0. Server must
// own approval, authenticated auditing, FIXED and CURRENT decisions.
