// Nodes, engines, rule bundles and custom rules.
export interface NodeInfo {
  id: string;
  kind: 'worker' | 'updater';
  hostId: string;
  ip: string;
  status: 'ONLINE' | 'OFFLINE' | 'BUSY' | 'UNKNOWN';
  currentTask?: string;
  boundRuleVersion?: string;
  lastHeartbeat: string;
  fenceStatus: 'ACTIVE' | 'NOT_SUPPORTED' | 'NOT_VERIFIED';
  dropCount: number;
  engines?: EngineStatus[];
  lifecycleStatus?: NodeLifecycleStatus;
  lifecycleRegisteredAt?: string;
  lifecycleRevokedAt?: string;
  lifecycleOfflineGeneration?: number;
}

export type NodeLifecycleStatus = 'REGISTERED' | 'ONLINE' | 'OFFLINE' | 'REVOKED';
export type NodeLifecycleEventKind = 'REGISTERED' | 'ONLINE' | 'OFFLINE' | 'RECOVERED' | 'REVOKED';
export interface NodeLifecycle {
  id: string;
  kind: 'worker' | 'updater';
  hostId: string;
  status: NodeLifecycleStatus;
  registeredAt: string;
  lastHeartbeat?: string;
  revokedAt?: string;
  offlineGeneration: number;
}
export interface NodeLifecycleEvent {
  id: string;
  nodeId: string;
  kind: NodeLifecycleEventKind;
  generation: number;
  createdAt: string;
}
export interface NodeCredential {
  id: string;
  kind: 'worker' | 'updater';
  hostId: string;
  serverUrl?: string;
  token: string;
}

export interface RuleBundle {
  version: string;
  channel: 'stable' | 'beta' | 'local';
  engines?: string[];
  integrityVerified?: boolean;
  signatureVerified?: boolean;
  engineValidated?: boolean;
  manifestSha256: string;
  publishedAt: string;
  isCurrent: boolean;
  isBackup: boolean;
  inUseByTasks: number;
}

export interface EngineStatus { name: string; version: string; installed: boolean; ready: boolean; message: string }

export interface RuleJob {
  id: string; kind: 'IMPORT'|'FETCH'|'ACTIVATE'; status: 'PENDING'|'RUNNING'|'COMPLETED'|'FAILED';
  version: string; message: string; createdAt: string; completedAt: string;
}


export interface CustomRule {
  id: string;
  name: string;
  severity: 'info'|'low'|'medium'|'high'|'critical';
  description: string;
  matchType: 'word'|'regex'|'status';
  part?: 'header'|'body';
  values?: string[];
  statusCodes?: number[];
  enabled: boolean;
  path?: string;
  template?: string;
}
