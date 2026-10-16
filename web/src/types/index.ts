// UI response types mirror docs/api/openapi.yaml (HTTP DTOs, not repo schemas).
// API date-time fields are RFC 3339 with timezone offsets.
export type UserRole = 'admin' | 'security_engineer' | 'ops_approver' | 'viewer';

export interface User {
  id: string;
  username: string;
  role: UserRole;
  isActive: boolean;
}

export type PortKind = 'WEB' | 'NON_WEB' | 'EXCLUDED_PROXY';

export interface AssetPort {
  port: number;
  kind: PortKind;
  source: string;
}

export interface PortQuarantine {
  assetId: string;
  address: string;
  port: number;
  reason: string;
  detectedAt: string;
  status: 'ACTIVE' | 'RELEASED';
  reviewedBy?: string;
  reviewedAt?: string;
}

export interface Asset {
  id: string;
  kind: 'host' | 'image_repo';
  address: string;
  resolvedIp?: string;
  businessGroup: string;
  owner: string;
  createdAt: string;
  ports: AssetPort[];
  quarantinedPorts?: number[];
}

export interface TimeWindow {
  weekdays: number[]; // 0=Sunday, 1=Monday...
  start: string; // HH:MM
  end: string; // HH:MM
  timeZone: string;
}

export interface AuthorizedScope {
  id: string;
  cidrOrHost: string;
  maxTargets: number;
  timeWindows: TimeWindow[];
  approvedBy: string;
  approvalTicket: string;
  expiresAt: string;
  isActive: boolean;
}

export type TaskStatus =
  | 'PENDING'
  | 'WAITING_WINDOW'
  | 'RUNNING'
  | 'PAUSED_WINDOW'
  | 'COMPLETED'
  | 'FAILED'
  | 'CANCELED';

export interface TaskChunk {
  id: string;
  taskId: string;
  workerNodeId?: string;
  pinnedRuleVersion?: string;
  leaseExpiresAt?: string;
  completedFully?: boolean;
  targets: string[];
  status: TaskStatus;
  startedAt?: string;
  finishedAt?: string;
}

export interface ScanTask {
  id: string;
  scopeId: string;
  scopeName: string;
  engines: ('nuclei' | 'trivy')[];
  status: TaskStatus;
  hardDeadline: string;
  totalChunks: number;
  completedChunks: number;
  targetCount: number;
  createdAt: string;
  chunks: TaskChunk[];
}

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus =
  | 'OPEN'
  | 'REOPENED'
  | 'IN_PROGRESS'
  | 'FIXED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK';

export interface Finding {
  id: string;
  fingerprint: string;
  severity: FindingSeverity;
  title: string;
  engine: 'nuclei' | 'trivy';
  templateOrCve: string;
  target: string;
  port?: number;
  status: FindingStatus;
  firstSeen: string;
  lastSeen: string;
  consecutiveMisses: number;
  businessGroup: string;
  owner: string;
  verifiedInRun: boolean;
}

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
}

export interface RuleBundle {
  version: string;
  channel: 'stable' | 'beta';
  manifestSha256: string;
  publishedAt: string;
  isCurrent: boolean;
  isBackup: boolean;
  inUseByTasks: number;
}
