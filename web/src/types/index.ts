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
  requestedPorts?: number[]; // Registration request only; NOT an approved scan port
  quarantinedPorts?: number[];
  skippedPorts?: number[];
}

export interface TimeWindow {
  weekdays: number[]; // 0=Sunday, 1=Monday...
  start: string; // HH:MM
  end: string; // HH:MM
  timeZone: string;
}

export type ReviewDecision = 'APPROVE' | 'REJECT';
export type ReviewStatus = 'PENDING' | 'APPROVED' | 'REJECTED';
export interface ApprovalDecision {
  decision: ReviewDecision;
  approvalTicket: string;
  note: string;
  kind?: 'WEB' | 'NON_WEB'; // Required for approved port
}
export interface PortRequest {
  assetId: string;
  address: string;
  port: number;
  kind: string;
  requestedBy: string;
  status: ReviewStatus;
  reviewedBy: string;
  approvalTicket: string;
  reviewedAt: string;
  reviewNote: string;
}
export interface AuthorizedScope {
  id: string;
  assetId?: string;
  cidrOrHost: string;
  maxTargets: number;
  timeWindows: TimeWindow[];
  requestedBy?: string;
  approvedBy: string;
  approvalTicket: string;
  expiresAt: string;
  isActive: boolean;
  status?: ReviewStatus | 'REVOKED';
  reviewNote?: string;
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
  engines: ('nuclei' | 'trivy' | 'zap' | 'synthetic')[];
  status: TaskStatus;
  hardDeadline: string;
  totalChunks: number;
  completedChunks: number;
  targetCount: number;
  createdAt: string;
  chunks: TaskChunk[];
  synthetic?: boolean;
  skippedTargets?: string[];
  timeWindows?: TimeWindow[];
  ruleVersion?: string;
  scheme?: string; inputPath?: string; inputKind?: string; error?: string;
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
  engine: 'nuclei' | 'trivy' | 'zap' | 'synthetic';
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
  synthetic?: boolean;
  artifactId?: string; matchedPath?: string; package?: string; installedVersion?: string; fixedVersion?: string; description?: string;
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
  engines?: EngineStatus[];
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
export interface TaskInput { synthetic: boolean; engine?: 'nuclei'|'trivy'|'zap'|'synthetic'; scheme?: 'http'|'https'; inputPath?: string; inputKind?: 'filesystem'|'image-archive'|'rootfs'; targets: string[]; timeWindows: TimeWindow[] }
export interface Schedule extends TaskInput {
  id: string; name: string; nextRun: string; intervalMinutes: number; enabled: boolean;
  lastTaskId: string; lastError: string; createdBy: string;
}
export interface RuleJob {
  id: string; kind: 'IMPORT'|'FETCH'|'ACTIVATE'; status: 'PENDING'|'RUNNING'|'COMPLETED'|'FAILED';
  version: string; message: string; createdAt: string; completedAt: string;
}
