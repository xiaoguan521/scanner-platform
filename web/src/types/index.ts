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

export interface LoginEntry { type: 'system'|'web'; name: string; port: number; url?: string; https: boolean; captcha?: boolean|null; antiBruteForce?: boolean|null; evidence?: string }
export interface AssetService { port: number; scheme?: string; kind?: 'HTTP'|'OTHER'; protocol?: string; state?: string; serviceName?: string; software?: string; version?: string; middleware?: string; language?: string; framework?: string; database?: string; application?: string; url?: string; title?: string; tls?: boolean; firstSeen?: string; lastSeen?: string; excluded?: boolean; quarantined?: boolean; quarantineReason?: string; loginEntries?: LoginEntry[] }
export interface AssetProfile { name?: string; isCore?: boolean; department?: string; phone?: string; mac?: string; osName?: string; osFamily?: string; deviceType?: string; deviceSubtype?: string; vendor?: string; model?: string }
export interface Asset extends AssetProfile {
  id: string;
  kind: 'host' | 'image_repo';
  address: string;
  resolvedIp?: string;
  businessGroup: string;
  owner: string;
  createdAt: string;
  ports: AssetPort[];
  services?: AssetService[];
  loginEntries?: LoginEntry[];
  requestedPorts?: number[]; // Registration request only; NOT an approved scan port
  quarantinedPorts?: number[];
  skippedPorts?: number[];
  reachabilityStatus?: 'UNCHECKED'|'REACHABLE'|'NO_RESPONSE'|'CHECK_FAILED';
  reachabilityCheckedAt?: string;
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
  engines: ('auto' | 'nuclei' | 'trivy' | 'zap' | 'synthetic' | 'port-probe')[];
  status: TaskStatus;
  archived?: boolean;
  findingCount: number;
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
  assetId?: string;
  portProbeConfig?: PortProbeConfig;
  effectiveExclusions?: PortProbeRange[];
  quarantinedPorts?: number[];
  assetProfile?: AssetProfile;
  portProbePorts?: number[];
  portProbeResults?: PortProbeResult[];
  vulnerabilityPorts?: number[];
  serviceResults?: ServiceResult[];
  systemScanStatus?: string;
  customRuleCount?: number;
}

export interface PortProbeRange { start: number; end: number }
export interface PortProbeConfig {
  preset: 'common'|'custom'|'common-and-custom'|'registered'|'full';
  intensity?: 'gentle'|'standard'|'aggressive';
  fullConfirmed?: boolean;
  commonPorts?: number[];
  registeredPorts?: number[];
  ranges?: PortProbeRange[];
  exclusions?: PortProbeRange[];
  opsApproved?: boolean;
}
export interface PortProbeResult { port: number }
export interface ServiceResult extends AssetService { kind: 'HTTP'|'OTHER' }

export type FindingSeverity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO';

export type FindingStatus =
  | 'OPEN'
  | 'REOPENED'
  | 'IN_PROGRESS'
  | 'FIXED'
  | 'FALSE_POSITIVE'
  | 'ACCEPTED_RISK';

export type RiskType = 'system'|'web'|'weak_credential'|'login_entry';
export type DetectMethod = 'principle'|'version'|'configuration';
export type Confidence = 'high'|'medium'|'low';
export interface Finding {
  assetId?: string; taskId?: string; riskType?: RiskType; detectMethod?: DetectMethod; confidence?: Confidence;
  cvssScore?: number; vulnCategory?: string; identifiers?: Record<string,string[]>;
  impact?: string; solution?: string; references?: string[]; evidence?: string; component?: string; contentLanguage?: string;
  id: string;
  fingerprint: string;
  severity: FindingSeverity;
  title: string;
  engine: 'nuclei' | 'trivy' | 'zap' | 'synthetic' | 'knowledge';
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
export interface TaskInput { synthetic: boolean; engine?: 'auto'|'nuclei'|'trivy'|'zap'|'synthetic'|'port-probe'; scheme?: 'http'|'https'; inputPath?: string; inputKind?: 'filesystem'|'image-archive'|'rootfs'|'artifact'; assetId?: string; portProbe?: PortProbeConfig; customRuleIds?: string[]; targets: string[]; timeWindows: TimeWindow[] }
export interface Schedule extends TaskInput {
  id: string; name: string; nextRun: string; intervalMinutes: number; enabled: boolean;
  lastTaskId: string; lastError: string; createdBy: string;
}
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
  template?: string;
}

export interface ScanPolicy { commonPorts: number[]; exclusions: PortProbeRange[]; quarantineThreshold: number; discoveryAttempts: number }
export interface DetectionCapability { id: string; name: string; status: 'enabled'|'disabled'|'unavailable'; message: string }
export interface VulnerabilityCategory { id: string; name: string; cwe?: string }
export interface KnowledgeEntry { id: string; title: string; description: string; impact: string; solution: string; references: string[]; cvssScore?: number; category: string; identifiers: Record<string,string[]>; component: string; affectedRanges: {introduced?:string;fixed?:string;lastAffected?:string}[]; source: string; updatedAt: string; language: string }
