// Scan plans, tasks, schedules and scan policy.
import type { AssetProfile, AssetService } from './asset';
import type { TimeWindow } from './scope';

/** Stable system-scan codes from taskflow.SystemScanCode; "unknown" for unrecognized text. */
export type SystemScanCode = 'not_started' | 'not_configured' | 'port_out_of_scope' | 'port_closed' | 'client_missing' | 'host_key_mismatch' | 'auth_failed' | 'python_missing' | 'collection_failed' | 'invalid_snapshot' | 'trivy_unavailable' | 'unsupported_os' | 'trivy_failed' | 'completed' | 'unknown';
export type ScanPlanPortPreset = 'common' | 'custom' | 'common-and-custom' | 'registered' | 'full';
export type ScanPlanIntensity = 'gentle' | 'standard' | 'aggressive';
export interface ScanPlanDefaults {
  portPreset: ScanPlanPortPreset;
  intensity: ScanPlanIntensity;
  portRanges: string;
  portExclusions: string;
  customRuleIds: string[];
}
export interface ScanPlan {
  id: string;
  title: string;
  summary: string;
  detail: string;
  kind: 'PRESET' | 'CUSTOM';
  readOnly: boolean;
  defaults: ScanPlanDefaults;
  sourceId?: string;
  createdBy?: string;
  createdAt?: string;
  updatedAt?: string;
}
export interface ScanPlanInput {
  title: string;
  summary: string;
  detail: string;
  defaults: ScanPlanDefaults;
  sourceId?: string;
}


export type TaskStatus =
  | 'PENDING'
  | 'WAITING_WINDOW'
  | 'RUNNING'
  | 'PAUSED'
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
  /** Ports that completed the TCP handshake but ran no service (nmap's tcpwrapped). */
  tcpWrapped?: number;
  /** Ports whose state could not be decided from repeated checks. */
  unconfirmedPorts?: number[];
  vulnerabilityPorts?: number[];
  serviceResults?: ServiceResult[];
  systemScanStatus?: string;
  /** Stable code derived by the Server from systemScanStatus. */
  systemScanCode?: SystemScanCode;
  applicationScanStatus?: string;
  applicationResults?: ApplicationResult[];
  fenceStatus?: 'ENFORCED' | 'NOT_SUPPORTED' | 'NOT_VERIFIED';
  dropCount?: number;
  progress?: TaskProgress;
  customRuleCount?: number;
  retestFindingId?: string;
}

export interface ApplicationResult {
  alias: string;
  status: string;
  selectedCount: number;
  analyzedCount: number;
}

export interface TaskProgress {
  phase: string;
  completed: number;
  total: number;
  updatedAt: string;
  /** Final counts of phases already left behind (older Servers omit it). */
  phases?: Record<string, { completed: number; total: number }>;
  /** Ports found so far while the task runs (omitted for unusually long lists). */
  openPorts?: number[];
  httpPorts?: number[];
  /** Compact identified services while the task runs; the full inventory arrives with the final report. */
  services?: { port: number; kind: string; scheme?: string; software?: string; version?: string; title?: string; tls?: boolean }[];
}
export interface TaskLog {
  id: string;
  actor: string;
  action: string;
  message: string;
  createdAt: string;
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


export interface TaskInput { synthetic: boolean; engine?: 'auto'|'nuclei'|'trivy'|'zap'|'synthetic'|'port-probe'; scheme?: 'http'|'https'; inputPath?: string; inputKind?: 'filesystem'|'image-archive'|'rootfs'|'artifact'; assetId?: string; portProbe?: PortProbeConfig; customRuleIds?: string[]; targets: string[]; timeWindows: TimeWindow[] }
export interface Schedule extends TaskInput {
  id: string; name: string; nextRun: string; intervalMinutes: number; enabled: boolean;
  lastTaskId: string; lastError: string; createdBy: string;
}
export interface ScheduleRun {
  id: string; scheduleId: string; taskId: string; triggeredAt: string; status: string; error?: string;
}

export interface ScanPolicy { commonPorts: number[]; exclusions: PortProbeRange[]; quarantineThreshold: number; discoveryAttempts: number; fixedThreshold: number }
