// Findings, their workflow records and the vulnerability knowledge base.
import type { TaskStatus } from './task';

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
export interface FindingEvent { id:string; findingId:string; fromStatus:FindingStatus; toStatus:FindingStatus; actor:string; reason?:string; createdAt:string }
export interface FindingAssignee { id:string; name:string }
export interface FindingNote { id:string; findingId:string; actor:string; actorName:string; body:string; createdAt:string }
export interface FindingAssignmentEvent { id:string; findingId:string; fromAssigneeId?:string; toAssigneeId?:string; actor:string; createdAt:string }
export interface FindingRetest { id:string; findingId:string; taskId:string; actor:string; status:TaskStatus; createdAt:string }
export interface Finding {
  assigneeId?:string; assigneeName?:string;
  acceptedReason?:string; acceptedUntil?:string;
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
  resolvedAt?: string;
  synthetic?: boolean;
  artifactId?: string; matchedPath?: string; package?: string; installedVersion?: string; fixedVersion?: string; description?: string;
}


export interface DetectionCapability { id: string; name: string; status: 'enabled'|'disabled'|'unavailable'; message: string }
export interface VulnerabilityCategory { id: string; name: string; cwe?: string }
export interface KnowledgeEntry { id: string; title: string; description: string; impact: string; solution: string; references: string[]; cvssScore?: number; category: string; identifiers: Record<string,string[]>; component: string; affectedRanges: {introduced?:string;fixed?:string;lastAffected?:string}[]; source: string; updatedAt: string; language: string }
