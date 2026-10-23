// Authorized scopes, port requests and time windows.
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
  expiryState?: 'NOT_APPLICABLE' | 'ACTIVE' | 'EXPIRING' | 'EXPIRED';
  status?: ReviewStatus | 'REVOKED';
  reviewNote?: string;
}
