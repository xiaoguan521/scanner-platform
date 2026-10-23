// Accounts, roles, system settings and audit records.
export type UserRole = 'admin' | 'security_engineer' | 'ops_approver' | 'viewer';

export interface User {
  id: string;
  username: string;
  role: UserRole;
  isActive: boolean;
}

export interface SystemSettings {
  timeZone: 'UTC' | 'Asia/Shanghai' | 'America/New_York';
  sessionDurationMinutes: number;
}


export interface AuditLog {
  id: string;
  actor: string;
  action: string;
  objectType: string;
  objectId: string;
  createdAt: string;
}
