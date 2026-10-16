import type { User } from '../types';

// Example identities only; these are not real accounts or credentials.
export const mockUsers: User[] = [
  { id: 'user-demo-001', username: 'demo_admin', role: 'admin', isActive: true },
  { id: 'user-demo-002', username: 'demo_security', role: 'security_engineer', isActive: true },
  { id: 'user-demo-003', username: 'demo_approver', role: 'ops_approver', isActive: true },
  { id: 'user-demo-004', username: 'demo_viewer', role: 'viewer', isActive: false },
];
