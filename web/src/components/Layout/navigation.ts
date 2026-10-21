export type NavigationRole = 'admin' | 'security_engineer' | 'ops_approver' | 'viewer';

export interface NavigationLeaf {
  key: string;
  label: string;
  roles?: readonly NavigationRole[];
}

export interface NavigationGroup {
  key: string;
  label: string;
  defaultPath: string;
  children: readonly NavigationLeaf[];
}

/**
 * The product information architecture has six stable top-level domains.
 * Only pages with a real route are listed; unfinished modules stay out of the
 * menu until their API and empty/error states are ready.
 */
export const navigationGroups: readonly NavigationGroup[] = [
  { key: 'overview', label: '总览', defaultPath: '/', children: [{ key: '/', label: '态势总览' }] },
  { key: 'assets', label: '资产', defaultPath: '/assets', children: [{ key: '/assets', label: '资产列表' }] },
  { key: 'scans', label: '扫描', defaultPath: '/tasks', children: [{ key: '/tasks', label: '扫描任务与计划' }] },
  { key: 'findings', label: '漏洞', defaultPath: '/findings', children: [{ key: '/findings', label: '漏洞列表' }] },
  { key: 'reports', label: '报告', defaultPath: '/reports', children: [{ key: '/reports', label: '报告中心' }] },
  {
    key: 'system',
    label: '系统',
    defaultPath: '/scopes',
    children: [
      { key: '/scopes', label: '授权范围' },
      { key: '/nodes', label: '节点与规则库' },
      { key: '/knowledge', label: '漏洞知识库' },
      { key: '/users', label: '用户与角色', roles: ['admin'] },
      { key: '/audit', label: '审计日志', roles: ['admin'] },
      { key: '/settings', label: '系统设置', roles: ['admin'] },
    ],
  },
];

export function visibleNavigation(role?: NavigationRole): NavigationGroup[] {
  return navigationGroups
    .map(group => ({
      ...group,
      children: group.children.filter(item => !item.roles || (role !== undefined && item.roles.includes(role))),
    }))
    .filter(group => group.children.length > 0);
}

export function navigationLabel(pathname: string, groups: readonly NavigationGroup[] = navigationGroups): string | undefined {
  for (const group of groups) {
    const child = group.children.find(item => item.key === pathname);
    if (child) return child.label;
  }
  return undefined;
}
