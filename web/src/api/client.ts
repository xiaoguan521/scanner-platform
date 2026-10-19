import type { Asset, AuthorizedScope, Finding, NodeInfo, PortQuarantine, RuleBundle, ScanTask, User, UserRole, PortRequest, TimeWindow, ApprovalDecision, Schedule, RuleJob } from '../types';

export const dataMode: 'demo' | 'server' = import.meta.env.VITE_DATA_MODE === 'server' ? 'server' : 'demo';
export const isDemoMode = dataMode === 'demo';

export interface SystemStatus {
  role: 'sec-server' | 'sec-portable';
  phase: string;
  state: 'SCAFFOLD' | 'RUNNING';
  ready: boolean;
  enabled: string[];
  unavailable: string[];
}
export interface Capabilities { enabled: string[]; unavailable: string[] }
export interface ApiErrorBody { error: string; message: string }
export interface ListResponse<T> { items: T[]; total: number }
export interface Resources {
  users: User;
  assets: Asset;
  'port-quarantines': PortQuarantine;
  scopes: AuthorizedScope;
  'port-requests': PortRequest;
  tasks: ScanTask;
  findings: Finding;
  nodes: NodeInfo;
  rules: RuleBundle;
  schedules: Schedule;
  'rule-jobs': RuleJob;
}
export class ApiRequestError extends Error {
  constructor(public readonly status: number, message: string) {
    super(message);
    this.name = 'ApiRequestError';
  }
}
export async function requestJSON<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(path, {
    method,
    headers: {
      Accept: 'application/json',
      ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}),
      ...(method !== 'GET' ? { 'X-Requested-With': 'XMLHttpRequest' } : {}),
    },
    credentials: 'same-origin',
    signal,
    cache: 'no-store',
    ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
  });
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event('scanner-session-expired'));
    let description = response.statusText || 'Request failed';
    try {
      const err: ApiErrorBody = await response.json();
      if (typeof err.message === 'string') {
        const messages:Record<string,string>={invalid_user:'用户名、角色或密码不符合要求（密码 12–72 字节）',user_exists:'用户名已存在',invalid_asset:'请输入有效数字 IP、业务组、负责人和端口；跳过端口须属于目标端口',asset_exists:'资产已存在',invalid_port_request:'端口申请格式无效',port_request_conflict:'端口已申请、已跳过或处于隔离状态',forbidden:'当前账号无权执行此操作',invalid_approval:'审批记录或时间窗格式不正确',approval_conflict:'记录已审核、已过期或端口被标记跳过',db_error:'保存失败，请查看 Server 日志',already_initialized:'管理员已初始化，请直接登录'};
        description=messages[err.error]??err.message;
      }
    } catch { /* Unknown error bodies stay generic. */ }
    throw new ApiRequestError(response.status, description);
  }
  return response.json() as Promise<T>;
}
export const apiClient = {
  systemStatus(signal?: AbortSignal) { return requestJSON<SystemStatus>('/api/v1/system/status', 'GET', undefined, signal); },
  capabilities(signal?: AbortSignal) { return requestJSON<Capabilities>('/api/v1/system/capabilities', 'GET', undefined, signal); },
  collection<K extends keyof Resources>(name: K, signal?: AbortSignal) {
    return requestJSON<ListResponse<Resources[K]>>('/api/v1/' + name, 'GET', undefined, signal);
  },
  setupStatus() { return requestJSON<{required:boolean}>('/api/v1/auth/setup'); },
  setup(username:string,password:string) { return requestJSON('/api/v1/auth/setup','POST',{username,password}); },
  me() { return requestJSON<User>('/api/v1/auth/me'); },
  login(username: string, password: string) { return requestJSON<User>('/api/v1/auth/login', 'POST', { username, password }); },
  logout() { return requestJSON<{state:string}>('/api/v1/auth/logout', 'POST'); },
  createUser(username: string, password: string, role: UserRole) {
    return requestJSON<User>('/api/v1/users', 'POST', {username,password,role});
  },
  updateUser(id: string, role: UserRole, isActive: boolean) {
    return requestJSON<User>('/api/v1/users/' + encodeURIComponent(id), 'PATCH', {role,isActive});
  },
  createAsset(input: {kind: Asset['kind']; address: string; businessGroup: string; owner: string; requestedPorts: number[]; skippedPorts?: number[]}) {
    return requestJSON<Asset>('/api/v1/assets', 'POST', input);
  },
  updateAsset(id: string, input: {businessGroup: string; owner: string; requestedPorts: number[]; skippedPorts?: number[]}) {
    return requestJSON<Asset>('/api/v1/assets/' + encodeURIComponent(id), 'PATCH', input);
  },
  requestAssetPort(id: string, port: number) {
    return requestJSON<{port:number;status:string}>('/api/v1/assets/' + encodeURIComponent(id) + '/port-requests', 'POST', {port});
  },
  requestScope(input: {assetId:string; timeWindows:TimeWindow[]; expiresAt:string}) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes', 'POST', input);
  },
  reviewScope(id:string, decision:ApprovalDecision) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes/' + encodeURIComponent(id) + '/review', 'POST', decision);
  },
  reviewPort(assetId:string, port:number, decision:ApprovalDecision) {
    return requestJSON<PortRequest>('/api/v1/port-requests/' + encodeURIComponent(assetId) + '/' + port + '/review', 'POST', decision);
  },
};
// Approval endpoints are administrative records only; no execution leases or
// scanner operations are exposed. The Server retains all execution decisions.
