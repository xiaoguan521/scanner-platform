import type { AssetImportPreview } from '../pages/Assets/import';
import type { Asset, AuthorizedScope, Finding, NodeInfo, PortQuarantine, RuleBundle, ScanTask, User, UserRole, PortRequest, TimeWindow, ApprovalDecision, Schedule, RuleJob, CustomRule, AssetProfile, KnowledgeEntry, DetectionCapability, VulnerabilityCategory, ScanPolicy, ScanPlan, SystemSettings } from '../types';

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
export interface DashboardSummary {
  assetCount: number;
  taskCount: number;
  runningTaskCount: number;
  hasNonSyntheticTask: boolean;
  hasCompletedScan: boolean;
  riskScore: number;
  riskyAssetCount: number;
  findingCount: number;
  criticalCount: number;
  highCount: number;
  severityDistribution: Record<string, number>;
  findingCounts: { vulnerabilities: number; loginEntries: number; unknown: number; version: number; verified: number };
  trend: { date: string; label: string; count: number }[];
  riskGroups: { name: string; score: number; openCount: number }[];
  riskAssets: { id: string; name: string; address: string; score: number; openCount: number }[];
  pendingCount: number;
  pendingFindings: { id: string; severity: 'CRITICAL' | 'HIGH'; title: string; target: string; status: 'OPEN' | 'REOPENED' | 'IN_PROGRESS'; businessGroup: string }[];
  currentRule?: Resources['rules'];
}
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
  'custom-rules': CustomRule;
  knowledge: KnowledgeEntry;
  'detection-capabilities': DetectionCapability;
  'vulnerability-categories': VulnerabilityCategory;
  'scan-plans': ScanPlan;
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
      const messages:Record<string,string>={asset_import_unavailable:'预览已过期、已确认或被替换，请重新上传预览',asset_import_conflict:'资产在预览后发生冲突，整批未导入；请重新上传预览',invalid_user:'用户名、角色或密码不符合要求（密码 12–72 字节）',invalid_password:'新密码需为 12–72 字节',user_exists:'用户名已存在',invalid_asset:'请输入有效数字 IP、业务组、负责人和端口；跳过端口须属于目标端口',asset_exists:'资产已存在',asset_in_use_remove_authorization_first:'资产仍有授权记录，请先撤销或删除关联授权',host_asset_required:'仅支持对已登记主机检查 Ping 可达性',reachability_check_failed:'可达性检测失败，请稍后重试',invalid_port_request:'端口申请格式无效',port_request_conflict:'端口已申请、已跳过或处于隔离状态',invalid_asset_export_filter:'资产筛选条件无效，请勿重复填写且长度不要超过 160 字节',invalid_scan_plan:'扫描方案字段或端口范围无效，请检查后重试',scan_plan_conflict:'预置方案不能修改或删除，方案可能已被其他人更新',task_not_found:'扫描任务不存在或已删除',task_not_terminal:'只能归档或删除已结束的任务',task_has_findings:'任务有关联发现，不能彻底删除；可以归档隐藏',task_state_conflict:'任务当前状态不支持暂停或恢复',invalid_task_export_format:'结果导出格式无效，请选择 JSON 或 CSV',invalid_archive_filter:'归档筛选条件无效',forbidden:'当前账号无权执行此操作',invalid_approval:'审批记录或时间窗格式不正确',approval_conflict:'记录已审核、已过期或端口被标记跳过',invalid_system_settings:'系统时区或会话时长无效，请检查后重试',db_error:'保存失败，请查看 Server 日志',already_initialized:'管理员已初始化，请直接登录'};
        description=messages[err.error]??err.message;
      }
    } catch { /* Unknown error bodies stay generic. */ }
    throw new ApiRequestError(response.status, description);
  }
  return response.json() as Promise<T>;
}
export async function requestBlob(path: string, signal?: AbortSignal, accept = 'text/csv'): Promise<Blob> {
  const response = await fetch(path, {
    headers: { Accept: accept },
    credentials: 'same-origin',
    signal,
    cache: 'no-store',
  });
  if (!response.ok) {
    if (response.status === 401) window.dispatchEvent(new Event('scanner-session-expired'));
    let description = response.statusText || 'Request failed';
    try {
      const err: ApiErrorBody = await response.json();
      if (typeof err.message === 'string') description = err.message;
    } catch { /* Unknown error bodies stay generic. */ }
    throw new ApiRequestError(response.status, description);
  }
  return response.blob();
}
export const apiClient = {
  async previewAssetImport(file:File):Promise<AssetImportPreview> {
    const response=await fetch('/api/v1/assets/import/preview',{method:'POST',headers:{'Content-Type':'text/csv; charset=utf-8','X-Requested-With':'XMLHttpRequest'},body:file,credentials:'same-origin',cache:'no-store'});
    if(!response.ok){
      if(response.status===401)window.dispatchEvent(new Event('scanner-session-expired'));
      const messages:Record<number,string>={400:'CSV 格式无效，请检查 UTF-8 编码、表头和内容',403:'当前账号无导入权限或会话校验失败',413:'文件超过 1 MiB 或 1000 行上限',415:'请上传 UTF-8 CSV 文件'};
      throw new ApiRequestError(response.status,messages[response.status]??'导入预览失败，请重试');
    }
    return response.json() as Promise<AssetImportPreview>;
  },
  confirmAssetImport(previewId:string) {return requestJSON<{imported:number}>('/api/v1/assets/import/confirm','POST',{previewId});},
  scanPolicy() { return requestJSON<ScanPolicy>('/api/v1/scan-policy'); },
  saveScanPolicy(input:ScanPolicy) { return requestJSON<ScanPolicy>('/api/v1/scan-policy','PUT',input); },
  systemSettings() { return requestJSON<SystemSettings>('/api/v1/system-settings'); },
  saveSystemSettings(input:SystemSettings) { return requestJSON<SystemSettings>('/api/v1/system-settings','PUT',input); },
  releaseQuarantine(assetId:string,port:number,reason:string) { return requestJSON('/api/v1/port-quarantines/release','POST',{assetId,port,reason}); },
  systemStatus(signal?: AbortSignal) { return requestJSON<SystemStatus>('/api/v1/system/status', 'GET', undefined, signal); },
  capabilities(signal?: AbortSignal) { return requestJSON<Capabilities>('/api/v1/system/capabilities', 'GET', undefined, signal); },
  dashboardSummary(days: 7 | 30 | 90, signal?: AbortSignal) { return requestJSON<DashboardSummary>('/api/v1/dashboard/summary?days=' + days, 'GET', undefined, signal); },
  collection<K extends keyof Resources>(name: K, signal?: AbortSignal, query = '') {
    return requestJSON<ListResponse<Resources[K]>>('/api/v1/' + name + query, 'GET', undefined, signal);
  },
  exportAssets(filter = '', signal?: AbortSignal) {
    const query = filter.trim() ? '?q=' + encodeURIComponent(filter.trim()) : '';
    return requestBlob('/api/v1/assets/export' + query, signal);
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
  resetUserPassword(id: string, password: string) {
    return requestJSON<User>('/api/v1/users/' + encodeURIComponent(id) + '/password-reset', 'POST', {password});
  },
  createAsset(input: AssetProfile & {kind: Asset['kind']; address: string; businessGroup: string; owner: string; requestedPorts: number[]; skippedPorts?: number[]}) {
    return requestJSON<Asset>('/api/v1/assets', 'POST', input);
  },
  updateAsset(id: string, input: AssetProfile & {address:string;businessGroup: string; owner: string; requestedPorts: number[]; skippedPorts?: number[]}) {
    return requestJSON<Asset>('/api/v1/assets/' + encodeURIComponent(id), 'PATCH', input);
  },
  deleteAsset(id: string) {
    return requestJSON<{status:string}>('/api/v1/assets/' + encodeURIComponent(id), 'DELETE');
  },
  checkAssetReachability(id: string) {
    return requestJSON<{status:'REACHABLE'|'NO_RESPONSE'|'CHECK_FAILED';checkedAt:string}>('/api/v1/assets/' + encodeURIComponent(id) + '/reachability-check', 'POST', {});
  },
  testAssetAddress(address: string) {
    return requestJSON<{status:'REACHABLE'|'NO_RESPONSE'|'CHECK_FAILED';checkedAt:string}>('/api/v1/assets/reachability-test', 'POST', {address});
  },
  requestAssetPort(id: string, port: number) {
    return requestJSON<{port:number;status:string}>('/api/v1/assets/' + encodeURIComponent(id) + '/port-requests', 'POST', {port});
  },
  requestAssetPorts(id: string, ports: number[]) {
    return requestJSON<{requested:number;status:string}>('/api/v1/assets/' + encodeURIComponent(id) + '/port-requests/batch', 'POST', {ports});
  },
  requestScope(input: {assetId:string; timeWindows:TimeWindow[]; expiresAt:string}) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes', 'POST', input);
  },
  updateScope(id:string,input:{assetId:string;timeWindows:TimeWindow[];expiresAt:string}) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes/' + encodeURIComponent(id), 'PUT', input);
  },
  deleteScope(id:string) {
    return requestJSON<{status:string}>('/api/v1/scopes/' + encodeURIComponent(id), 'DELETE');
  },
  revokeScope(id:string) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes/' + encodeURIComponent(id) + '/revoke', 'POST', {});
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
