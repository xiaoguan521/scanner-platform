import type { AssetImportPreview } from '../pages/Assets/import';
import type { Asset, AssetImportHistory, AuthorizedScope, Finding, NodeCredential, NodeInfo, NodeLifecycle, NodeLifecycleEvent, NotificationList, NotificationListPage, NotificationSettings, NotificationDeliveryList, PortQuarantine, RuleBundle, ScanTask, User, UserRole, PortRequest, TimeWindow, ApprovalDecision, Schedule, RuleJob, CustomRule, AssetProfile, KnowledgeEntry, DetectionCapability, VulnerabilityCategory, ScanPolicy, ScanPlan, SystemSettings, BusinessGroup } from '../types';

export interface SystemStatus {
  role: 'sec-server' | 'sec-portable';
  phase: string;
  state: 'SCAFFOLD' | 'RUNNING';
  ready: boolean;
  enabled: string[];
  unavailable: string[];
}
export interface Capabilities { enabled: string[]; unavailable: string[] }
export interface ApiErrorBody {
  code?: string;
  /** Deprecated compatibility alias for code. */
  error?: string;
  message: string;
  hint?: string;
  request_id?: string;
}
export interface ListResponse<T> { items: T[]; total: number }
export interface PagedListResponse<T> extends ListResponse<T> { page: number; pageSize: number }
export interface TaskPageResponse<T> extends PagedListResponse<T> { statusCounts: Record<string, number> }
export interface FindingPageResponse<T> extends PagedListResponse<T> { counts: { vulnerabilities: number; loginEntries: number; unknown: number; version: number; verified: number } }
export type ReportPageResponse<T> = PagedListResponse<T>
export interface ScopePageResponse extends PagedListResponse<AuthorizedScope> { expiringCount: number; expiredCount: number }
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
  constructor(public readonly status: number, message: string, public readonly code?: string, public readonly hint?: string, public readonly requestId?: string) {
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
    let apiError: ApiErrorBody | undefined;
    try {
      const parsed: unknown = await response.json();
      if (parsed && typeof parsed === 'object' && typeof (parsed as {message?: unknown}).message === 'string') {
        apiError = parsed as ApiErrorBody;
      }
    } catch { /* Unknown error bodies stay generic. */ }
    if (apiError) {
      const err = apiError;
      const code = typeof err.code === 'string' ? err.code : err.error;
      const messages:Record<string,string>={asset_import_unavailable:'预览已过期、已确认或被替换，请重新上传预览',asset_import_conflict:'资产在预览后发生冲突，整批未导入；请重新上传预览',invalid_user:'用户名、角色或密码不符合要求（密码 12–72 字节）',invalid_password:'新密码需为 12–72 字节',user_exists:'用户名已存在',invalid_asset:'请输入有效数字 IP、业务组、负责人和端口；跳过端口须属于目标端口',asset_exists:'资产已存在',asset_in_use_remove_authorization_first:'资产仍有授权范围，请先撤销或删除关联授权',host_asset_required:'仅支持对已登记主机检查 Ping 可达性',reachability_check_failed:'可达性检测失败，请稍后重试',invalid_port_request:'端口申请格式无效',port_request_conflict:'端口已申请、已跳过或处于隔离状态',invalid_asset_export_filter:'资产筛选条件无效，请勿重复填写且长度不要超过 160 字节',invalid_asset_list_query:'资产分页、搜索或排序条件无效',asset_pagination_unavailable:'当前 Server 不支持资产分页',invalid_task_list_query:'任务分页、筛选或排序条件无效',task_pagination_unavailable:'当前 Server 不支持任务分页',invalid_finding_list_query:'漏洞分页、筛选或排序条件无效',finding_pagination_unavailable:'当前 Server 不支持漏洞分页',invalid_report_list_query:'报告分页、筛选或排序条件无效',invalid_node_list_query:'节点分页、搜索或排序条件无效',invalid_rule_list_query:'规则版本分页、搜索或排序条件无效',invalid_custom_rule_list_query:'自定义规则分页、筛选或排序条件无效',invalid_rule_job_list_query:'规则操作记录分页、筛选或排序条件无效',invalid_notification_settings:'Webhook 地址必须是 HTTPS；本机测试可用回环 HTTP',invalid_notification_delivery_query:'通知投递分页参数无效',invalid_business_group_list_query:'业务组分页或搜索条件无效',invalid_asset_import_history_list_query:'导入记录分页或搜索条件无效',invalid_knowledge_list_query:'知识库分页、搜索或排序条件无效',invalid_notification_list_query:'通知分页或筛选条件无效',invalid_scope_list_query:'授权范围分页或期限筛选条件无效',invalid_port_request_list_query:'端口申请分页、状态或搜索条件无效',scope_pagination_unavailable:'当前 Server 不支持授权范围分页',port_request_pagination_unavailable:'当前 Server 不支持端口申请分页',invalid_scan_plan:'扫描方案字段或端口范围无效，请检查后重试',scan_plan_conflict:'预置方案不能修改或删除，方案可能已被其他人更新',task_not_found:'扫描任务不存在或已删除',task_not_terminal:'只能归档或删除已结束的任务',task_has_findings:'任务有关联发现，不能彻底删除；可以归档隐藏',task_state_conflict:'任务当前状态不支持暂停或恢复',invalid_task_export_format:'任务导出格式无效，请选择 JSON 或 CSV',invalid_archive_filter:'归档筛选条件无效',invalid_business_group:'请输入 1–100 个字符的业务组名称',business_group_exists:'业务组已存在',business_group_unavailable:'业务组管理暂不可用',asset_import_history_unavailable:'导入记录暂不可用',forbidden:'当前账号无权执行此操作',invalid_approval:'审批记录或时间窗格式不正确',approval_conflict:'记录已审核、已过期或端口被标记跳过',invalid_system_settings:'系统时区或会话时长无效，请检查后重试',invalid_node_registration:'节点 ID、类型或主机 ID 无效',node_already_registered:'该节点已经登记',invalid_node_id:'节点 ID 无效',node_not_registered:'节点尚未登记',node_revoked:'节点已吊销',node_kind_mismatch:'节点类型不匹配',node_registry_unavailable:'节点状态暂不可用',db_error:'保存失败，请查看 Server 日志',already_initialized:'管理员已初始化，请直接登录'};
        messages.node_credential_exists='该节点已经签发过令牌，请使用令牌轮换';
        messages.node_credential_not_found='该节点还没有可轮换的令牌，请先签发令牌';
        messages.node_issuance_unavailable='当前 Server 未配置可用的节点令牌签发能力';
      description=messages[code??'']??err.message;
      throw new ApiRequestError(response.status, description, code, err.hint, err.request_id);
    }
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
    let apiError: ApiErrorBody | undefined;
    try {
      const parsed: unknown = await response.json();
      if (parsed && typeof parsed === 'object' && typeof (parsed as {message?: unknown}).message === 'string') {
        apiError = parsed as ApiErrorBody;
      }
    } catch { /* Unknown error bodies stay generic. */ }
    if (apiError) {
      const code = typeof apiError.code === 'string' ? apiError.code : apiError.error;
      throw new ApiRequestError(response.status, apiError.message, code, apiError.hint, apiError.request_id);
    }
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
  businessGroups() { return requestJSON<ListResponse<BusinessGroup>>('/api/v1/business-groups'); },
  businessGroupsPage(page:number,pageSize:number,search='',signal?:AbortSignal) { const params=new URLSearchParams({page:String(page),page_size:String(pageSize)}); if(search.trim())params.set('q',search.trim()); return requestJSON<PagedListResponse<BusinessGroup>>('/api/v1/business-groups?'+params.toString(),'GET',undefined,signal); },
  createBusinessGroup(name:string) { return requestJSON<BusinessGroup>('/api/v1/business-groups','POST',{name}); },
  assetImportHistory() { return requestJSON<ListResponse<AssetImportHistory>>('/api/v1/assets/import-history'); },
  assetImportHistoryPage(page:number,pageSize:number,search='',signal?:AbortSignal) { const params=new URLSearchParams({page:String(page),page_size:String(pageSize)}); if(search.trim())params.set('q',search.trim()); return requestJSON<PagedListResponse<AssetImportHistory>>('/api/v1/assets/import-history?'+params.toString(),'GET',undefined,signal); },
  scanPolicy() { return requestJSON<ScanPolicy>('/api/v1/scan-policy'); },
  saveScanPolicy(input:ScanPolicy) { return requestJSON<ScanPolicy>('/api/v1/scan-policy','PUT',input); },
  systemSettings() { return requestJSON<SystemSettings>('/api/v1/system-settings'); },
  saveSystemSettings(input:SystemSettings) { return requestJSON<SystemSettings>('/api/v1/system-settings','PUT',input); },
  notificationSettings() { return requestJSON<NotificationSettings>('/api/v1/notification-settings'); },
  saveNotificationSettings(input:NotificationSettings) { return requestJSON<NotificationSettings>('/api/v1/notification-settings','PUT',input); },
  notificationDeliveries(limit=50,offset=0) { return requestJSON<NotificationDeliveryList>('/api/v1/notification-deliveries?limit='+limit+'&offset='+offset); },
  notifications(unreadOnly = false) { return requestJSON<NotificationList>('/api/v1/notifications?unread=' + String(unreadOnly)); },
  notificationsPage(page:number,pageSize:number,unreadOnly=false,signal?:AbortSignal) { const params=new URLSearchParams({page:String(page),page_size:String(pageSize),unread:String(unreadOnly)}); return requestJSON<NotificationListPage>('/api/v1/notifications?'+params.toString(),'GET',undefined,signal); },
  markNotificationRead(id:string) { return requestJSON<{status:string}>('/api/v1/notifications/' + encodeURIComponent(id) + '/read','POST',{}); },
  markAllNotificationsRead() { return requestJSON<{status:string}>('/api/v1/notifications/read-all','POST',{}); },
  releaseQuarantine(assetId:string,port:number,reason:string) { return requestJSON('/api/v1/port-quarantines/release','POST',{assetId,port,reason}); },
  systemStatus(signal?: AbortSignal) { return requestJSON<SystemStatus>('/api/v1/system/status', 'GET', undefined, signal); },
  capabilities(signal?: AbortSignal) { return requestJSON<Capabilities>('/api/v1/system/capabilities', 'GET', undefined, signal); },
  dashboardSummary(days: 7 | 30 | 90, signal?: AbortSignal) { return requestJSON<DashboardSummary>('/api/v1/dashboard/summary?days=' + days, 'GET', undefined, signal); },
  collection<K extends keyof Resources>(name: K, signal?: AbortSignal, query = '') {
    return requestJSON<ListResponse<Resources[K]>>('/api/v1/' + name + query, 'GET', undefined, signal);
  },
  assetsPage(page:number,pageSize:number,search:string,sort='-created_at',signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort});
    if(search.trim())params.set('q',search.trim());
    return requestJSON<PagedListResponse<Asset>>('/api/v1/assets?'+params.toString(),'GET',undefined,signal);
  },
  tasksPage(page:number,pageSize:number,options:{search?:string;status?:string;engine?:string;archived?:'true'|'false'|'all';sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),archived:options.archived??'false',sort:options.sort??'-created_at'});
    if(options.search?.trim())params.set('q',options.search.trim());
    if(options.status&&options.status!=='all')params.set('status',options.status);
    if(options.engine&&options.engine!=='all')params.set('engine',options.engine);
    return requestJSON<TaskPageResponse<ScanTask>>('/api/v1/tasks?'+params.toString(),'GET',undefined,signal);
  },
  findingsPage(page:number,pageSize:number,options:{search?:string;severity?:string;status?:string;method?:string;confidence?:string;risk?:string;onlyVerified?:boolean;businessGroup?:string;assetId?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'-last_seen'});
    for(const key of ['severity','status','method','confidence','risk'] as const){const value=options[key];if(value&&value!=='ALL')params.set(key,value);}
    if(options.onlyVerified)params.set('onlyVerified','true');
    if(options.businessGroup?.trim())params.set('businessGroup',options.businessGroup.trim());
    if(options.assetId?.trim())params.set('assetId',options.assetId.trim());
    if(options.search?.trim())params.set('q',options.search.trim());
    return requestJSON<FindingPageResponse<Finding>>('/api/v1/findings?'+params.toString(),'GET',undefined,signal);
  },
  nodesPage<T>(page:number,pageSize:number,options:{search?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'id'});
    if(options.search?.trim())params.set('q',options.search.trim());
    return requestJSON<PagedListResponse<T>>('/api/v1/nodes?'+params.toString(),'GET',undefined,signal);
  },
  registerNode(input:Pick<NodeLifecycle,'id'|'kind'|'hostId'>) { return requestJSON<NodeLifecycle>('/api/v1/nodes/register','POST',input); },
  issueNodeCredential(id:string) { return requestJSON<NodeCredential>('/api/v1/nodes/' + encodeURIComponent(id) + '/issue','POST',{}); },
  rotateNodeCredential(id:string) { return requestJSON<NodeCredential>('/api/v1/nodes/' + encodeURIComponent(id) + '/rotate','POST',{}); },
  revokeNode(id:string) { return requestJSON<{status:string}>('/api/v1/nodes/' + encodeURIComponent(id) + '/revoke','POST',{}); },
  nodeLifecycle(id:string,signal?:AbortSignal) { return requestJSON<NodeLifecycle>('/api/v1/nodes/' + encodeURIComponent(id) + '/lifecycle','GET',undefined,signal); },
  nodeLifecycleEvents(id:string,signal?:AbortSignal) { return requestJSON<ListResponse<NodeLifecycleEvent>>('/api/v1/nodes/' + encodeURIComponent(id) + '/events','GET',undefined,signal); },
  rulesPage<T>(page:number,pageSize:number,options:{search?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'-version'});
    if(options.search?.trim())params.set('q',options.search.trim());
    return requestJSON<PagedListResponse<T>>('/api/v1/rules?'+params.toString(),'GET',undefined,signal);
  },
  ruleJobsPage<T>(page:number,pageSize:number,options:{search?:string;status?:string;kind?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'-created_at'});
    if(options.search?.trim())params.set('q',options.search.trim());
    if(options.status&&options.status!=='ALL')params.set('status',options.status);
    if(options.kind&&options.kind!=='ALL')params.set('kind',options.kind);
    return requestJSON<PagedListResponse<T>>('/api/v1/rule-jobs?'+params.toString(),'GET',undefined,signal);
  },
  customRulesPage<T>(page:number,pageSize:number,options:{search?:string;severity?:string;enabled?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'-updated_at'});
    if(options.search?.trim())params.set('q',options.search.trim());
    if(options.severity&&options.severity!=='ALL')params.set('severity',options.severity);
    if(options.enabled&&options.enabled!=='ALL')params.set('enabled',options.enabled);
    return requestJSON<PagedListResponse<T>>('/api/v1/custom-rules?'+params.toString(),'GET',undefined,signal);
  },
  knowledgePage(page:number,pageSize:number,search='',signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize)});
    if(search.trim())params.set('q',search.trim());
    return requestJSON<PagedListResponse<KnowledgeEntry>>('/api/v1/knowledge?'+params.toString(),'GET',undefined,signal);
  },
  reportsPage<T>(page:number,pageSize:number,options:{search?:string;status?:string;format?:string;sort?:string}={},signal?:AbortSignal) {
    const params=new URLSearchParams({page:String(page),page_size:String(pageSize),sort:options.sort??'-created_at'});
    if(options.search?.trim())params.set('q',options.search.trim());
    if(options.status&&options.status!=='ALL')params.set('status',options.status);
    if(options.format&&options.format!=='ALL')params.set('format',options.format);
    return requestJSON<ReportPageResponse<T>>('/api/v1/reports?'+params.toString(),'GET',undefined,signal);
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
  renewScopes(ids:string[], expiresAt:string) {
    return requestJSON<{items:AuthorizedScope[];status:string}>('/api/v1/scopes/renew', 'POST', {ids, expiresAt});
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
  scopesPage(page:number,pageSize:number,expiry='all',signal?:AbortSignal) { const params=new URLSearchParams({page:String(page),page_size:String(pageSize),expiry}); return requestJSON<ScopePageResponse>('/api/v1/scopes?'+params.toString(),'GET',undefined,signal); },
  portRequestsPage(page:number,pageSize:number,options:{status?:string;search?:string}={},signal?:AbortSignal) { const params=new URLSearchParams({page:String(page),page_size:String(pageSize),status:options.status??'ALL'}); if(options.search?.trim())params.set('q',options.search.trim()); return requestJSON<PagedListResponse<PortRequest>>('/api/v1/port-requests?'+params.toString(),'GET',undefined,signal); },
  reviewScope(id:string, decision:ApprovalDecision) {
    return requestJSON<AuthorizedScope>('/api/v1/scopes/' + encodeURIComponent(id) + '/review', 'POST', decision);
  },
  reviewPort(assetId:string, port:number, decision:ApprovalDecision) {
    return requestJSON<PortRequest>('/api/v1/port-requests/' + encodeURIComponent(assetId) + '/' + port + '/review', 'POST', decision);
  },
};
// Approval endpoints are administrative records only; no execution leases or
// scanner operations are exposed. The Server retains all execution decisions.
