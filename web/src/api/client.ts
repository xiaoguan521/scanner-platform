import type { AssetImportPreview } from '../pages/Assets/import';
import type { Asset, SystemScanCode, AssetImportHistory, AuthorizedScope, Finding, NodeCredential, NodeInfo, NodeLifecycle, NodeLifecycleEvent, NotificationList, NotificationListPage, NotificationSettings, NotificationDeliveryList, PortQuarantine, RuleBundle, ScanTask, User, UserRole, PortRequest, TimeWindow, ApprovalDecision, Schedule, RuleJob, CustomRule, AssetProfile, KnowledgeEntry, DetectionCapability, VulnerabilityCategory, ScanPolicy, ScanPlan, SystemSettings, BusinessGroup } from '../types';

import { toApiError } from './errors';
export { ApiRequestError, errorMessage } from './errors';
export type { ApiErrorBody } from './errors';

export interface SystemStatus {
  role: 'sec-server' | 'sec-portable';
  phase: string;
  state: 'SCAFFOLD' | 'RUNNING';
  ready: boolean;
  enabled: string[];
  unavailable: string[];
}
export interface Capabilities { enabled: string[]; unavailable: string[] }
export interface ListResponse<T> { items: T[]; total: number }
export interface PagedListResponse<T> extends ListResponse<T> { page: number; pageSize: number }
export interface TaskPageResponse<T> extends PagedListResponse<T> { statusCounts: Record<string, number> }
export interface FindingPageResponse<T> extends PagedListResponse<T> { counts: { vulnerabilities: number; loginEntries: number; unknown: number; version: number; verified: number } }
export type ReportPageResponse<T> = PagedListResponse<T>
export interface AssetInsight {
  assetId: string;
  activeFindingCount: number;
  activeFindings: Pick<Finding,'id'|'severity'|'title'|'status'|'engine'|'templateOrCve'|'lastSeen'>[];
  latestProbe?: { id: string; status: ScanTask['status']; createdAt: string; openPorts: number[] };
  recentTasks: { id: string; engines: string[]; status: ScanTask['status']; findingCount: number; createdAt: string; finishedAt?: string; systemScanCode?: SystemScanCode }[];
}
export interface FindingQueryOptions {search?:string;severity?:string;status?:string;method?:string;confidence?:string;risk?:string;engine?:string;onlyVerified?:boolean;fixable?:boolean;businessGroup?:string;assetId?:string;cve?:string;package?:string;taskId?:string}
function findingQueryParams(options:FindingQueryOptions):URLSearchParams {
  const params=new URLSearchParams();
  for(const key of ['severity','status','method','confidence','risk','engine'] as const){const value=options[key];if(value&&value!=='ALL')params.set(key,value);}
  if(options.onlyVerified)params.set('onlyVerified','true');
  if(options.fixable)params.set('fixable','true');
  for(const key of ['businessGroup','assetId','cve','package','taskId'] as const){const value=options[key]?.trim();if(value)params.set(key,value);}
  if(options.search?.trim())params.set('q',options.search.trim());
  return params;
}
export interface FindingGroup { key:string; title?:string; count:number; maxSeverity:Finding['severity']; statusCounts:Record<string,number>; assetCount:number; packages?:string[]; cveCount?:number; installedVersions?:string[]; fixedVersions?:string[]; lastSeen:string }
export interface FindingGroupPage { items:FindingGroup[]; total:number; page:number; pageSize:number; findings:number; ungrouped:number; counts:FindingPageResponse<Finding>['counts'] }
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
  if (!response.ok) throw await toApiError(response);
  return response.json() as Promise<T>;
}
export async function requestBlob(path: string, signal?: AbortSignal, accept = 'text/csv'): Promise<Blob> {
  const response = await fetch(path, {
    headers: { Accept: accept },
    credentials: 'same-origin',
    signal,
    cache: 'no-store',
  });
  if (!response.ok) throw await toApiError(response);
  return response.blob();
}
export const apiClient = {
  async previewAssetImport(file:File):Promise<AssetImportPreview> {
    const response=await fetch('/api/v1/assets/import/preview',{method:'POST',headers:{'Content-Type':'text/csv; charset=utf-8','X-Requested-With':'XMLHttpRequest'},body:file,credentials:'same-origin',cache:'no-store'});
    if(!response.ok)throw await toApiError(response,{400:'CSV 格式无效，请检查 UTF-8 编码、表头和内容',403:'当前账号无导入权限或会话校验失败',413:'文件超过 1 MiB 或 1000 行上限',415:'请上传 UTF-8 CSV 文件'},'导入预览失败，请重试');
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
  releaseAllQuarantines(assetId:string,reason:string) { return requestJSON('/api/v1/port-quarantines/release-all','POST',{assetId,reason}) as Promise<{status:string;released:number}>; },
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
  findingsPage(page:number,pageSize:number,options:FindingQueryOptions&{sort?:string}={},signal?:AbortSignal) {
    const params=findingQueryParams(options);
    params.set('page',String(page));params.set('page_size',String(pageSize));params.set('sort',options.sort??'-last_seen');
    return requestJSON<FindingPageResponse<Finding>>('/api/v1/findings?'+params.toString(),'GET',undefined,signal);
  },
  findingGroups(by:'cve'|'package',page:number,pageSize:number,options:FindingQueryOptions={},signal?:AbortSignal) {
    const params=findingQueryParams(options);
    params.set('by',by);params.set('page',String(page));params.set('page_size',String(pageSize));
    return requestJSON<FindingGroupPage>('/api/v1/findings/groups?'+params.toString(),'GET',undefined,signal);
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
  assetInsights(ids:string[],signal?:AbortSignal) {
    return requestJSON<ListResponse<AssetInsight>>('/api/v1/assets/insights?ids='+ids.map(encodeURIComponent).join(','),'GET',undefined,signal);
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
  scopesPage(page:number,pageSize:number,expiry='all',signal?:AbortSignal,search='') { const params=new URLSearchParams({page:String(page),page_size:String(pageSize),expiry}); if(search.trim())params.set('q',search.trim()); return requestJSON<ScopePageResponse>('/api/v1/scopes?'+params.toString(),'GET',undefined,signal); },
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
