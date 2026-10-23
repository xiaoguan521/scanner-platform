// Shared API error handling: every request path (JSON, blob, uploads) turns a
// failed response into an ApiRequestError with a Chinese message.

export interface ApiErrorBody {
  code?: string;
  /** Deprecated compatibility alias for code. */
  error?: string;
  message: string;
  hint?: string;
  request_id?: string;
}

export class ApiRequestError extends Error {
  constructor(public readonly status: number, message: string, public readonly code?: string, public readonly hint?: string, public readonly requestId?: string) {
    super(message);
    this.name = 'ApiRequestError';
  }
}

/** Chinese messages for Server error codes; unknown codes fall back to the Server message. */
export const errorMessages: Record<string, string> = {
  asset_import_unavailable: '预览已过期、已确认或被替换，请重新上传预览',
  asset_import_conflict: '资产在预览后发生冲突，整批未导入；请重新上传预览',
  invalid_user: '用户名、角色或密码不符合要求（密码 12–72 字节）',
  invalid_password: '新密码需为 12–72 字节',
  user_exists: '用户名已存在',
  invalid_asset: '请输入有效数字 IP、业务组、负责人和端口；跳过端口须属于目标端口',
  asset_exists: '资产已存在',
  asset_in_use_remove_authorization_first: '资产仍有授权范围，请先撤销或删除关联授权',
  host_asset_required: '仅支持对已登记主机检查 Ping 可达性',
  reachability_check_failed: '可达性检测失败，请稍后重试',
  invalid_port_request: '端口申请格式无效',
  port_request_conflict: '端口已申请、已跳过或处于隔离状态',
  invalid_asset_export_filter: '资产筛选条件无效，请勿重复填写且长度不要超过 160 字节',
  invalid_asset_list_query: '资产分页、搜索或排序条件无效',
  asset_pagination_unavailable: '当前平台不支持资产分页',
  invalid_task_list_query: '任务分页、筛选或排序条件无效',
  task_pagination_unavailable: '当前平台不支持任务分页',
  invalid_finding_list_query: '漏洞分页、筛选或排序条件无效',
  finding_pagination_unavailable: '当前平台不支持漏洞分页',
  invalid_report_list_query: '报告分页、筛选或排序条件无效',
  invalid_node_list_query: '节点分页、搜索或排序条件无效',
  invalid_rule_list_query: '规则版本分页、搜索或排序条件无效',
  invalid_custom_rule_list_query: '自定义规则分页、筛选或排序条件无效',
  invalid_rule_job_list_query: '规则操作记录分页、筛选或排序条件无效',
  invalid_notification_settings: 'Webhook 地址必须是 HTTPS；本机测试可用回环 HTTP',
  invalid_notification_delivery_query: '通知投递分页参数无效',
  invalid_business_group_list_query: '业务组分页或搜索条件无效',
  invalid_asset_import_history_list_query: '导入记录分页或搜索条件无效',
  invalid_knowledge_list_query: '知识库分页、搜索或排序条件无效',
  invalid_notification_list_query: '通知分页或筛选条件无效',
  invalid_scope_list_query: '授权范围分页或期限筛选条件无效',
  invalid_port_request_list_query: '端口申请分页、状态或搜索条件无效',
  scope_pagination_unavailable: '当前平台不支持授权范围分页',
  port_request_pagination_unavailable: '当前平台不支持端口申请分页',
  invalid_scan_plan: '扫描方案字段或端口范围无效，请检查后重试',
  scan_plan_conflict: '预置方案不能修改或删除，方案可能已被其他人更新',
  task_not_found: '扫描任务不存在或已删除',
  task_not_terminal: '只能归档或删除已结束的任务',
  task_has_findings: '任务有关联发现，不能彻底删除；可以归档隐藏',
  task_state_conflict: '任务当前状态不支持暂停或恢复',
  invalid_task_export_format: '任务导出格式无效，请选择 JSON 或 CSV',
  invalid_archive_filter: '归档筛选条件无效',
  invalid_business_group: '请输入 1–100 个字符的业务组名称',
  business_group_exists: '业务组已存在',
  business_group_unavailable: '业务组管理暂不可用',
  asset_import_history_unavailable: '导入记录暂不可用',
  forbidden: '当前账号无权执行此操作',
  invalid_approval: '审批记录或时间窗格式不正确',
  approval_conflict: '记录已审核、已过期或端口被标记跳过',
  invalid_system_settings: '系统时区或会话时长无效，请检查后重试',
  invalid_node_registration: '节点 ID、类型或主机 ID 无效',
  node_already_registered: '该节点已经登记',
  invalid_node_id: '节点 ID 无效',
  node_not_registered: '节点尚未登记',
  node_revoked: '节点已吊销',
  node_kind_mismatch: '节点类型不匹配',
  node_registry_unavailable: '节点状态暂不可用',
  db_error: '保存失败，请查看平台日志',
  already_initialized: '管理员已初始化，请直接登录',
  node_credential_exists: '该节点已经签发过令牌，请使用令牌轮换',
  node_credential_not_found: '该节点还没有可轮换的令牌，请先签发令牌',
  node_issuance_unavailable: '当前平台未配置可用的节点令牌签发能力',
};

/**
 * Builds the error for a failed response. A 401 also announces the expired
 * session so the login screen can take over. `statusMessages` covers
 * endpoints whose errors are keyed by HTTP status rather than code.
 */
export async function toApiError(response: Response, statusMessages: Record<number, string> = {}, fallback?: string): Promise<ApiRequestError> {
  if (response.status === 401) window.dispatchEvent(new Event('scanner-session-expired'));
  let apiError: ApiErrorBody | undefined;
  try {
    const parsed: unknown = await response.json();
    if (parsed && typeof parsed === 'object' && typeof (parsed as { message?: unknown }).message === 'string') {
      apiError = parsed as ApiErrorBody;
    }
  } catch { /* Unknown error bodies stay generic. */ }
  const byStatus = statusMessages[response.status];
  if (apiError) {
    const code = typeof apiError.code === 'string' ? apiError.code : apiError.error;
    return new ApiRequestError(response.status, errorMessages[code ?? ''] ?? byStatus ?? apiError.message, code, apiError.hint, apiError.request_id);
  }
  return new ApiRequestError(response.status, byStatus ?? fallback ?? (response.statusText || 'Request failed'));
}

/** Message for display; never shows the "Error: " prefix that String(e) adds. */
export function errorMessage(cause: unknown, fallback = '操作失败，请稍后重试'): string {
  if (cause instanceof Error && cause.message) return cause.message;
  if (typeof cause === 'string' && cause) return cause;
  return fallback;
}
