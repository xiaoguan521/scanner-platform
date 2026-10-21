# API 错误码

所有 JSON API 的失败响应使用统一结构：

```json
{
  "code": "invalid_input",
  "error": "invalid_input",
  "message": "输入无效",
  "hint": "请检查请求参数后重试",
  "request_id": "<server-generated-id>"
}
```

`code` 是新客户端必须使用的稳定机器码。`error` 是迁移期间保留的兼容别名，值始终与 `code` 相同；新代码不得依赖它。`message` 面向当前界面语言，`hint` 只给出安全的下一步动作，不包含凭据、目标证据、原始请求/响应或引擎输出。`request_id` 同时通过 `X-Request-ID` 响应头返回，可用于关联 Server 日志。客户端不得把请求编号当作认证凭据。

## 常用错误码

| 错误码 | HTTP 常见状态 | 含义与处理 |
| --- | ---: | --- |
| `invalid_json` / `extra_json` / `json_required` | 400 / 415 | 请求体不是一个符合接口要求的 JSON 对象 |
| `invalid_input` | 400 | 字段、范围或组合校验失败 |
| `unauthorized` / `invalid_credentials` | 401 | 当前会话无效或登录凭据错误 |
| `forbidden` / `admin_required` | 403 | 当前账号没有该操作权限 |
| `request_header_required` | 403 | 写请求缺少 `X-Requested-With: XMLHttpRequest` |
| `not_found` / `task_not_found` | 404 | 资源不存在或已被删除 |
| `task_conflict` / `lease_conflict` | 409 | 任务、租约或结果与当前状态不一致 |
| `task_not_terminal` / `task_has_findings` / `task_state_conflict` | 409 | 任务当前状态不允许归档、删除、暂停或恢复 |
| `approval_conflict` / `port_request_conflict` | 409 | 审批、端口或授权状态已发生变化 |
| `node_revoked` / `node_kind_mismatch` | 403 | 节点已吊销或节点类型与接口不匹配 |
| `node_auth_required` / `node_identity_mismatch` | 401 | 节点令牌缺失、无效或身份不一致 |
| `node_registry_unavailable` | 503 | 节点状态注册表暂不可用 |
| `backend_capability_unavailable` | 503 | 当前存储后端没有实现请求的能力 |
| `db_error` / `database_error` | 500 | Server 持久化操作失败；按 `request_id` 查询日志 |
| `rate_limited` | 429 | 登录或接口限流生效，稍后重试 |
| `not_implemented` | 501 | 当前部署仍处于早期阶段，接口尚未开放 |

## 资源校验类错误

资产、授权、任务、漏洞、报告、规则、通知、计划和知识库接口会使用带资源前缀的 `invalid_*`、`*_pagination_unavailable`、`*_conflict` 或 `*_not_found` 错误码。错误码本身是公开的接口元数据；具体字段原因放在 `message`，可操作建议放在 `hint`。服务端不通过错误响应回显目标地址、凭据、原始引擎输出或未授权范围。

当前资源错误码包括：

```text
already_initialized, asset_exists, asset_import_conflict,
asset_import_history_unavailable, asset_import_limit, asset_import_unavailable,
asset_in_use_remove_authorization_first, asset_pagination_unavailable,
assignee_id_required, authentication_required, bundle_required, business_group_exists,
business_group_unavailable, csv_required, custom_rule_conflict, custom_rule_id_mismatch,
enabled_required, invalid_approval, invalid_archive_filter, invalid_asset,
invalid_asset_csv, invalid_asset_export_filter, invalid_asset_import_history_list_query,
invalid_asset_list_query, invalid_audit_filter, invalid_business_group,
invalid_business_group_list_query, invalid_custom_rule, invalid_custom_rule_list_query,
invalid_dashboard_trend_days, invalid_finding_list_query, invalid_input,
invalid_knowledge_list_query, invalid_lease, invalid_node, invalid_node_id,
invalid_node_list_query, invalid_node_registration, invalid_node_status,
invalid_notification, invalid_notification_delivery_query, invalid_notification_filter,
invalid_notification_list_query, invalid_notification_settings, invalid_or_oversized_zip,
invalid_password, invalid_port, invalid_port_request, invalid_port_request_list_query,
invalid_report, invalid_report_list_query, invalid_rule_job_list_query,
invalid_rule_list_query, invalid_rule_readiness, invalid_rule_version,
invalid_scan_plan, invalid_schedule_run_pagination, invalid_scope_list_query,
invalid_system_settings, invalid_task_export_format, invalid_task_list_query,
invalid_task_progress, invalid_user, invalid_worker, knowledge_id_mismatch,
node_already_registered, node_issuance_unavailable, node_not_registered,
notification_not_found, oversized_zip, port_request_pagination_unavailable,
reachability_check_failed, report_conflict, report_not_found, scan_plan_conflict,
scope_pagination_unavailable, setup_unavailable, template_id_mismatch, user_exists
```

新增错误码必须同时更新本文、OpenAPI 的 `APIError` 说明和前端错误映射；不得用 HTTP 状态文本替代稳定错误码。
