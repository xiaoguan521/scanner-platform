import type { Tone } from '../../theme/palette';

export const applicationStatuses: Record<string, string> = { not_configured: '未配置部署目录', not_started: '尚未开始', port_out_of_scope: '未采集：SSH 端口不在本次范围', collecting: '采集中', collection_failed: '采集未完成', scanning: '分析中', analysis_failed: '分析未完成', completed: '已完成' };

const applicationTones: Record<string, Tone> = { completed: 'ok', collecting: 'running', scanning: 'running', collection_failed: 'error', analysis_failed: 'error' };

const applicationHints: Record<string, string> = {
  not_configured: '在 Worker 的 SSH 档案中填写 Java / Go 应用部署目录后重新扫描。',
  port_out_of_scope: '把配置的 SSH 端口加入本次扫描范围后重新扫描。',
  collection_failed: '检查 Worker 到目标的 SSH 连接和部署目录权限。',
  analysis_failed: '检查 Worker 本地日志中的依赖分析错误。',
};

export type Coverage = { tone: Tone; label: string; hint?: string };

export function applicationCoverage(status?: string): Coverage {
  if (!status) return { tone: 'neutral', label: '未记录' };
  return { tone: applicationTones[status] ?? 'warning', label: applicationStatuses[status] ?? '状态未知', hint: applicationHints[status] };
}

const systemCodes: Record<string, Coverage> = {
  completed: { tone: 'ok', label: '已完成' },
  not_started: { tone: 'warning', label: '未开始', hint: '任务在系统包检查前已失败或中止，请查看任务日志。' },
  not_configured: { tone: 'warning', label: '未配置 SSH 采集', hint: '在资产列表点「SSH 采集配置」生成该主机的 Worker SSH 档案，放到 Worker 并核对 known_hosts 后重新扫描。' },
  port_out_of_scope: { tone: 'warning', label: 'SSH 端口不在范围', hint: '把配置的 SSH 端口（常见为 22）加入本次扫描范围。' },
  port_closed: { tone: 'warning', label: 'SSH 端口未开放', hint: '确认目标 SSH 服务正在监听且网络可达。' },
  client_missing: { tone: 'error', label: 'Worker 缺少 SSH 客户端', hint: '在 Worker 上安装 OpenSSH 客户端。' },
  host_key_mismatch: { tone: 'error', label: '主机指纹不匹配', hint: '核对目标主机指纹后更新 Worker 本地 known_hosts。' },
  auth_failed: { tone: 'error', label: 'SSH 认证失败', hint: '检查 Worker 上配置的密钥或 SSH Agent。' },
  python_missing: { tone: 'warning', label: '目标缺少 Python 3', hint: '目标服务器需要可用的 Python 3 才能采集软件包。' },
  collection_failed: { tone: 'error', label: '采集失败', hint: '检查网络与目标系统，查看 Worker 日志。' },
  invalid_snapshot: { tone: 'error', label: '快照校验失败', hint: '重新扫描；若仍失败，请查看 Worker 日志。' },
  trivy_unavailable: { tone: 'error', label: '漏洞库不可用', hint: '检查 Worker 上的 Trivy 引擎和本地漏洞库。' },
  unsupported_os: { tone: 'warning', label: '发行版未适配', hint: '目标 Linux 发行版暂无可用的漏洞源。' },
  trivy_failed: { tone: 'error', label: '分析失败', hint: '查看 Worker 本地日志中的 Trivy 错误。' },
};

// Prefer the Server's stable code; older Servers only send the sentence.
export function systemCoverage(status?: string, code?: string): Coverage {
  if (code && systemCodes[code]) return systemCodes[code];
  if (!status) return { tone: 'neutral', label: '未记录' };
  if (status.startsWith('已')) return systemCodes.completed;
  if (status.startsWith('未完成')) return { tone: 'error', label: '分析未完成', hint: status };
  return { tone: 'warning', label: status.replace(/^未采集：/, ''), hint: status };
}
