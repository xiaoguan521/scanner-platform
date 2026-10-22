import type { Tone } from '../../theme/palette';

export const applicationStatuses: Record<string, string> = { not_configured: '未配置部署目录', not_started: '尚未开始', port_out_of_scope: '未采集：SSH 端口不在本次范围', collecting: '采集中', collection_failed: '采集未完成', scanning: '分析中', analysis_failed: '分析未完成', completed: '已完成' };

const applicationTones: Record<string, Tone> = { completed: 'ok', collecting: 'running', scanning: 'running', collection_failed: 'error', analysis_failed: 'error' };

export function applicationCoverage(status?: string): { tone: Tone; label: string } {
  if (!status) return { tone: 'neutral', label: '未记录' };
  return { tone: applicationTones[status] ?? 'warning', label: applicationStatuses[status] ?? '状态未知' };
}

// The Server reports system-package coverage as a sentence; completed runs
// start with "已", skipped or failed runs with "未采集" / "未完成".
export function systemCoverage(status?: string): { tone: Tone; label: string } {
  if (!status) return { tone: 'neutral', label: '未记录' };
  if (status.startsWith('已')) return { tone: 'ok', label: '已完成' };
  if (status.startsWith('未完成')) return { tone: 'error', label: '分析未完成' };
  return { tone: 'warning', label: status.replace(/^未采集：/, '') };
}
