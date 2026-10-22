import type { ScanTask } from '../../types';
import type { Tone } from '../../theme/palette';
import { progressPhases } from './progress';
import { applicationCoverage, systemCoverage } from './coverage';

export type PhaseState = 'done' | 'running' | 'failed' | 'skipped' | 'pending';
export type PhaseView = { key: string; name: string; state: PhaseState; detail: string };

const autoPhases = ['tcp_probe', 'service_identification', 'http_scan', 'ssh_collection', 'trivy_scan', 'application_scan'] as const;
export const phaseTones: Record<PhaseState, Tone> = { done: 'ok', running: 'running', failed: 'error', skipped: 'warning', pending: 'neutral' };
export const phaseLabels: Record<PhaseState, string> = { done: '已完成', running: '进行中', failed: '未完成', skipped: '已跳过', pending: '未开始' };

type PhaseTask = Pick<ScanTask, 'status' | 'engines' | 'progress' | 'portProbePorts' | 'portProbeResults' | 'serviceResults' | 'systemScanStatus' | 'systemScanCode' | 'applicationScanStatus' | 'findingCount'>;

/** Per-phase state of an automatic scan, derived from status, progress and coverage reports. */
export function taskPhases(task: PhaseTask): PhaseView[] {
  if (task.engines?.[0] !== 'auto') return [];
  const current = task.progress ? autoPhases.indexOf(task.progress.phase as typeof autoPhases[number]) : -1;
  const terminal = ['COMPLETED', 'FAILED', 'CANCELED'].includes(task.status);
  const system = systemCoverage(task.systemScanStatus, task.systemScanCode);
  const app = applicationCoverage(task.applicationScanStatus);
  const http = task.serviceResults?.filter(item => item.kind === 'HTTP').length ?? 0;
  const details: Record<string, string> = {
    tcp_probe: `${task.portProbeResults?.length ?? 0} / ${task.portProbePorts?.length ?? 0} 个端口开放`,
    service_identification: `识别出 ${http} 个 HTTP(S) 服务`,
    http_scan: http ? `检查 ${http} 个服务` : '没有可检查的 HTTP(S) 服务',
    ssh_collection: system.tone === 'ok' ? '已通过 SSH 采集软件包清单' : system.label,
    trivy_scan: system.tone === 'ok' ? '已用本地漏洞库完成分析' : system.label,
    application_scan: app.label,
  };
  return autoPhases.map((key, index) => {
    let state: PhaseState = 'pending';
    if (task.status === 'COMPLETED') state = 'done';
    else if (current >= 0 && index < current) state = 'done';
    else if (index === current) state = terminal ? 'failed' : task.status === 'RUNNING' ? 'running' : 'pending';
    // Coverage reports override the generic state for the optional phases.
    if ((key === 'ssh_collection' || key === 'trivy_scan') && task.systemScanStatus && (state === 'done' || terminal)) {
      state = system.tone === 'ok' ? 'done' : system.tone === 'error' ? 'failed' : 'skipped';
    }
    if (key === 'application_scan' && task.applicationScanStatus && (state === 'done' || terminal)) {
      state = app.tone === 'ok' ? 'done' : app.tone === 'error' ? 'failed' : app.tone === 'running' ? 'running' : 'skipped';
    }
    const progress = index === current && task.progress && task.progress.total > 0 ? `${task.progress.completed.toLocaleString()} / ${task.progress.total.toLocaleString()}` : '';
    return { key, name: progressPhases[key] ?? key, state, detail: state === 'running' && progress ? progress : state === 'pending' ? '等待执行' : details[key] };
  });
}

export function isTerminalTask(status: string): boolean {
  return ['COMPLETED', 'FAILED', 'CANCELED'].includes(status);
}
