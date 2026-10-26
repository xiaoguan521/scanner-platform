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
  const finished = task.status === 'COMPLETED';
  // Each phase works on the result of the one before: ports probed -> open
  // ports identified -> HTTP(S) services checked. Show every phase as n / m.
  const counts = (key: string, index: number): { completed: number; total: number } | null => {
    if (index === current && task.progress) return task.progress;
    const recorded = task.progress?.phases?.[key];
    if (recorded) return recorded;
    if (key === 'tcp_probe' && task.portProbePorts && (finished || current > index)) return { completed: task.portProbePorts.length, total: task.portProbePorts.length };
    if (key === 'service_identification' && task.portProbeResults && (finished || current > index)) return { completed: task.portProbeResults.length, total: task.portProbeResults.length };
    if (key === 'http_scan' && task.serviceResults && (finished || current > index)) return { completed: http, total: http };
    // http_scan reports nothing when identification found no HTTP(S) service.
    if (key === 'http_scan' && current > index) return { completed: 0, total: 0 };
    return null;
  };
  const unit: Record<string, string> = { tcp_probe: '个端口', service_identification: '个开放端口', http_scan: '个 HTTP(S) 服务' };
  const openCount = (): number | null => task.portProbeResults?.length ?? task.progress?.openPorts?.length ?? task.progress?.phases?.service_identification?.total ?? (current === 1 ? task.progress?.total ?? null : null);
  const details: Record<string, string> = {
    tcp_probe: '',
    service_identification: '',
    http_scan: '',
    ssh_collection: system.tone === 'ok' ? '已通过 SSH 采集软件包清单' : system.label,
    trivy_scan: system.tone === 'ok' ? '已用本地漏洞库完成分析' : system.label,
    application_scan: app.label,
  };
  return autoPhases.map((key, index) => {
    let state: PhaseState = 'pending';
    if (task.status === 'COMPLETED') state = 'done';
    else if (current >= 0 && index < current) state = 'done';
    else if (index === current) state = terminal ? 'failed' : task.status === 'RUNNING' ? 'running' : 'pending';
    // No open port: the scan ends after identification, later phases never start.
    const noOpen = finished && task.portProbeResults?.length === 0 && index >= 2;
    if (noOpen) state = 'skipped';
    // Coverage reports override the generic state for the optional phases.
    if ((key === 'ssh_collection' || key === 'trivy_scan') && task.systemScanStatus && (state === 'done' || terminal) && !noOpen) {
      state = system.tone === 'ok' ? 'done' : system.tone === 'error' ? 'failed' : 'skipped';
    }
    if (key === 'application_scan' && task.applicationScanStatus && (state === 'done' || terminal) && !noOpen) {
      state = app.tone === 'ok' ? 'done' : app.tone === 'error' ? 'failed' : app.tone === 'running' ? 'running' : 'skipped';
    }
    const count = unit[key] ? counts(key, index) : null;
    let detail = state === 'pending' ? '等待执行' : noOpen ? '没有开放端口，已跳过' : details[key];
    if (count && state !== 'pending' && !noOpen) {
      detail = `${count.completed.toLocaleString()} / ${count.total.toLocaleString()} ${unit[key]}`;
      const open = key === 'tcp_probe' ? openCount() : null;
      if (open !== null && state !== 'running') detail += `，${open.toLocaleString()} 个开放`;
    } else if (state !== 'pending' && !noOpen && unit[key]) detail = '统计中';
    return { key, name: progressPhases[key] ?? key, state, detail };
  });
}

/** Open-port and HTTP(S)-service counts known so far; null until the phase producing them has started. */
export function liveScanCounts(task: Pick<ScanTask, 'progress'>): { open: number | null; http: number | null; openPorts: number[]; httpPorts: number[] } {
  const progress = task.progress;
  const count = (phase: string): number | null => progress?.phase === phase ? progress.total : progress?.phases?.[phase]?.total ?? null;
  const openPorts = progress?.openPorts ?? [];
  const httpPorts = progress?.httpPorts ?? [];
  return { open: openPorts.length ? openPorts.length : count('service_identification'), http: httpPorts.length ? httpPorts.length : count('http_scan'), openPorts, httpPorts };
}

export function isTerminalTask(status: string): boolean {
  return ['COMPLETED', 'FAILED', 'CANCELED'].includes(status);
}
