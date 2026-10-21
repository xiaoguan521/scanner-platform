import type { ScanTask } from '../../types';

export const progressPhases: Record<string, string> = {
  tcp_probe: 'TCP 端口探测',
  service_identification: '服务识别',
  http_scan: 'HTTP 基线扫描',
  ssh_collection: 'SSH 信息采集',
  trivy_scan: 'Trivy 系统包分析',
  application_scan: '应用依赖分析',
  engine_scan: '引擎扫描',
};

export const progressBands: Record<string, [number, number]> = {
  tcp_probe: [0, 55],
  service_identification: [55, 65],
  http_scan: [65, 78],
  ssh_collection: [78, 88],
  trivy_scan: [88, 94],
  application_scan: [94, 100],
  engine_scan: [0, 100],
};

export function progressPercent(progress: NonNullable<ScanTask['progress']>): number {
  const band = progressBands[progress.phase] ?? [0, 100];
  if (progress.total <= 0) return band[0];
  return Math.max(band[0], Math.min(band[1], Math.floor(band[0] + (band[1] - band[0]) * progress.completed / progress.total)));
}
