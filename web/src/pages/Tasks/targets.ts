import type { ScanTask } from '../../types';

type TaskTargetFields = Pick<ScanTask, 'engines' | 'targetCount' | 'skippedTargets' | 'portProbePorts' | 'inputPath' | 'chunks'>;

// The list shows the searchable target (address or offline input path) plus a
// short scale line, so the task search box matches a visible column.
export function taskTargetSummary(task: TaskTargetFields): { primary: string; detail: string } {
  const targets = [...new Set(task.chunks?.flatMap(chunk => chunk.targets ?? []) ?? [])];
  const engine = task.engines?.[0];
  if (task.inputPath && targets.length === 0) return { primary: task.inputPath, detail: '离线输入' };
  const primary = targets.length === 0 ? '—' : targets.length === 1 ? targets[0] : `${targets[0]} 等 ${targets.length} 个`;
  if (engine === 'port-probe' || engine === 'auto') {
    return { primary, detail: `${task.targetCount} 台主机 / ${task.portProbePorts?.length ?? 0} 端口` };
  }
  const skipped = task.skippedTargets?.length ?? 0;
  return { primary, detail: skipped ? `${task.targetCount} 个目标，跳过 ${skipped}` : `${task.targetCount} 个目标` };
}
