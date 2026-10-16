import type { ScanTask } from '../types';

export async function createSyntheticTask(): Promise<ScanTask> {
  const response = await fetch('/api/v1/tasks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ synthetic: true }),
  });
  if (!response.ok) throw new Error('创建模拟任务失败');
  return response.json() as Promise<ScanTask>;
}
