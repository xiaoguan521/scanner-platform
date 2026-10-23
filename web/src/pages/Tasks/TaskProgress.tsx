import React from 'react';
import { Progress, Space, Spin, Typography } from 'antd';
import { progressPercent, progressPhases } from './progress';
import type { ScanTask } from '../../types';

/** Progress cell for the task table and the detail drawer. */
export function renderTaskProgress(task: ScanTask): React.ReactNode {
  const current = task.progress;
  if (task.status === 'COMPLETED') return <div><Typography.Text type="success">扫描完成</Typography.Text><Progress percent={100} size="small" status="success"/></div>;
  if (current) {
    const percent = progressPercent(current);
    const status = task.status === 'FAILED' || task.status === 'CANCELED' ? 'exception' : task.status === 'RUNNING' ? 'active' : 'normal';
    const detail = current.total > 0 ? ` ${current.completed.toLocaleString()} / ${current.total.toLocaleString()}` : ' 进行中';
    return <div><Typography.Text>{progressPhases[current.phase] ?? '扫描'}{detail}</Typography.Text><Progress percent={percent} size="small" status={status}/></div>;
  }
  if (task.status === 'RUNNING') return <Space size={6}><Spin size="small"/><Typography.Text>Worker 执行中，等待进度上报</Typography.Text></Space>;
  return `${task.completedChunks} / ${task.totalChunks}`;
}
