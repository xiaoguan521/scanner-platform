import React from 'react';
import { Button, Card, Space, Typography } from 'antd';
import { DataTable } from '../../components/DataState';
import { StatusPill } from '../../components/Semantic';
import { formatTime } from '../../utils/time';
import type { Schedule } from '../../types';

/** Saved schedules; every action is handled by the task page. */
export const ScheduleTable: React.FC<{
  schedules: Schedule[];
  loading: boolean;
  canWrite: boolean;
  onToggle: (schedule: Schedule) => void;
  onRunNow: (schedule: Schedule) => void;
  onHistory: (schedule: Schedule) => void;
  onEdit: (schedule: Schedule) => void;
  onRemove: (schedule: Schedule) => void;
}> = ({ schedules, loading, canWrite, onToggle, onRunNow, onHistory, onEdit, onRemove }) => (
  <Card title="定时任务" extra={<Typography.Text type="secondary">间隔 0 表示仅运行一次；错过的重复任务不会集中补跑</Typography.Text>}>
    <DataTable<Schedule> dataSource={schedules} rowKey="id" loading={loading} tableLayout="fixed" scroll={{ x: 1050 }} locale={{ emptyText: '暂无定时任务。创建时填写首次运行时间；间隔 0 表示只运行一次。' }} columns={[
      { title: '名称', dataIndex: 'name' },
      { title: '下一次运行', dataIndex: 'nextRun', render: (v: string) => formatTime(v) },
      { title: '重复间隔', dataIndex: 'intervalMinutes', render: (v: number) => v ? `${v} 分钟` : '仅一次' },
      { title: '状态', key: 'enabled', render: (_, s) => <StatusPill tone={s.enabled ? 'ok' : 'neutral'}>{s.enabled ? '启用' : '停用 / 单次已触发'}</StatusPill> },
      { title: '最近任务 / 错误', key: 'last', render: (_, s) => s.lastError || s.lastTaskId || '尚未触发' },
      { title: '操作', key: 'actions', width: 360, render: (_, s) => <Space wrap>
        <Button size="small" disabled={!canWrite} onClick={() => onToggle(s)}>{s.enabled ? '停用' : '启用'}</Button>
        <Button size="small" disabled={!canWrite} onClick={() => onRunNow(s)}>手动运行</Button>
        <Button size="small" onClick={() => onHistory(s)}>历史运行</Button>
        <Button size="small" disabled={!canWrite} onClick={() => onEdit(s)}>修改</Button>
        <Button size="small" danger disabled={!canWrite} onClick={() => onRemove(s)}>删除</Button>
      </Space> },
    ]}/>
  </Card>
);
