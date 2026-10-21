import React from 'react';
import { Card, Skeleton, Statistic, Tag, Typography } from 'antd';
import type { CSSProperties, ReactNode } from 'react';
import type { StatisticProps, TagProps } from 'antd';
import type { FindingSeverity, FindingStatus, TaskStatus } from '../types';

type TagColor = TagProps['color'];

export type SemanticMeta = {
  color: TagColor;
  label: string;
};

export const severityMeta: Record<FindingSeverity, SemanticMeta> = {
  CRITICAL: { color: 'magenta', label: '严重 (Critical)' },
  HIGH: { color: 'red', label: '高危 (High)' },
  MEDIUM: { color: 'orange', label: '中危 (Medium)' },
  LOW: { color: 'blue', label: '低危 (Low)' },
  INFO: { color: 'default', label: '信息 (Info)' },
};

export const findingStatusMeta: Record<FindingStatus, SemanticMeta> = {
  OPEN: { color: 'error', label: '待修复 (OPEN)' },
  REOPENED: { color: 'error', label: '重新出现 (REOPENED)' },
  IN_PROGRESS: { color: 'processing', label: '修复中 (IN_PROGRESS)' },
  FIXED: { color: 'success', label: '已修复 (FIXED)' },
  FALSE_POSITIVE: { color: 'default', label: '误报静默 (FALSE_POSITIVE)' },
  ACCEPTED_RISK: { color: 'warning', label: '接受风险 (ACCEPTED_RISK)' },
};

export const taskStatusMeta: Record<TaskStatus, SemanticMeta> = {
  PENDING: { color: 'default', label: '待领取' },
  RUNNING: { color: 'processing', label: '执行中' },
  WAITING_WINDOW: { color: 'warning', label: '等待时间窗' },
  PAUSED: { color: 'default', label: '已暂停' },
  PAUSED_WINDOW: { color: 'default', label: '窗口结束，等待恢复' },
  COMPLETED: { color: 'success', label: '已完成' },
  CANCELED: { color: 'default', label: '已取消' },
  FAILED: { color: 'error', label: '失败' },
};

export const scheduleStatusMeta: Record<string, SemanticMeta> = {
  ...taskStatusMeta,
  DELETED: { color: 'default', label: '任务记录已删除' },
};

function resolveMeta<T extends string>(value: T, metadata: Record<string, SemanticMeta>): SemanticMeta {
  return metadata[value] ?? { color: 'default', label: value };
}

export const SeverityTag: React.FC<{ value: FindingSeverity | string }> = ({ value }) => {
  const meta = resolveMeta(value, severityMeta);
  return <Tag color={meta.color}>{meta.label}</Tag>;
};

export const FindingStatusTag: React.FC<{ value: FindingStatus | string }> = ({ value }) => {
  const meta = resolveMeta(value, findingStatusMeta);
  return <Tag color={meta.color}>{meta.label}</Tag>;
};

export const TaskStatusTag: React.FC<{ value: TaskStatus | string }> = ({ value }) => {
  const meta = resolveMeta(value, taskStatusMeta);
  return <Tag color={meta.color}>{meta.label}</Tag>;
};

export const ScheduleStatusTag: React.FC<{ value: string }> = ({ value }) => {
  const meta = resolveMeta(value, scheduleStatusMeta);
  return <Tag color={meta.color}>{meta.label}</Tag>;
};

export const StatCard: React.FC<{
  title: ReactNode;
  value: StatisticProps['value'];
  suffix?: ReactNode;
  prefix?: ReactNode;
  valueStyle?: CSSProperties;
  footer?: ReactNode;
}> = ({ title, value, suffix, prefix, valueStyle, footer }) => (
  <Card bordered={false}>
    <Statistic title={title} value={value} suffix={suffix} prefix={prefix} valueStyle={valueStyle} />
    {footer && <div style={{ marginTop: 8, fontSize: 12 }}><Typography.Text type="secondary">{footer}</Typography.Text></div>}
  </Card>
);

export const LoadingSkeleton: React.FC<{ rows?: number; label?: string }> = ({ rows = 3, label = '正在加载…' }) => (
  <div role="status" aria-label={label} style={{ padding: '8px 0' }}>
    <Skeleton active title paragraph={{ rows }} />
  </div>
);
