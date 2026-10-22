import React from 'react';
import { Skeleton } from 'antd';
import type { CSSProperties, ReactNode } from 'react';
import type { FindingSeverity, FindingStatus, NotificationSeverity, TaskStatus, UserRole } from '../types';
import { useAppTheme } from '../context/ThemeContext';
import { monoFamily, type Severity, type Tone } from '../theme/palette';

export type SemanticMeta = {
  tone: Tone;
  label: string;
};

export const severityMeta: Record<FindingSeverity, { label: string }> = {
  CRITICAL: { label: '严重' },
  HIGH: { label: '高危' },
  MEDIUM: { label: '中危' },
  LOW: { label: '低危' },
  INFO: { label: '信息' },
};

export const findingStatusMeta: Record<FindingStatus, SemanticMeta> = {
  OPEN: { tone: 'error', label: '待修复' },
  REOPENED: { tone: 'error', label: '重新出现' },
  IN_PROGRESS: { tone: 'running', label: '修复中' },
  FIXED: { tone: 'ok', label: '已修复' },
  FALSE_POSITIVE: { tone: 'neutral', label: '误报' },
  ACCEPTED_RISK: { tone: 'warning', label: '接受风险' },
};

export const taskStatusMeta: Record<TaskStatus, SemanticMeta> = {
  PENDING: { tone: 'neutral', label: '待领取' },
  RUNNING: { tone: 'running', label: '执行中' },
  WAITING_WINDOW: { tone: 'warning', label: '等待时间窗' },
  PAUSED: { tone: 'neutral', label: '已暂停' },
  PAUSED_WINDOW: { tone: 'neutral', label: '窗口结束，等待恢复' },
  COMPLETED: { tone: 'ok', label: '已完成' },
  CANCELED: { tone: 'neutral', label: '已取消' },
  FAILED: { tone: 'error', label: '失败' },
};

export const scheduleStatusMeta: Record<string, SemanticMeta> = {
  ...taskStatusMeta,
  DELETED: { tone: 'neutral', label: '任务记录已删除' },
};

export const roleNames: Record<UserRole, string> = {
  admin: '系统管理员',
  security_engineer: '安全工程师',
  ops_approver: '运维审批人',
  viewer: '只读观察员',
};

export const notificationSeverityMeta: Record<NotificationSeverity, SemanticMeta> = {
  info: { tone: 'running', label: '信息' },
  warning: { tone: 'warning', label: '提醒' },
  error: { tone: 'error', label: '需要处理' },
};

function resolveMeta(value: string, metadata: Record<string, SemanticMeta>): SemanticMeta {
  return metadata[value] ?? { tone: 'neutral', label: value };
}

const pillStyle: CSSProperties = {
  display: 'inline-flex', alignItems: 'center', gap: 6, padding: '1px 10px', borderRadius: 999,
  fontSize: 12, fontWeight: 500, lineHeight: '20px', whiteSpace: 'nowrap',
};
const dotStyle: CSSProperties = { width: 6, height: 6, borderRadius: '50%', background: 'currentColor', flex: '0 0 auto' };

/** A rounded status label with a leading dot; colour comes from the theme tone. */
export const StatusPill: React.FC<{ tone: Tone; children: ReactNode; title?: string }> = ({ tone, children, title }) => {
  const { palette } = useAppTheme();
  const colors = palette.tone[tone];
  return <span title={title} style={{ ...pillStyle, color: colors.fg, background: colors.bg }}><span aria-hidden="true" style={dotStyle} />{children}</span>;
};

export const SeverityTag: React.FC<{ value: FindingSeverity | string }> = ({ value }) => {
  const { palette } = useAppTheme();
  const colors = palette.severity[value as Severity] ?? palette.severity.INFO;
  const label = severityMeta[value as FindingSeverity]?.label ?? value;
  return <span style={{ ...pillStyle, fontWeight: 600, padding: '1px 8px', color: colors.fg, background: colors.bg }}><span aria-hidden="true" style={dotStyle} />{label}</span>;
};

export const FindingStatusTag: React.FC<{ value: FindingStatus | string }> = ({ value }) => {
  const meta = resolveMeta(value, findingStatusMeta);
  return <StatusPill tone={meta.tone}>{meta.label}</StatusPill>;
};

export const TaskStatusTag: React.FC<{ value: TaskStatus | string }> = ({ value }) => {
  const meta = resolveMeta(value, taskStatusMeta);
  return <StatusPill tone={meta.tone}>{meta.label}</StatusPill>;
};

export const ScheduleStatusTag: React.FC<{ value: string }> = ({ value }) => {
  const meta = resolveMeta(value, scheduleStatusMeta);
  return <StatusPill tone={meta.tone}>{meta.label}</StatusPill>;
};

export const NotificationSeverityTag: React.FC<{ value: NotificationSeverity | string }> = ({ value }) => {
  const meta = resolveMeta(value, notificationSeverityMeta);
  return <StatusPill tone={meta.tone}>{meta.label}</StatusPill>;
};

/** Monospace text for addresses, CVE IDs, versions and other identifiers. */
export const Mono: React.FC<{ children: ReactNode; style?: CSSProperties; title?: string }> = ({ children, style, title }) => (
  <span title={title} style={{ fontFamily: monoFamily, fontVariantNumeric: 'tabular-nums', ...style }}>{children}</span>
);

/** Key metric tile: label, large tabular value, optional meter and footer. */
export const StatCard: React.FC<{
  title: ReactNode;
  value: ReactNode;
  suffix?: ReactNode;
  valueColor?: string;
  meter?: number;
  meterColor?: string;
  footer?: ReactNode;
}> = ({ title, value, suffix, valueColor, meter, meterColor, footer }) => {
  const { palette } = useAppTheme();
  return (
    <div style={{ padding: 20, borderRadius: 12, background: palette.bgContainer, border: `1px solid ${palette.borderSubtle}`, display: 'flex', flexDirection: 'column', gap: 10, minWidth: 0 }}>
      <span style={{ fontSize: 13, color: palette.textSecondary }}>{title}</span>
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, minWidth: 0 }}>
        <span style={{ fontSize: 32, lineHeight: 1.1, fontWeight: 700, fontVariantNumeric: 'tabular-nums', color: valueColor ?? palette.text, overflowWrap: 'anywhere' }}>{value}</span>
        {suffix && <span style={{ color: palette.textTertiary }}>{suffix}</span>}
      </div>
      {meter !== undefined && <div role="presentation" style={{ height: 6, borderRadius: 3, background: palette.borderSubtle }}><div style={{ width: `${Math.max(0, Math.min(100, meter))}%`, height: 6, borderRadius: 3, background: meterColor ?? palette.primary }} /></div>}
      {footer && <div style={{ fontSize: 13, color: palette.textSecondary }}>{footer}</div>}
    </div>
  );
};

export const LoadingSkeleton: React.FC<{ rows?: number; label?: string }> = ({ rows = 3, label = '正在加载…' }) => (
  <div role="status" aria-label={label} style={{ padding: '8px 0' }}>
    <Skeleton active title paragraph={{ rows }} />
  </div>
);
