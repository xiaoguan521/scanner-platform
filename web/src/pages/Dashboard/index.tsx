import React, { useMemo, useState } from 'react';
import { Button, Segmented, Tooltip } from 'antd';
import { CheckCircleOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { useDashboardSummary, useRecentTasks } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { FindingStatusTag, Mono, SeverityTag, StatCard, StatusPill, TaskStatusTag, severityMeta } from '../../components/Semantic';
import { AutoGrid, PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { Severity } from '../../theme/palette';
import { taskTargetSummary } from '../Tasks/targets';
import { applicationCoverage, systemCoverage } from '../Tasks/coverage';

const severities: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'];

export const DashboardPage: React.FC = () => {
  const [trendDays, setTrendDays] = useState<7 | 30 | 90>(30);
  const { palette } = useAppTheme();
  const { data: summary, loading: summaryLoading, error: summaryError } = useDashboardSummary(trendDays);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useRecentTasks(6);
  const counts = summary?.findingCounts ?? { vulnerabilities: 0, loginEntries: 0, unknown: 0, version: 0, verified: 0 };
  const distribution = summary?.severityDistribution ?? {};
  const totalFindings = summary?.findingCount ?? 0;
  const riskScore = summary?.riskScore ?? 0;
  const trend = summary?.trend ?? [];
  const maxTrend = Math.max(1, ...trend.map(point => point.count));
  const scoreColor = riskScore >= 70 ? palette.severity.HIGH.solid : riskScore >= 40 ? palette.severity.MEDIUM.solid : palette.success;
  const quickStart = useMemo(() => [
    { key: 'asset', label: '登记第一个资产', done: Boolean(summary?.assetCount), to: '/assets', action: '去登记' },
    { key: 'task', label: '发起第一次扫描', done: Boolean(summary?.hasNonSyntheticTask), to: '/tasks', action: '去扫描' },
    { key: 'result', label: '查看第一份扫描结果', done: Boolean(summary?.hasCompletedScan), to: '/findings', action: '看结果' },
  ], [summary]);
  const showQuickStart = !summaryLoading && Boolean(summary) && quickStart.some(step => !step.done);
  const labelEvery = Math.max(1, Math.ceil(trend.length / 6));
  const barWidth = 600 / Math.max(1, trend.length);
  const muted = { color: palette.textSecondary };
  const rowBorder = `1px solid ${palette.borderSubtle}`;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="态势总览"
        description={`已登记 ${summary?.assetCount ?? 0} 台资产 · 规则版本 ${summary?.currentRule?.version ?? '尚未导入'} · 数据每 10 秒刷新`}
        extra={<Link to="/tasks"><Button type="primary">新建扫描</Button></Link>}
      />
      <CollectionNotice loading={summaryLoading && !summary} error={summaryError || tasksError} />

      {showQuickStart && <Panel title="快速开始" extra={<span style={muted}>完成后自动隐藏</span>}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          {quickStart.map(step => <div key={step.key} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: 12 }}>
            <span style={{ display: 'flex', alignItems: 'center', gap: 8, color: step.done ? palette.textTertiary : palette.text, textDecoration: step.done ? 'line-through' : undefined }}>
              <CheckCircleOutlined style={{ color: step.done ? palette.success : palette.textTertiary }} />{step.label}
            </span>
            {!step.done && <Link to={step.to}><Button size="small" type={step.key === 'asset' ? 'primary' : 'default'}>{step.action}</Button></Link>}
          </div>)}
        </div>
      </Panel>}

      <AutoGrid min={220}>
        <StatCard title="风险评分" value={riskScore} suffix="/ 100" valueColor={scoreColor} meter={riskScore} meterColor={scoreColor} />
        <StatCard title="活动漏洞" value={totalFindings.toLocaleString()} footer={<span style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          <Link to="/findings?severity=CRITICAL" aria-label={`严重 ${summary?.criticalCount ?? 0} 项`}><SeverityTag value="CRITICAL" /> {summary?.criticalCount ?? 0}</Link>
          <Link to="/findings?severity=HIGH" aria-label={`高危 ${summary?.highCount ?? 0} 项`}><SeverityTag value="HIGH" /> {summary?.highCount ?? 0}</Link>
        </span>} />
        <StatCard title="风险资产" value={summary?.riskyAssetCount ?? 0} suffix={`/ ${summary?.assetCount ?? 0} 台`} footer={<Link to="/assets">查看资产台账</Link>} />
        <StatCard title="执行中任务" value={summary?.runningTaskCount ?? 0} suffix={`/ 共 ${summary?.taskCount ?? 0}`} footer={<Link to="/tasks">查看扫描任务</Link>} />
      </AutoGrid>

      <AutoGrid min={420}>
        <Panel title="活动漏洞趋势" extra={<Segmented size="small" value={trendDays} onChange={value => setTrendDays(value as 7 | 30 | 90)} options={[{ label: '7 天', value: 7 }, { label: '30 天', value: 30 }, { label: '90 天', value: 90 }]} />}>
          <svg viewBox="0 0 600 190" width="100%" height="190" role="img" aria-label={`近 ${trendDays} 天每日活动漏洞数，最高 ${maxTrend} 项`}>
            <g stroke={palette.borderSubtle} strokeWidth="1"><line x1="0" y1="20" x2="600" y2="20" /><line x1="0" y1="85" x2="600" y2="85" /><line x1="0" y1="150" x2="600" y2="150" /></g>
            {trend.map((point, index) => {
              const height = Math.max(2, point.count / maxTrend * 130);
              return <rect key={point.date} x={index * barWidth + barWidth * 0.2} y={150 - height} width={barWidth * 0.6} height={height} rx={Math.min(3, barWidth * 0.2)} fill={palette.primary}><title>{`${point.date}：${point.count} 项`}</title></rect>;
            })}
            <g fill={palette.textTertiary} fontSize="11">
              {trend.map((point, index) => index % labelEvery === 0 || index === trend.length - 1 ? <text key={point.date} x={index * barWidth + barWidth / 2} y="172" textAnchor="middle">{point.label}</text> : null)}
              <text x="600" y="14" textAnchor="end">{maxTrend.toLocaleString()}</text>
            </g>
          </svg>
          <span style={{ fontSize: 12, ...muted }}>按每日结束时仍处于活动状态的系统 / Web 漏洞统计</span>
        </Panel>

        <Panel title="严重级别分布" extra={<Link to="/findings">查看漏洞列表</Link>}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div role="img" aria-label={severities.map(level => `${severityMeta[level].label} ${distribution[level] ?? 0}`).join('，')} style={{ display: 'flex', height: 12, borderRadius: 6, overflow: 'hidden', gap: 2, background: palette.borderSubtle }}>
              {severities.map(level => (distribution[level] ?? 0) > 0 && <div key={level} style={{ flex: distribution[level], background: palette.severity[level].solid }} />)}
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, minmax(0, 1fr))', gap: '10px 24px' }}>
              {severities.map(level => <Link key={level} to={`/findings?severity=${level}`} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', color: palette.text }} aria-label={`${severityMeta[level].label} ${distribution[level] ?? 0} 项`}>
                <SeverityTag value={level} /><Mono>{(distribution[level] ?? 0).toLocaleString()}</Mono>
              </Link>)}
            </div>
            <div style={{ paddingTop: 12, borderTop: rowBorder, display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
              <span style={{ fontWeight: 600 }}>检测结果口径</span>
              <span style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 16px', ...muted }}>
                <Link to="/findings?method=version">版本推断 {counts.version}</Link>
                <Link to="/findings?onlyVerified=true">已验证 {counts.verified}</Link>
                <Link to="/findings?risk=login_entry">登录入口 {counts.loginEntries}</Link>
                <Link to="/findings?risk=unknown">未核实类型 {counts.unknown}</Link>
              </span>
            </div>
          </div>
        </Panel>
      </AutoGrid>

      <AutoGrid min={420}>
        <Panel flush title="待处置 · 严重 / 高危" extra={<Link to="/findings?severity=CRITICAL">全部 {summary?.pendingCount ?? 0} 项</Link>}>
          {(summary?.pendingFindings ?? []).length === 0
            ? <div style={{ padding: '24px 20px', ...muted }}>暂无待处置的严重或高危漏洞</div>
            : (summary?.pendingFindings ?? []).map(finding => <div key={finding.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1fr) auto auto', gap: 12, alignItems: 'center', padding: '12px 20px', borderTop: rowBorder, fontSize: 13 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
                <Link to={`/findings?severity=${finding.severity}&businessGroup=${encodeURIComponent(finding.businessGroup)}`} style={{ color: palette.text, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{finding.title}</Link>
                <Mono style={{ ...muted, fontSize: 12 }}>{finding.target}</Mono>
              </div>
              <FindingStatusTag value={finding.status} />
              <SeverityTag value={finding.severity} />
            </div>)}
        </Panel>

        <Panel flush title="风险最高资产" extra={<Link to="/assets">资产台账</Link>}>
          {(summary?.riskAssets ?? []).length === 0
            ? <div style={{ padding: '24px 20px', ...muted }}>暂无活动漏洞资产</div>
            : <div style={{ display: 'flex', flexDirection: 'column', gap: 14, padding: '8px 20px 20px' }}>
              {(summary?.riskAssets ?? []).map(asset => <Link key={asset.id} to={`/findings?assetId=${encodeURIComponent(asset.id)}`} style={{ display: 'grid', gridTemplateColumns: 'minmax(0, 1.2fr) minmax(0, 1fr) 72px', gap: 12, alignItems: 'center', fontSize: 13, color: palette.text }}>
                <span style={{ display: 'flex', flexDirection: 'column', minWidth: 0 }}><span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{asset.name || asset.address}</span><Mono style={{ ...muted, fontSize: 12 }}>{asset.address}</Mono></span>
                <span role="presentation" style={{ height: 8, borderRadius: 4, background: palette.borderSubtle }}><span style={{ display: 'block', height: 8, borderRadius: 4, width: `${Math.min(100, asset.score)}%`, background: asset.score > 80 ? palette.severity.HIGH.solid : palette.primary }} /></span>
                <Mono style={{ textAlign: 'right', ...muted }}>{asset.openCount} 项</Mono>
              </Link>)}
            </div>}
          {(summary?.riskGroups ?? []).length > 0 && <div style={{ borderTop: rowBorder, padding: '12px 20px 16px', display: 'flex', flexDirection: 'column', gap: 8, fontSize: 13 }}>
            <span style={{ fontWeight: 600 }}>风险最高业务组</span>
            {(summary?.riskGroups ?? []).map(group => <Link key={group.name} to={`/findings?businessGroup=${encodeURIComponent(group.name)}`} style={{ display: 'flex', justifyContent: 'space-between', color: palette.text }}>
              <span>{group.name}</span><Mono style={muted}>风险 {group.score} · {group.openCount} 项</Mono>
            </Link>)}
          </div>}
        </Panel>
      </AutoGrid>

      <Panel flush title="近期扫描任务" extra={<Link to="/tasks">全部任务</Link>}>
        <div style={{ overflowX: 'auto' }}>
          {!tasksLoading && tasks.length === 0 && <div style={{ padding: '24px 20px', ...muted }}>尚未发起扫描</div>}
          {tasks.map(task => {
            const target = taskTargetSummary(task);
            const auto = task.engines?.[0] === 'auto';
            const system = systemCoverage(task.systemScanStatus);
            const app = applicationCoverage(task.applicationScanStatus);
            return <div key={task.id} style={{ display: 'grid', gridTemplateColumns: 'minmax(180px, 1.3fr) minmax(0, 2fr) 120px', gap: 16, alignItems: 'center', padding: '14px 20px', borderTop: rowBorder, fontSize: 13, minWidth: 640 }}>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><Mono>{target.primary}</Mono><span style={{ ...muted, fontSize: 12 }}>{new Date(task.createdAt).toLocaleString()} · {target.detail}</span></div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                {auto ? <>
                  <Tooltip title={task.systemScanStatus}><span><StatusPill tone={system.tone}>系统包 · {system.label}</StatusPill></span></Tooltip>
                  <StatusPill tone={app.tone}>应用依赖 · {app.label}</StatusPill>
                  <StatusPill tone="neutral">HTTP 服务 · {task.serviceResults?.filter(item => item.kind === 'HTTP').length ?? 0}</StatusPill>
                </> : <StatusPill tone="neutral">{task.synthetic ? '模拟任务' : task.inputPath ? '离线输入扫描' : (task.engines ?? []).join(' / ')}</StatusPill>}
              </div>
              <span style={{ justifySelf: 'end' }}><TaskStatusTag value={task.status} /></span>
            </div>;
          })}
        </div>
      </Panel>
    </div>
  );
};
