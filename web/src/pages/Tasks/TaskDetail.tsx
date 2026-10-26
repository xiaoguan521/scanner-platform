import React from 'react';
import { Alert, Button, Spin, Tooltip } from 'antd';
import { DownloadOutlined } from '@ant-design/icons';
import { Link } from 'react-router-dom';
import { DataTable } from '../../components/DataState';
import { Mono, StatusPill, TaskStatusTag } from '../../components/Semantic';
import { AutoGrid, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { ScanTask, TaskLog } from '../../types';
import { applicationCoverage, applicationStatuses, systemCoverage, type Coverage } from './coverage';
import { isTerminalTask, liveScanCounts, phaseLabels, phaseTones, taskPhases } from './phases';
import { compressPorts, presetLabels, showRanges } from './policy';
import { formatTime } from '../../utils/time';
import { taskTargetSummary } from './targets';

const intensityLabels: Record<string, string> = { gentle: '温和', standard: '标准', aggressive: '积极' };
const fenceLabels: Record<string, string> = { ENFORCED: '已启用', NOT_SUPPORTED: '当前平台不支持', NOT_VERIFIED: '未验证' };
const weekdays = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];

function duration(start?: string, end?: string): string {
  if (!start || !end) return '';
  const seconds = Math.max(0, Math.round((Date.parse(end) - Date.parse(start)) / 1000));
  if (!Number.isFinite(seconds)) return '';
  const minutes = Math.floor(seconds / 60);
  return minutes ? `${minutes} 分 ${seconds % 60} 秒` : `${seconds} 秒`;
}

const CoverageRow: React.FC<{ name: string; coverage: Coverage; detail?: React.ReactNode; title?: string }> = ({ name, coverage, detail, title }) => {
  const { palette } = useAppTheme();
  return (
    <div style={{ display: 'grid', gridTemplateColumns: 'minmax(120px, 160px) minmax(0, 1fr)', gap: 16, padding: '14px 20px', borderTop: `1px solid ${palette.borderSubtle}`, fontSize: 13 }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, alignItems: 'flex-start' }}>
        <span style={{ fontWeight: 600, color: palette.text }}>{name}</span>
        <Tooltip title={title}><span><StatusPill tone={coverage.tone}>{coverage.label}</StatusPill></span></Tooltip>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, minWidth: 0, color: palette.textSecondary }}>
        {detail}
        {coverage.hint && coverage.tone !== 'ok' && <span style={{ padding: '8px 10px', borderRadius: 8, background: palette.tone[coverage.tone].bg, color: palette.tone[coverage.tone].fg }}>处理方法：{coverage.hint}</span>}
      </div>
    </div>
  );
};

/** Task detail body: phases, coverage, results, scope and logs. */
export const TaskDetail: React.FC<{
  task: ScanTask;
  logs: TaskLog[];
  loading: boolean;
  refreshing: boolean;
  error: string;
  canWrite: boolean;
  exporting: 'json' | 'csv' | null;
  progress: React.ReactNode;
  onPause: () => void;
  onResume: () => void;
  onStop: () => void;
  onExport: (format: 'json' | 'csv') => void;
}> = ({ task, logs, loading, refreshing, error, canWrite, exporting, progress, onPause, onResume, onStop, onExport }) => {
  const { palette } = useAppTheme();
  const muted = { color: palette.textSecondary };
  const terminal = isTerminalTask(task.status);
  const auto = task.engines?.[0] === 'auto' || task.engines?.[0] === 'port-probe';
  const phases = taskPhases(task);
  const live = liveScanCounts(task);
  const target = taskTargetSummary(task);
  const startedAt = task.chunks?.map(chunk => chunk.startedAt).filter(Boolean).sort()[0];
  const finishedAt = task.chunks?.map(chunk => chunk.finishedAt).filter(Boolean).sort().slice(-1)[0];
  const worker = [...new Set(task.chunks?.map(chunk => chunk.workerNodeId).filter(Boolean))].join('、');
  const openPorts = task.portProbeResults?.map(item => item.port) ?? [];
  const httpServices = task.serviceResults?.filter(item => item.kind === 'HTTP') ?? [];
  const system = systemCoverage(task.systemScanStatus, task.systemScanCode);
  const app = applicationCoverage(task.applicationScanStatus);
  const kind = task.synthetic ? '模拟任务' : task.engines?.[0] === 'auto' ? '自动综合扫描' : task.engines?.[0] === 'port-probe' ? '历史 TCP 端口探测' : task.inputPath ? '离线输入扫描' : (task.engines ?? []).join('、').toUpperCase();
  const meta = [
    `创建于 ${formatTime(task.createdAt)}`,
    finishedAt && terminal ? `完成于 ${formatTime(finishedAt)}` : '',
    duration(startedAt, finishedAt) && terminal ? `用时 ${duration(startedAt, finishedAt)}` : '',
    worker ? `节点 ${worker}` : '',
    `规则版本 ${task.ruleVersion || '无需外部规则包'}`,
  ].filter(Boolean);
  const scope: [string, React.ReactNode][] = [
    ['目标', <Mono key="target">{target.primary}</Mono>],
    ...(auto ? [
      ['端口策略', `${presetLabels[task.portProbeConfig?.preset ?? 'common']} · ${(task.portProbePorts?.length ?? 0).toLocaleString()} 个 TCP 端口`],
      ['任务排除', <Mono key="ex">{showRanges(task.portProbeConfig?.exclusions)}</Mono>],
      ['合并排除', <Mono key="merged">{showRanges(task.effectiveExclusions ?? task.portProbeConfig?.exclusions)}</Mono>],
      ['隔离端口', <Mono key="q">{compressPorts(task.quarantinedPorts) || '无'}</Mono>],
      ['扫描强度', intensityLabels[task.portProbeConfig?.intensity ?? 'gentle']],
    ] as [string, React.ReactNode][] : []),
    ...(task.inputKind ? [['离线输入', `${task.inputKind} · ${task.inputPath ?? ''}`]] as [string, React.ReactNode][] : []),
    ['时间窗', task.timeWindows?.length ? task.timeWindows.map(window => `${window.weekdays.map(day => weekdays[day]).join('、')} ${window.start}–${window.end} · ${window.timeZone}`).join('；') : '不限时间'],
    ['本地截止时间', formatTime(task.hardDeadline,'—')],
    ['跳过目标', task.skippedTargets?.join('、') || '无'],
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {loading && <Spin tip="正在加载任务最新状态" />}
      {error && <Alert type="error" showIcon message="任务详情加载失败" description={error} />}

      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 18, fontWeight: 600, color: palette.text }}>{kind} · <Mono>{target.primary}</Mono></span>
          <TaskStatusTag value={task.status} />
          {!terminal && <StatusPill tone="running">{refreshing ? '正在刷新' : '每 3 秒自动刷新'}</StatusPill>}
        </div>
        <span style={{ fontSize: 13, ...muted }}>{meta.join(' · ')}</span>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginTop: 4 }}>
          {!terminal && task.status !== 'PAUSED' && <Button disabled={!canWrite} onClick={onPause}>暂停任务</Button>}
          {task.status === 'PAUSED' && <Button type="primary" disabled={!canWrite} onClick={onResume}>恢复任务</Button>}
          {!terminal && <Button danger disabled={!canWrite} onClick={onStop}>取消任务</Button>}
          <Button icon={<DownloadOutlined />} loading={exporting === 'json'} onClick={() => onExport('json')}>导出 JSON 结果</Button>
          <Button icon={<DownloadOutlined />} loading={exporting === 'csv'} onClick={() => onExport('csv')}>导出 CSV 结果</Button>
          {task.findingCount > 0 && <Link to={`/findings?taskId=${encodeURIComponent(task.id)}`}><Button type="primary">查看本任务 {task.findingCount.toLocaleString()} 项发现</Button></Link>}
        </div>
        <span style={{ fontSize: 12, color: palette.textTertiary }}>导出包含稳定的任务与发现字段，不包含证据、凭据和原始引擎输出。</span>
      </div>

      {task.error && <Alert type="error" showIcon message={task.error} />}

      <Panel title="执行进度">
        {phases.length ? (
          <ol style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(140px, 1fr))', gap: 10 }}>
            {phases.map((phase, index) => (
              <li key={phase.key} style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: 12, borderRadius: 10, background: palette.bgSubtle, border: `1px solid ${phase.state === 'running' ? palette.primary : palette.borderSubtle}` }}>
                <span style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 13, fontWeight: 600, color: palette.text }}><Mono style={{ color: palette.textTertiary }}>{index + 1}</Mono>{phase.name}</span>
                <span style={{ alignSelf: 'flex-start' }}><StatusPill tone={phaseTones[phase.state]}>{phaseLabels[phase.state]}</StatusPill></span>
                <span style={{ fontSize: 12, ...muted }}>{phase.detail}</span>
              </li>
            ))}
          </ol>
        ) : progress}
      </Panel>

      <Panel title="扫描结果">
        <AutoGrid min={150} gap={12}>
          {[
            ['开放端口', openPorts.length || live.open || 0, openPorts.length ? compressPorts(openPorts) : live.open ? '端口明细在任务结束后显示' : '无'],
            ['HTTP(S) 服务', httpServices.length || live.http || 0, !httpServices.length && live.http ? '正在检查，服务明细在任务结束后显示' : (task.serviceResults?.length ?? 0) > httpServices.length ? `另有 ${(task.serviceResults?.length ?? 0) - httpServices.length} 个非 HTTP 服务` : '已执行只读基线检查'],
            ['发现项', task.findingCount, task.findingCount ? '可在漏洞列表中按任务筛选' : '本次没有发现项'],
          ].map(([label, value, note]) => (
            <div key={String(label)} style={{ display: 'flex', flexDirection: 'column', gap: 4, padding: 12, borderRadius: 10, background: palette.bgSubtle }}>
              <span style={{ fontSize: 12, ...muted }}>{label}</span>
              <Mono style={{ fontSize: 22, fontWeight: 600, color: palette.text }}>{Number(value).toLocaleString()}</Mono>
              <span style={{ fontSize: 12, color: palette.textTertiary, overflowWrap: 'anywhere' }}>{note}</span>
            </div>
          ))}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: 12, borderRadius: 10, background: palette.bgSubtle }}>
            <span style={{ fontSize: 12, ...muted }}>网络围栏</span>
            <span style={{ alignSelf: 'flex-start' }}><StatusPill tone={task.dropCount ? 'warning' : task.fenceStatus === 'ENFORCED' ? 'ok' : 'neutral'}>{task.fenceStatus ? fenceLabels[task.fenceStatus] ?? task.fenceStatus : '未上报'}</StatusPill></span>
            <span style={{ fontSize: 12, color: palette.textTertiary }}>{task.fenceStatus ? `拦截范围外连接 ${task.dropCount ?? 0} 次` : '该 Worker 未上报网络围栏状态'}</span>
          </div>
        </AutoGrid>
        {task.dropCount ? <Alert type="warning" showIcon message="检测到范围外连接尝试，已被网络围栏拦截" description="请检查 Worker 日志和授权范围；平台不会展示原始地址或请求内容。" style={{ marginTop: 12 }} /> : null}
      </Panel>

      {task.engines?.[0] === 'auto' && <Panel flush title="检测覆盖">
        <CoverageRow name="Linux 系统包" coverage={system} title={task.systemScanStatus} detail={<span>{task.systemScanStatus || '等待 Worker 回报'}</span>} />
        <CoverageRow name="Java / Go 应用依赖" coverage={app} detail={task.applicationResults?.length
          ? task.applicationResults.map(item => <span key={item.alias}>应用 <Mono>{item.alias}</Mono>：{applicationStatuses[item.status] ?? '状态未知'}，已分析 {item.analyzedCount} / 选中 {item.selectedCount} 个文件</span>)
          : <span>{task.applicationScanStatus ? '本次没有可分析的应用产物' : '等待 Worker 回报（旧任务未记录应用覆盖）'}</span>} />
        <CoverageRow name="HTTP(S) 服务" coverage={httpServices.length ? { tone: 'ok', label: `${httpServices.length} 个服务` } : { tone: 'neutral', label: '没有 HTTP(S) 服务' }} detail={httpServices.length
          ? httpServices.map(item => <span key={item.port}><Mono>{item.port}</Mono>{[item.software, item.version].filter(Boolean).length ? ` · ${[item.software, item.version].filter(Boolean).join(' ')}` : ''}{item.tls ? ' · TLS' : ''}{item.title ? ` · ${item.title}` : ''}</span>)
          : <span>开放端口中没有识别出 HTTP(S) 服务，只读基线检查未执行。自定义规则 {task.customRuleCount ?? 0} 条。</span>} />
      </Panel>}

      <AutoGrid min={380}>
        <Panel title="扫描范围">
          <dl style={{ margin: 0, display: 'grid', gridTemplateColumns: '96px minmax(0, 1fr)', gap: '10px 12px', fontSize: 13 }}>
            {scope.map(([label, value]) => <React.Fragment key={label}><dt style={{ color: palette.textTertiary }}>{label}</dt><dd style={{ margin: 0, color: palette.text, overflowWrap: 'anywhere' }}>{value}</dd></React.Fragment>)}
          </dl>
        </Panel>
        <Panel flush title="目标级状态">
          <DataTable<ScanTask['chunks'][number]> size="small" rowKey="id" pagination={false} dataSource={task.chunks ?? []} columns={[
            { title: '目标', dataIndex: 'targets', render: (targets: string[]) => <Mono>{targets?.join('、') || '—'}</Mono> },
            { title: '状态', dataIndex: 'status', width: 120, render: (value: string) => <TaskStatusTag value={value} /> },
            { title: 'Worker', dataIndex: 'workerNodeId', render: (value: string) => value ? <Mono>{value}</Mono> : '尚未领取' },
          ]} />
        </Panel>
      </AutoGrid>

      <Panel flush title="只读任务日志" extra={<span style={{ color: palette.textTertiary }}>不显示原始引擎输出、凭据或请求响应</span>}>
        <DataTable<TaskLog> size="small" rowKey="id" loading={loading} dataSource={logs} pagination={{ pageSize: 10, hideOnSinglePage: true }} locale={{ emptyText: '暂无任务日志' }} columns={[
          { title: '时间', dataIndex: 'createdAt', width: 190, render: (value: string) => <Mono style={muted}>{formatTime(value)}</Mono> },
          { title: '事件', dataIndex: 'message' },
          { title: '操作者', dataIndex: 'actor', width: 150 },
        ]} />
      </Panel>
    </div>
  );
};
