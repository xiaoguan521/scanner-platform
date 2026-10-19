import React, { useMemo, useState } from 'react';
import { Alert, Button, Card, DatePicker, Empty, message, Select, Space, Statistic, Table, Tag, Typography } from 'antd';
import dayjs, { Dayjs } from 'dayjs';
import { DownloadOutlined, FileTextOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { mockAssets, mockFindings, mockTasks } from '../../mock/data';
import type { Asset, Finding, ScanTask } from '../../types';
import type { ReportSnapshot, ReportTemplate } from './exporters';

const { RangePicker } = DatePicker;
const { Text, Title } = Typography;
type Template = ReportTemplate;

const templateNames: Record<Template, string> = { overview: '安全总览报告', asset: '资产安全报告', task: '扫描任务报告' };
const severityNames: Record<string, string> = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息' };
const statusNames: Record<string, string> = { OPEN: '待修复', REOPENED: '重新出现', IN_PROGRESS: '修复中', FIXED: '已修复', FALSE_POSITIVE: '误报', ACCEPTED_RISK: '接受风险' };
const taskStatusNames: Record<string, string> = { PENDING: '待领取', RUNNING: '执行中', WAITING_WINDOW: '等待时间窗', PAUSED_WINDOW: '等待恢复', COMPLETED: '已完成', CANCELED: '已取消', FAILED: '失败' };

function targetMatchesAsset(target: string, asset: Asset): boolean {
  if (target === asset.address) return true;
  const prefix = asset.address.includes(':') ? `[${asset.address}]:` : `${asset.address}:`;
  return target.startsWith(prefix) || target.startsWith(`${asset.address}/`);
}

function inDateRange(value: string, range: [Dayjs | null, Dayjs | null] | null): boolean {
  if (!range || (!range[0] && !range[1])) return true;
  const time = Date.parse(value);
  if (!Number.isFinite(time)) return false;
  return (!range[0] || time >= range[0].startOf('day').valueOf()) && (!range[1] || time <= range[1].endOf('day').valueOf());
}

function escapeHTML(value: unknown): string {
  return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!);
}

function csvCell(value: unknown): string {
  let text = String(value ?? '');
  if (/^\s*[=+@-]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

function downloadFile(name: string, content: string, type: string): void {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function downloadBlob(name: string, blob: Blob): void {
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = name;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export const ReportsPage: React.FC = () => {
  const { data: assets, loading: assetsLoading, error: assetsError } = useCollection('assets', mockAssets);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useCollection('tasks', mockTasks);
  const { data: findings, loading: findingsLoading, error: findingsError } = useCollection('findings', mockFindings);
  const [template, setTemplate] = useState<Template>('overview');
  const [assetId, setAssetId] = useState<string>();
  const [group, setGroup] = useState<string>();
  const [taskId, setTaskId] = useState<string>();
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [snapshot, setSnapshot] = useState<ReportSnapshot | null>(null);
  const loading = assetsLoading || tasksLoading || findingsLoading;
  const error = assetsError || tasksError || findingsError;
  const groups = useMemo(() => [...new Set(assets.map(asset => asset.businessGroup).filter(Boolean))].sort(), [assets]);
  const availableTasks = useMemo(() => tasks.slice().sort((a, b) => Date.parse(b.createdAt) - Date.parse(a.createdAt)), [tasks]);
  const selectedAsset = assets.find(asset => asset.id === assetId);
  const selectedTask = tasks.find(task => task.id === taskId);

  const generate = () => {
    if (template === 'asset' && !selectedAsset) { message.warning('请选择一项资产'); return; }
    if (template === 'task' && !selectedTask) { message.warning('请选择一个扫描任务'); return; }
    let filteredAssets = assets.filter(asset => (!assetId || asset.id === assetId) && (!group || asset.businessGroup === group));
    let filteredTasks = tasks.filter(task => inDateRange(task.createdAt, range));
    if (assetId && selectedAsset) filteredTasks = filteredTasks.filter(task => task.chunks?.some(chunk => chunk.targets.some(target => targetMatchesAsset(target, selectedAsset))));
    if (selectedTask) filteredTasks = filteredTasks.filter(task => task.id === selectedTask.id);

    const selectedTargets = new Set(selectedTask?.chunks.flatMap(chunk => chunk.targets) ?? []);
    if (selectedTask) filteredAssets = filteredAssets.filter(asset => [...selectedTargets].some(target => targetMatchesAsset(target, asset)));
    const filteredFindings = findings.filter(finding =>
      (!group || finding.businessGroup === group) &&
      (!assetId || (selectedAsset && targetMatchesAsset(finding.target, selectedAsset))) &&
      (!selectedTask || selectedTargets.has(finding.target) || (!selectedTargets.size && selectedTask.inputPath === finding.target)) &&
      inDateRange(finding.lastSeen, range));
    const severity: Record<string, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (const finding of filteredFindings) severity[finding.severity] = (severity[finding.severity] ?? 0) + 1;
    const openFindings = filteredFindings.filter(finding => ['OPEN', 'REOPENED', 'IN_PROGRESS'].includes(finding.status)).length;
    const title = templateNames[template];
    setSnapshot({
      title,
      generatedAt: new Date().toISOString(),
      filters: { template, asset: selectedAsset?.address, businessGroup: group, task: selectedTask?.id, from: range?.[0]?.format('YYYY-MM-DD'), to: range?.[1]?.format('YYYY-MM-DD') },
      summary: { assets: filteredAssets.length, tasks: filteredTasks.length, findings: filteredFindings.length, openFindings, severity },
      assets: filteredAssets,
      tasks: filteredTasks,
      findings: filteredFindings,
    });
    message.success('报告已生成，可下载 Word、Excel、HTML、CSV 或 JSON');
  };

  const downloadHTML = () => {
    if (!snapshot) return;
    const scopeText = [
      `资产：${snapshot.filters.asset ?? '全部'}`,
      `业务组：${snapshot.filters.businessGroup ?? '全部'}`,
      `任务：${snapshot.filters.task ?? '全部'}`,
      `时间：${snapshot.filters.from ?? '不限开始'} 至 ${snapshot.filters.to ?? '不限结束'}`,
    ].join('；');
    const rows = snapshot.findings.map(finding => `<tr><td>${escapeHTML(severityNames[finding.severity] ?? finding.severity)}</td><td>${escapeHTML(finding.title)}</td><td>${escapeHTML(finding.templateOrCve)}</td><td>${escapeHTML(finding.target)}</td><td>${escapeHTML(finding.businessGroup)}</td><td>${escapeHTML(statusNames[finding.status] ?? finding.status)}</td></tr>`).join('');
    const assetRows = snapshot.assets.map(asset => `<tr><td>${escapeHTML(asset.address)}</td><td>${escapeHTML(asset.kind === 'host' ? '主机' : '镜像仓库')}</td><td>${escapeHTML(asset.businessGroup)}</td><td>${escapeHTML(asset.owner)}</td><td>${asset.ports?.length ?? 0}</td></tr>`).join('');
    const taskRows = snapshot.tasks.map(task => `<tr><td>${escapeHTML(task.id)}</td><td>${escapeHTML(task.engines.join(', '))}</td><td>${escapeHTML(taskStatusNames[task.status] ?? task.status)}</td><td>${task.completedChunks} / ${task.totalChunks}</td><td>${escapeHTML(task.chunks.flatMap(chunk => chunk.targets).slice(0, 10).join('、') || task.inputPath || '—')}</td></tr>`).join('');
    const documentText = `<!doctype html><html lang="zh-CN"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${escapeHTML(snapshot.title)}</title><style>body{font:15px/1.6 system-ui,-apple-system,"Microsoft YaHei",sans-serif;color:#172033;max-width:1200px;margin:36px auto;padding:0 20px}h1{margin-bottom:4px}.muted{color:#667085}.stats{display:flex;gap:14px;flex-wrap:wrap;margin:24px 0}.stats div{border:1px solid #dfe4ec;border-radius:8px;padding:14px 20px;min-width:130px}table{border-collapse:collapse;width:100%;margin-top:18px}th,td{border:1px solid #dfe4ec;padding:9px;text-align:left;vertical-align:top}th{background:#f4f6f9}small{color:#667085}</style><body><h1>${escapeHTML(snapshot.title)}</h1><div class="muted">生成时间：${escapeHTML(new Date(snapshot.generatedAt).toLocaleString())}</div><p>筛选范围：${escapeHTML(scopeText)}</p><div class="stats"><div>资产<br><strong>${snapshot.summary.assets}</strong></div><div>扫描任务<br><strong>${snapshot.summary.tasks}</strong></div><div>发现项<br><strong>${snapshot.summary.findings}</strong></div><div>待处置<br><strong>${snapshot.summary.openFindings}</strong></div></div><h2>风险等级</h2><p>${Object.entries(snapshot.summary.severity).map(([severity, count]) => `${escapeHTML(severityNames[severity] ?? severity)}：${count}`).join('　')}</p><h2>资产</h2><table><thead><tr><th>地址</th><th>类型</th><th>业务组</th><th>负责人</th><th>已分类端口</th></tr></thead><tbody>${assetRows || '<tr><td colspan="5">该范围没有资产</td></tr>'}</tbody></table><h2>扫描任务</h2><table><thead><tr><th>任务 ID</th><th>执行方式</th><th>状态</th><th>进度</th><th>目标或输入</th></tr></thead><tbody>${taskRows || '<tr><td colspan="5">该范围没有任务</td></tr>'}</tbody></table><h2>发现项</h2><table><thead><tr><th>等级</th><th>名称</th><th>CVE / 规则</th><th>目标</th><th>业务组</th><th>状态</th></tr></thead><tbody>${rows || '<tr><td colspan="6">该范围没有发现项</td></tr>'}</tbody></table><p><small>报告根据生成时平台可见数据生成；未检出不表示资产不存在风险。</small></p></body></html>`;
    downloadFile('scanner-report.html', documentText, 'text/html;charset=utf-8');
  };

  const downloadCSV = () => {
    if (!snapshot) return;
    const header = ['严重度', '名称', 'CVE或规则', '引擎', '目标', '业务组', '负责人', '状态', '首次发现', '最近发现'];
    const rows = snapshot.findings.map(finding => [severityNames[finding.severity] ?? finding.severity, finding.title, finding.templateOrCve, finding.engine, finding.target, finding.businessGroup, finding.owner, statusNames[finding.status] ?? finding.status, finding.firstSeen, finding.lastSeen]);
    downloadFile('scanner-findings.csv', `\uFEFF${[header, ...rows].map(row => row.map(csvCell).join(',')).join('\r\n')}`, 'text/csv;charset=utf-8');
  };

  const downloadJSON = () => {
    if (!snapshot) return;
    downloadFile('scanner-report.json', `${JSON.stringify(snapshot, null, 2)}\n`, 'application/json;charset=utf-8');
  };

  const downloadWord = async () => {
    if (!snapshot) return;
    try { const { buildWordReport } = await import('./exporters'); downloadBlob('scanner-report.docx', await buildWordReport(snapshot)); message.success('Word 报告已下载'); }
    catch { message.error('Word 报告生成失败，请缩小范围后重试'); }
  };

  const downloadExcel = async () => {
    if (!snapshot) return;
    try { const { buildExcelReport } = await import('./exporters'); downloadBlob('scanner-report.xlsx', await buildExcelReport(snapshot)); message.success('Excel 报告已下载'); }
    catch { message.error('Excel 报告生成失败，请缩小范围后重试'); }
  };

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <CollectionNotice loading={loading} error={error} />
    <Alert showIcon type="info" message="按平台当前可见数据生成报告" description="选择报告模板和范围后生成快照，可下载 Word、Excel、HTML、CSV 或 JSON。Excel 包含总览、资产风险、漏洞影响、主机/网站资产、漏洞明细、弱口令和登录入口 8 个工作表；未采集内容会明确标注，不以空白或零风险代替。" />
    <Card title={<Space><FileTextOutlined/><span>生成安全报告</span></Space>}>
      <Space wrap align="end" style={{ width: '100%' }}>
        <div><Text type="secondary">报告模板</Text><Select value={template} onChange={value => { setTemplate(value); setSnapshot(null); }} style={{ display: 'block', width: 190 }} options={Object.entries(templateNames).map(([value, label]) => ({ value, label }))} /></div>
        <div><Text type="secondary">业务组</Text><Select allowClear value={group} onChange={value => { setGroup(value); setSnapshot(null); }} style={{ display: 'block', width: 190 }} placeholder="全部业务组" options={groups.map(value => ({ value, label: value }))} /></div>
        <div><Text type="secondary">资产</Text><Select allowClear showSearch optionFilterProp="label" value={assetId} onChange={value => { setAssetId(value); setSnapshot(null); }} style={{ display: 'block', width: 240 }} placeholder="全部资产" options={assets.map(asset => ({ value: asset.id, label: `${asset.address} · ${asset.businessGroup}` }))} /></div>
        <div><Text type="secondary">扫描任务</Text><Select allowClear showSearch optionFilterProp="label" value={taskId} onChange={value => { setTaskId(value); setSnapshot(null); }} style={{ display: 'block', width: 250 }} placeholder="全部任务" options={availableTasks.map(task => ({ value: task.id, label: `${task.id.slice(0, 18)} · ${task.status}` }))} /></div>
        <div><Text type="secondary">时间范围</Text><RangePicker value={range} onChange={value => { setRange(value); setSnapshot(null); }} allowEmpty={[true, true]} /></div>
        <Button type="primary" icon={<FileTextOutlined/>} disabled={loading || !!error} onClick={generate}>生成报告</Button>
      </Space>
      {template === 'asset' && <Text type="secondary" style={{ display: 'block', marginTop: 12 }}>资产报告需要选择资产；可再按业务组和最近发现时间缩小范围。</Text>}
      {template === 'task' && <Text type="secondary" style={{ display: 'block', marginTop: 12 }}>任务报告需要选择任务；报告会包含该任务的目标和匹配的发现项。</Text>}
    </Card>
    {snapshot ? <>
      <Card title={<Space><Title level={5} style={{ margin: 0 }}>{snapshot.title}</Title><Tag color="blue">{dayjs(snapshot.generatedAt).format('YYYY-MM-DD HH:mm:ss')}</Tag></Space>} extra={<Space wrap><Button type="primary" icon={<DownloadOutlined/>} onClick={()=>void downloadWord()}>下载 Word</Button><Button icon={<DownloadOutlined/>} onClick={()=>void downloadExcel()}>下载 Excel</Button><Button onClick={downloadHTML}>下载 HTML</Button><Button onClick={downloadCSV}>下载 CSV</Button><Button onClick={downloadJSON}>下载 JSON</Button></Space>}>
        <Space wrap size="large">
          <Statistic title="资产" value={snapshot.summary.assets}/>
          <Statistic title="扫描任务" value={snapshot.summary.tasks}/>
          <Statistic title="发现项" value={snapshot.summary.findings}/>
          <Statistic title="待处置" value={snapshot.summary.openFindings}/>
          {Object.entries(snapshot.summary.severity).map(([severity, count]) => <Statistic key={severity} title={severityNames[severity]} value={count} />)}
        </Space>
        <Typography.Paragraph type="secondary" style={{ marginTop: 16, marginBottom: 0 }}>
          筛选范围：{snapshot.filters.asset ?? '全部资产'} · {snapshot.filters.businessGroup ?? '全部业务组'} · {snapshot.filters.task ?? '全部任务'} · {snapshot.filters.from ?? '不限开始'} 至 {snapshot.filters.to ?? '不限结束'}
        </Typography.Paragraph>
      </Card>
      <Card title="报告发现项">
        <Table<Finding> rowKey="id" dataSource={snapshot.findings} tableLayout="fixed" scroll={{ x: 1080 }} pagination={{ pageSize: 10, showTotal: total => `共 ${total} 项` }} locale={{ emptyText: <Empty description="所选范围没有发现项"/> }} columns={[
          { title: '等级', dataIndex: 'severity', width: 100, render: (value: string) => <Tag>{severityNames[value] ?? value}</Tag> },
          { title: '漏洞 / 风险', dataIndex: 'title', width: 260, ellipsis: true },
          { title: 'CVE / 规则', dataIndex: 'templateOrCve', width: 190, ellipsis: true },
          { title: '目标', dataIndex: 'target', width: 210, ellipsis: true },
          { title: '业务组 / 负责人', width: 180, render: (_: unknown, finding: Finding) => `${finding.businessGroup} / ${finding.owner}` },
          { title: '状态', dataIndex: 'status', width: 110, render: (value: string) => statusNames[value] ?? value },
          { title: '最近发现', dataIndex: 'lastSeen', width: 170, render: (value: string) => value ? new Date(value).toLocaleString() : '—' },
        ]}/>
      </Card>
      <Card title="范围内资产与任务">
        <Table<Asset> rowKey="id" size="small" dataSource={snapshot.assets} pagination={false} locale={{ emptyText: '范围内没有资产' }} columns={[
          { title: '资产地址', dataIndex: 'address' }, { title: '业务组', dataIndex: 'businessGroup' }, { title: '负责人', dataIndex: 'owner' }, { title: '端口分类数', dataIndex: 'ports', render: (ports: Asset['ports']) => ports?.length ?? 0 },
        ]}/>
        <Table<ScanTask> rowKey="id" size="small" style={{ marginTop: 16 }} dataSource={snapshot.tasks} pagination={false} locale={{ emptyText: '范围内没有任务' }} columns={[
          { title: '任务 ID', dataIndex: 'id', ellipsis: true }, { title: '执行方式', dataIndex: 'engines', render: (engines: string[]) => engines.join('、') }, { title: '状态', dataIndex: 'status', render: (value: string) => taskStatusNames[value] ?? value }, { title: '进度', render: (_: unknown, task: ScanTask) => `${task.completedChunks} / ${task.totalChunks}` },
        ]}/>
      </Card>
    </> : <Card><Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="选择模板和范围，然后生成报告" /></Card>}
  </div>;
};
