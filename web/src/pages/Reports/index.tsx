import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Checkbox, DatePicker, Drawer, Dropdown, Empty, Form, Input, message, Progress, Select, Space, Upload } from 'antd';
import { TitleWithHelp } from '../../components/HelpTip';
import type { Dayjs } from 'dayjs';
import { DownloadOutlined, FileTextOutlined, SettingOutlined, UploadOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { apiClient, requestJSON, errorMessage } from '../../api/client';
import { CollectionNotice } from '../../api/CollectionNotice';
import { pollIntervals, pollWhileVisible } from '../../api/polling';
import { useAuth } from '../../auth/AuthProvider';
import { Mono, StatusPill, taskStatusMeta } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { Tone } from '../../theme/palette';
import { taskTargetSummary } from '../Tasks/targets';
import type { ReportJob, ReportScope, ReportTemplate } from './types';

const sections = { cover: '封面', overview: '综述', assets: '资产统计', 'asset-risks': '资产风险信息', 'asset-details': '资产详情', 'risk-statistics': '风险统计', 'risk-details': '风险详情', appendix: '附录' };
const stateNames = { QUEUED: '排队中', GENERATING: '生成中', READY: '就绪', FAILED: '失败' };
const formatNames = { html: 'HTML', xlsx: 'Excel', docx: 'Word', pdf: 'PDF', csv: 'CSV（漏洞明细）', json: 'JSON（完整快照）' };
const endpoint = '/api/v1/reports';
const templatesEndpoint = '/api/v1/report-templates';

// Report task targets can be a bare IP (automatic scan) or an IP:port
// (HTTP checks). Both must map to the same registered asset.
function reportTargetHost(raw: string): string {
  const target = raw.trim();
  if (/^https?:\/\//i.test(target)) {
    try { return new URL(target).hostname.replace(/^\[|\]$/g, ''); }
    catch { return target; }
  }
  const ipv6 = target.match(/^\[([^\]]+)\](?::\d+)?$/);
  if (ipv6) return ipv6[1];
  const ipv4Port = target.match(/^([^:]+):(\d+)$/);
  return ipv4Port ? ipv4Port[1] : target;
}

export const ReportsPage: React.FC = () => {
  const { canWrite } = useAuth();
  const { palette } = useAppTheme();
  
  const { data: assets, loading: assetsLoading, error: assetsError } = useCollection('assets', '', true, pollIntervals.reference);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useCollection('tasks', '', true, pollIntervals.reference);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [jobs, setJobs] = useState<ReportJob[]>([]);
  const [reportPage, setReportPage] = useState(1);
  const [reportPageSize, setReportPageSize] = useState(10);
  const [reportTotal, setReportTotal] = useState(0);
  const [reportSearch, setReportSearch] = useState('');
  const [reportStatus, setReportStatus] = useState('ALL');
  const [reportFormat, setReportFormat] = useState('ALL');
  const [reportLoading, setReportLoading] = useState(true);
  const [templateId, setTemplateId] = useState('default');
  const [format, setFormat] = useState<ReportJob['format']>('xlsx');
  const [assetId, setAssetId] = useState<string>();
  const [businessGroup, setBusinessGroup] = useState<string>();
  const [taskId, setTaskId] = useState<string>();
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [editing, setEditing] = useState(false);
  const [logo, setLogo] = useState<string>();
  const [form] = Form.useForm<ReportTemplate & { enabledSections: string[] }>();
  const groups = useMemo(() => [...new Set(assets.map(a => a.businessGroup).filter(Boolean))].sort(), [assets]);
  const scopedAssets = useMemo(() =>
    assets.filter(a => (!businessGroup || a.businessGroup === businessGroup) &&
      (!assetId || a.id === assetId)),
    [assets, businessGroup, assetId]);
  const availableTasks = useMemo(() => {
    if (!businessGroup && !assetId) return tasks;
    const ids = new Set(scopedAssets.map(a => a.id));
    const hosts = new Set(scopedAssets.map(a => a.address));
    return tasks.filter(task => ids.has(task.assetId ?? '') ||
      task.chunks?.some(chunk => chunk.targets?.some(target =>
        hosts.has(reportTargetHost(target)))));
  }, [tasks, scopedAssets, businessGroup, assetId]);
  const selectedTemplate = templates.find(t => t.id === templateId);
  const reload = useCallback(async (signal?: AbortSignal, silent = false, includeTemplates = true) => {
    if (!silent) setReportLoading(true);
    try {
      const [reports, nextTemplates] = await Promise.all([
        apiClient.reportsPage<ReportJob>(reportPage, reportPageSize, { search: reportSearch, status: reportStatus, format: reportFormat }, signal),
        includeTemplates ? requestJSON<{ items: ReportTemplate[] }>(templatesEndpoint, 'GET', undefined, signal) : undefined,
      ]);
      if (!signal?.aborted) { setJobs(reports.items); setReportTotal(reports.total); if (nextTemplates) setTemplates(nextTemplates.items); setError(null); }
    } catch (cause) { if (!signal?.aborted) setError(errorMessage(cause,'报告服务不可用')); }
    finally { if (!signal?.aborted) setReportLoading(false); }
  }, [reportPage, reportPageSize, reportSearch, reportStatus, reportFormat]);
  useEffect(() => { const controller = new AbortController(); void reload(controller.signal, true); return () => controller.abort(); }, [reload]);
  // Only queued or generating reports change on their own; poll just the job list while one exists.
  const hasActiveJobs = jobs.some(job => job.status === 'QUEUED' || job.status === 'GENERATING');
  useEffect(() => { if (!hasActiveJobs) return; const controller = new AbortController(); let loading = false; const load = async () => { if (loading) return; loading = true; await reload(controller.signal, true, false); loading = false; }; const stop = pollWhileVisible(() => void load(), pollIntervals.activeTask); return () => { controller.abort(); stop(); }; }, [reload, hasActiveJobs]);
  useEffect(() => { if (reportPage !== 1) setReportPage(1); }, [reportSearch, reportStatus, reportFormat]);
  const generate = async () => {
    const scope: ReportScope = { assetId, businessGroup, taskId, from: range?.[0]?.startOf('day').toISOString(), to: range?.[1]?.endOf('day').toISOString() };
    setBusy(true);
    try { await requestJSON(endpoint, 'POST', { templateId, format, scope }); message.success('已冻结数据快照，报告将在后台生成'); await reload(); }
    catch (cause) { message.error(errorMessage(cause,'生成失败')); }
    finally { setBusy(false); }
  };
  const retry = async (job: ReportJob) => { try { await requestJSON(`${endpoint}/${encodeURIComponent(job.id)}/retry`, 'POST'); message.success('已使用原快照重新排队'); await reload(); } catch (cause) { message.error(errorMessage(cause)); } };
  const exportFormat = async (job: ReportJob, nextFormat: string) => { try { await requestJSON(`${endpoint}/${encodeURIComponent(job.id)}/formats`, 'POST', { format: nextFormat }); message.success('已使用相同数据快照生成其他格式'); await reload(); } catch (cause) { message.error(errorMessage(cause)); } };
  const editTemplate = () => { if (!selectedTemplate) return; form.setFieldsValue({ ...selectedTemplate, enabledSections: Object.keys(sections).filter(k => selectedTemplate.sections[k] !== false) }); setLogo(selectedTemplate.logo); setEditing(true); };
  const saveTemplate = async () => {
    try { const values = await form.validateFields(); const { enabledSections, ...fields } = values; const body = { ...fields, logo: logo ?? '', sections: Object.fromEntries(Object.keys(sections).map(key => [key, enabledSections.includes(key)])) }; await requestJSON(`${templatesEndpoint}/${encodeURIComponent(templateId)}`, 'PUT', body); setEditing(false); message.success('模板已保存，新报告将使用更新后的模板'); await reload(); }
    catch (cause) { if (cause instanceof Error) message.error(cause.message); }
  };
  const muted = { color: palette.textSecondary };
  const small = { fontSize: 12, ...muted };
  const stateTones: Record<ReportJob['status'], Tone> = { QUEUED: 'neutral', GENERATING: 'running', READY: 'ok', FAILED: 'error' };
  const fileSize = (bytes: number) => bytes >= 1024 * 1024 ? `${(bytes / 1024 / 1024).toFixed(1)} MiB` : `${(bytes / 1024).toFixed(1)} KiB`;
  const taskLabel = (task: (typeof availableTasks)[number]) => {
    const target = taskTargetSummary(task);
    return `${target.primary} · ${new Date(task.createdAt).toLocaleString()} · ${taskStatusMeta[task.status as keyof typeof taskStatusMeta]?.label ?? task.status}`;
  };
  const scopeSummary = [
    businessGroup ? `业务组 ${businessGroup}` : '',
    assetId ? `资产 ${assets.find(a => a.id === assetId)?.address ?? assetId}` : '',
    taskId ? `任务 ${taskId}` : '',
    range?.[0] || range?.[1] ? `最近发现 ${range?.[0]?.format('YYYY-MM-DD') ?? '不限'} 至 ${range?.[1]?.format('YYYY-MM-DD') ?? '不限'}` : '',
  ].filter(Boolean).join(' · ') || '全部资产和发现项';
  const field = (label: string, control: React.ReactNode) => <label style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, color: palette.textTertiary, minWidth: 0 }}>{label}{control}</label>;

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <PageHeader title="报告中心" description="按范围冻结一份数据快照，再导出为 Excel、Word、PDF、HTML、CSV 或 JSON"
      extra={<Button icon={<SettingOutlined />} disabled={!canWrite || !selectedTemplate} onClick={editTemplate}>配置模板</Button>} />
    <CollectionNotice loading={(assetsLoading || tasksLoading || reportLoading) && jobs.length === 0 && templates.length === 0} error={assetsError || tasksError || error} />

    <Panel title={<TitleWithHelp title={<span style={{ display: 'inline-flex', alignItems: 'center', gap: 8 }}><FileTextOutlined /><span>生成安全报告</span></span>} helpTitle="后台生成与历史记录" help="每次生成冻结一份带版本的数据快照，HTML、Excel、Word、PDF、CSV 与 JSON 使用相同数据与统计规则。CSV 为漏洞明细平面文件，JSON 为完整快照。登录入口单独统计。报告上限 64 MiB，失败可用原快照重试。"/>}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(200px, 100%), 1fr))', gap: 12 }}>
          {field('报告模板', <Select aria-label="报告模板" value={templateId} onChange={setTemplateId} options={templates.map(t => ({ value: t.id, label: t.name }))} />)}
          {field('输出格式', <Select aria-label="输出格式" value={format} onChange={setFormat} options={Object.entries(formatNames).map(([value, label]) => ({ value, label }))} />)}
          {field('业务组', <Select aria-label="业务组" allowClear value={businessGroup} onChange={value => { setBusinessGroup(value); setAssetId(undefined); setTaskId(undefined); }} placeholder="全部业务组" options={groups.map(value => ({ value, label: value }))} />)}
          {field('资产', <Select aria-label="资产" allowClear showSearch optionFilterProp="label" value={assetId} onChange={value => { setAssetId(value); setTaskId(undefined); }} placeholder="全部资产" options={assets.filter(a => !businessGroup || a.businessGroup === businessGroup).map(a => ({ value: a.id, label: a.name ? `${a.address} · ${a.name}` : a.address }))} />)}
          {field('扫描任务', <Select aria-label="扫描任务" allowClear showSearch optionFilterProp="label" value={taskId} onChange={setTaskId} placeholder="全部任务" options={availableTasks.map(t => ({ value: t.id, label: taskLabel(t) }))} />)}
          {field('最近发现时间', <DatePicker.RangePicker aria-label="最近发现时间" value={range} onChange={setRange} allowEmpty={[true, true]} />)}
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '12px 14px', borderRadius: 10, background: palette.bgSubtle, border: `1px solid ${palette.borderSubtle}` }}>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}>
            <span style={{ fontSize: 13, color: palette.text }}>报告范围：{scopeSummary}</span>
            <span style={small}>任务范围使用该任务的历史观察记录；失败、取消或尚未完成的任务会保留状态说明，未知字段显示“未采集”或“未知”。</span>
          </div>
          <Button type="primary" loading={busy} disabled={!canWrite || !!error || !!assetsError || !!tasksError || !selectedTemplate} onClick={() => void generate()}>生成报告</Button>
        </div>
      </div>
    </Panel>

    <Panel flush title="报告历史" extra={<Space wrap>
      <Input aria-label="报告历史搜索" placeholder="搜索报告 ID、名称、创建人或快照" allowClear value={reportSearch} onChange={event => setReportSearch(event.target.value)} style={{ width: 260 }} />
      <Select aria-label="报告状态筛选" value={reportStatus} onChange={setReportStatus} style={{ width: 120 }} options={[{ value: 'ALL', label: '全部状态' }, ...Object.entries(stateNames).map(([value, label]) => ({ value, label }))]} />
      <Select aria-label="报告格式筛选" value={reportFormat} onChange={setReportFormat} style={{ width: 170 }} options={[{ value: 'ALL', label: '全部格式' }, ...Object.entries(formatNames).map(([value, label]) => ({ value, label }))]} />
      <Button onClick={() => void reload()}>刷新</Button>
    </Space>}>
      <DataTable<ReportJob> rowKey="id" dataSource={jobs} loading={reportLoading} tableLayout="fixed" scroll={{ x: 1000 }} pagination={{ current: reportPage, pageSize: reportPageSize, total: reportTotal, showSizeChanger: true, pageSizeOptions: [10, 20, 50], showTotal: total => `共 ${total} 项`, onChange: (page, size) => { if (size !== reportPageSize) { setReportPageSize(size); setReportPage(1); } else setReportPage(page); } }} locale={{ emptyText: <Empty description="暂无报告，选择范围后生成" /> }} columns={[
        { title: '报告', key: 'name', render: (_: unknown, job) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><span style={{ fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={job.name}>{job.name}</span><span style={small} title={`快照 ${job.snapshotId}`}>快照 <Mono>{job.snapshotId.slice(0, 12)}</Mono> · v{job.snapshotVersion}</span></div> },
        { title: '格式', key: 'format', width: 130, render: (_: unknown, job) => <StatusPill tone="neutral">{formatNames[job.format]}</StatusPill> },
        { title: '状态', key: 'status', width: 190, render: (_: unknown, job) => <div style={{ display: 'flex', flexDirection: 'column', gap: 4, alignItems: 'flex-start', width: '100%' }}><StatusPill tone={stateTones[job.status]}>{stateNames[job.status]}</StatusPill>{job.status === 'GENERATING' && <Progress size="small" percent={job.progress} style={{ width: '100%', margin: 0 }} />}{job.error && <span style={{ fontSize: 12, color: palette.error, overflowWrap: 'anywhere' }}>{job.error}</span>}</div> },
        { title: '文件大小', key: 'size', width: 100, render: (_: unknown, job) => job.status === 'READY' ? <Mono>{fileSize(job.fileSize)}</Mono> : <span style={small}>—</span> },
        { title: '创建', key: 'created', width: 180, render: (_: unknown, job) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}><span style={{ fontSize: 13 }}>{new Date(job.createdAt).toLocaleString()}</span><span style={{ ...small, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={job.createdBy}>{job.createdBy}</span></div> },
        { title: '操作', key: 'actions', width: 220, render: (_: unknown, job) => <Space size={0} wrap>{job.status === 'READY' && <Button type="link" size="small" icon={<DownloadOutlined />} href={`${endpoint}/${encodeURIComponent(job.id)}/download`}>下载</Button>}<Dropdown disabled={!canWrite} menu={{ items: Object.entries(formatNames).filter(([key]) => key !== job.format).map(([key, label]) => ({ key, label })), onClick: ({ key }) => void exportFormat(job, key) }}><Button type="link" size="small" disabled={!canWrite}>导出其他格式</Button></Dropdown>{job.status === 'FAILED' && <Button type="link" size="small" disabled={!canWrite} onClick={() => void retry(job)}>原快照重试</Button>}</Space> },
      ]} />
    </Panel>
    <Drawer title="报告模板" width="min(640px, 100vw)" open={editing} onClose={() => setEditing(false)} extra={<Button type="primary" onClick={() => void saveTemplate()}>保存模板</Button>}>
      <Form form={form} layout="vertical">
        <Form.Item name="id" hidden><Input /></Form.Item>
        <Form.Item name="name" label="方案名称" rules={[{ required: true, max: 200 }]}><Input /></Form.Item>
        <Form.Item name="company" label="公司名称" rules={[{ max: 200 }]}><Input /></Form.Item>
        <Form.Item label="公司 Logo（PNG，最多 1 MiB）"><Space direction="vertical">{logo && <img alt="公司 Logo 预览" src={logo} style={{ maxWidth: 160, maxHeight: 100 }} />}<Space><Upload accept="image/png" showUploadList={false} beforeUpload={file => { if (file.type !== 'image/png' || file.size > 1024 * 1024) { message.error('请选择不超过 1 MiB 的 PNG'); return false; } const reader = new FileReader(); reader.onload = () => setLogo(String(reader.result)); reader.readAsDataURL(file); return false; }}><Button icon={<UploadOutlined />}>选择 Logo</Button></Upload><Button onClick={() => setLogo(undefined)}>移除</Button></Space></Space></Form.Item>
        <Form.Item name="header" label="页眉" rules={[{ max: 500 }]}><Input /></Form.Item>
        <Form.Item name="footer" label="页脚" rules={[{ max: 500 }]}><Input /></Form.Item>
        <Form.Item name="ratingText" label="评定标准" rules={[{ max: 20000 }]}><Input.TextArea rows={5} /></Form.Item>
        <Form.Item name="advice" label="安全建议" rules={[{ max: 20000 }]}><Input.TextArea rows={5} /></Form.Item>
        <Form.Item name="enabledSections" label="Word / HTML / PDF 章节"><Checkbox.Group options={Object.entries(sections).map(([value, label]) => ({ value, label }))} /></Form.Item>
      </Form>
      <Alert type="info" showIcon message="模板更新只影响之后创建的报告，已有报告与重试均使用原冻结模板。Excel 固定保留八个工作表。" />
    </Drawer>
  </div>;
};
