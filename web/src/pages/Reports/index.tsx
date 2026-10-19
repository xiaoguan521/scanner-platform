import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Checkbox, DatePicker, Drawer, Dropdown, Empty, Form, Input, message, Progress, Select, Space, Table, Tag, Typography, Upload } from 'antd';
import type { Dayjs } from 'dayjs';
import { DownloadOutlined, FileTextOutlined, SettingOutlined, UploadOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { isDemoMode, requestJSON } from '../../api/client';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';
import { mockAssets, mockTasks } from '../../mock/data';
import type { ReportJob, ReportScope, ReportTemplate } from './types';

const sections = { cover: '封面', overview: '综述', assets: '资产统计', 'asset-risks': '资产风险信息', 'asset-details': '资产详情', 'risk-statistics': '风险统计', 'risk-details': '风险详情', appendix: '附录' };
const stateNames = { QUEUED: '排队中', GENERATING: '生成中', READY: '就绪', FAILED: '失败' };
const formatNames = { html: 'HTML', xlsx: 'Excel', docx: 'Word' };
const endpoint = '/api/v1/reports';
const templatesEndpoint = '/api/v1/report-templates';
const { Text } = Typography;

export const ReportsPage: React.FC = () => {
  const { user } = useAuth();
  const canWrite = !isDemoMode && (user?.role === 'admin' || user?.role === 'security_engineer');
  const { data: assets, loading: assetsLoading, error: assetsError } = useCollection('assets', mockAssets);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useCollection('tasks', mockTasks);
  const [templates, setTemplates] = useState<ReportTemplate[]>([]);
  const [jobs, setJobs] = useState<ReportJob[]>([]);
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
  const selectedTemplate = templates.find(t => t.id === templateId);
  const reload = useCallback(async (signal?: AbortSignal) => {
    if (isDemoMode) return;
    try {
      const [reports, nextTemplates] = await Promise.all([
        requestJSON<{ items: ReportJob[] }>(endpoint, 'GET', undefined, signal),
        requestJSON<{ items: ReportTemplate[] }>(templatesEndpoint, 'GET', undefined, signal),
      ]);
      if (!signal?.aborted) { setJobs(reports.items); setTemplates(nextTemplates.items); setError(null); }
    } catch (cause) { if (!signal?.aborted) setError(cause instanceof Error ? cause.message : '报告服务不可用'); }
  }, []);
  useEffect(() => { const controller = new AbortController(); let loading = false; const load = async () => { if (loading) return; loading = true; await reload(controller.signal); loading = false; }; void load(); const timer = window.setInterval(() => void load(), 2000); return () => { controller.abort(); window.clearInterval(timer); }; }, [reload]);
  const generate = async () => {
    const scope: ReportScope = { assetId, businessGroup, taskId, from: range?.[0]?.startOf('day').toISOString(), to: range?.[1]?.endOf('day').toISOString() };
    setBusy(true);
    try { await requestJSON(endpoint, 'POST', { templateId, format, scope }); message.success('已冻结数据快照，报告将在后台生成'); await reload(); }
    catch (cause) { message.error(cause instanceof Error ? cause.message : '生成失败'); }
    finally { setBusy(false); }
  };
  const retry = async (job: ReportJob) => { try { await requestJSON(`${endpoint}/${encodeURIComponent(job.id)}/retry`, 'POST'); message.success('已使用原快照重新排队'); await reload(); } catch (cause) { message.error(String(cause)); } };
  const exportFormat = async (job: ReportJob, nextFormat: string) => { try { await requestJSON(`${endpoint}/${encodeURIComponent(job.id)}/formats`, 'POST', { format: nextFormat }); message.success('已使用相同数据快照生成其他格式'); await reload(); } catch (cause) { message.error(String(cause)); } };
  const editTemplate = () => { if (!selectedTemplate) return; form.setFieldsValue({ ...selectedTemplate, enabledSections: Object.keys(sections).filter(k => selectedTemplate.sections[k] !== false) }); setLogo(selectedTemplate.logo); setEditing(true); };
  const saveTemplate = async () => {
    try { const values = await form.validateFields(); const { enabledSections, ...fields } = values; const body = { ...fields, logo: logo ?? '', sections: Object.fromEntries(Object.keys(sections).map(key => [key, enabledSections.includes(key)])) }; await requestJSON(`${templatesEndpoint}/${encodeURIComponent(templateId)}`, 'PUT', body); setEditing(false); message.success('模板已保存，新报告将使用更新后的模板'); await reload(); }
    catch (cause) { if (cause instanceof Error) message.error(cause.message); }
  };
  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <CollectionNotice loading={assetsLoading || tasksLoading} error={assetsError || tasksError || error} />
    <Alert showIcon type="info" message="后台生成与历史记录" description="每次生成冻结一份带版本的数据快照，HTML、Excel 与 Word 使用相同数据与统计规则。弱口令本次未启用，登录入口单独统计。报告上限 64 MiB，失败可用原快照重试。" />
    {isDemoMode && <Alert showIcon type="warning" message="演示模式不创建报告作业；请连接 Server 后生成和下载报告。" />}
    <Card title={<Space><FileTextOutlined />生成安全报告</Space>} extra={<Button icon={<SettingOutlined />} disabled={!canWrite || !selectedTemplate} onClick={editTemplate}>配置模板</Button>}>
      <Space wrap align="end">
        <div><Text type="secondary">报告模板</Text><Select value={templateId} onChange={setTemplateId} style={{ display: 'block', width: 190 }} options={templates.map(t => ({ value: t.id, label: t.name }))} /></div>
        <div><Text type="secondary">输出格式</Text><Select value={format} onChange={setFormat} style={{ display: 'block', width: 130 }} options={Object.entries(formatNames).map(([value, label]) => ({ value, label }))} /></div>
        <div><Text type="secondary">业务组</Text><Select allowClear value={businessGroup} onChange={setBusinessGroup} style={{ display: 'block', width: 180 }} placeholder="全部业务组" options={groups.map(value => ({ value, label: value }))} /></div>
        <div><Text type="secondary">资产</Text><Select allowClear showSearch optionFilterProp="label" value={assetId} onChange={setAssetId} style={{ display: 'block', width: 210 }} placeholder="全部资产" options={assets.map(a => ({ value: a.id, label: a.address }))} /></div>
        <div><Text type="secondary">扫描任务</Text><Select allowClear showSearch optionFilterProp="label" value={taskId} onChange={setTaskId} style={{ display: 'block', width: 220 }} placeholder="全部任务" options={tasks.map(t => ({ value: t.id, label: `${t.id} · ${t.status}` }))} /></div>
        <div><Text type="secondary">最近发现时间</Text><DatePicker.RangePicker value={range} onChange={setRange} allowEmpty={[true, true]} /></div>
        <Button type="primary" loading={busy} disabled={!canWrite || !!error || !!assetsError || !!tasksError || !selectedTemplate} onClick={() => void generate()}>生成报告</Button>
      </Space>
      <Typography.Paragraph type="secondary" style={{ marginTop: 14, marginBottom: 0 }}>任务范围使用该任务的历史观察记录；失败、取消或尚未完成的任务会保留状态说明。未知字段显示“未采集”或“未知”。</Typography.Paragraph>
    </Card>
    <Card title="报告历史" extra={<Button onClick={() => void reload()} disabled={isDemoMode}>刷新</Button>}>
      <Table<ReportJob> rowKey="id" dataSource={jobs} scroll={{ x: 1300 }} pagination={{ pageSize: 10 }} locale={{ emptyText: <Empty description="暂无报告，选择范围后生成" /> }} columns={[
        { title: '报告名称', dataIndex: 'name', width: 330, ellipsis: true, render: (value: string, job) => <span title={`${value}\n快照 ${job.snapshotId}`}>{value}</span> },
        { title: '格式', dataIndex: 'format', width: 85, render: (value: ReportJob['format']) => formatNames[value] },
        { title: '状态', dataIndex: 'status', width: 190, render: (value: ReportJob['status'], job) => <div><Tag color={value === 'READY' ? 'success' : value === 'FAILED' ? 'error' : 'processing'}>{stateNames[value]}</Tag>{value === 'GENERATING' && <Progress size="small" percent={job.progress} />}{job.error && <Text type="danger">{job.error}</Text>}</div> },
        { title: '文件大小', dataIndex: 'fileSize', width: 110, render: (value: number, job) => job.status === 'READY' ? `${(value / 1024).toFixed(1)} KiB` : '—' },
        { title: '创建时间', dataIndex: 'createdAt', width: 180, render: (value: string) => new Date(value).toLocaleString() },
        { title: '创建人 / 快照版本', width: 170, render: (_: unknown, job) => `${job.createdBy} / v${job.snapshotVersion}` },
        { title: '操作', width: 280, render: (_: unknown, job) => <Space>{job.status === 'READY' && <Button size="small" icon={<DownloadOutlined />} href={`${endpoint}/${encodeURIComponent(job.id)}/download`}>下载</Button>}<Dropdown disabled={!canWrite} menu={{ items: Object.entries(formatNames).filter(([key]) => key !== job.format).map(([key, label]) => ({ key, label })), onClick: ({ key }) => void exportFormat(job, key) }}><Button size="small" disabled={!canWrite}>导出其他格式</Button></Dropdown>{job.status === 'FAILED' && <Button size="small" disabled={!canWrite} onClick={() => void retry(job)}>原快照重试</Button>}</Space> },
      ]} />
    </Card>
    <Drawer title="报告模板" width={620} open={editing} onClose={() => setEditing(false)} extra={<Button type="primary" onClick={() => void saveTemplate()}>保存模板</Button>}>
      <Form form={form} layout="vertical">
        <Form.Item name="id" hidden><Input /></Form.Item>
        <Form.Item name="name" label="方案名称" rules={[{ required: true, max: 200 }]}><Input /></Form.Item>
        <Form.Item name="company" label="公司名称" rules={[{ max: 200 }]}><Input /></Form.Item>
        <Form.Item label="公司 Logo（PNG，最多 1 MiB）"><Space direction="vertical">{logo && <img alt="公司 Logo 预览" src={logo} style={{ maxWidth: 160, maxHeight: 100 }} />}<Space><Upload accept="image/png" showUploadList={false} beforeUpload={file => { if (file.type !== 'image/png' || file.size > 1024 * 1024) { message.error('请选择不超过 1 MiB 的 PNG'); return false; } const reader = new FileReader(); reader.onload = () => setLogo(String(reader.result)); reader.readAsDataURL(file); return false; }}><Button icon={<UploadOutlined />}>选择 Logo</Button></Upload><Button onClick={() => setLogo(undefined)}>移除</Button></Space></Space></Form.Item>
        <Form.Item name="header" label="页眉" rules={[{ max: 500 }]}><Input /></Form.Item>
        <Form.Item name="footer" label="页脚" rules={[{ max: 500 }]}><Input /></Form.Item>
        <Form.Item name="ratingText" label="评定标准" rules={[{ max: 20000 }]}><Input.TextArea rows={5} /></Form.Item>
        <Form.Item name="advice" label="安全建议" rules={[{ max: 20000 }]}><Input.TextArea rows={5} /></Form.Item>
        <Form.Item name="enabledSections" label="Word / HTML 章节"><Checkbox.Group options={Object.entries(sections).map(([value, label]) => ({ value, label }))} /></Form.Item>
      </Form>
      <Alert type="info" showIcon message="模板更新只影响之后创建的报告，已有报告与重试均使用原冻结模板。Excel 固定保留八个工作表。" />
    </Drawer>
  </div>;
};
