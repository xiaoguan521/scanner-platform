import React, { useEffect, useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { apiClient } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { pollIntervals, pollWhileVisible } from '../../api/polling';
import { useAuth } from '../../auth/AuthProvider';
import type { ApprovalDecision, AuthorizedScope, PortRequest, ReviewStatus, TimeWindow } from '../../types';
import { scopeExpiryLabel, scopeExpiryState, type ScopeExpiryFilter } from './expiry';

const { Text } = Typography;
const weekdays = [
  { value: 1, label: '周一' }, { value: 2, label: '周二' },
  { value: 3, label: '周三' }, { value: 4, label: '周四' },
  { value: 5, label: '周五' }, { value: 6, label: '周六' }, { value: 0, label: '周日' },
];
const statusNames: Record<ReviewStatus | 'REVOKED', string> = {
  PENDING: '待审核', APPROVED: '已批准', REJECTED: '已驳回', REVOKED: '已撤销',
};
type ScopeForm = {
  assetId: string;
  weekdays: number[];
  start: string;
  end: string;
  timeZone: string;
  expiresAt: string;
};
type ReviewTarget = { kind: 'scope'; id: string; requestedBy?: string } |
  { kind: 'port'; id: string; port: number; requestedBy?: string };

export const ScopesPage: React.FC = () => {
  const { user } = useAuth();
  const { data: assets } = useCollection('assets');
  const [scopes, setScopes] = useState<AuthorizedScope[]>([]);
  const [scopePage, setScopePage] = useState(1);
  const [scopePageSize, setScopePageSize] = useState(10);
  const [scopeTotal, setScopeTotal] = useState(0);
  const [selectedScopeIDs, setSelectedScopeIDs] = useState<React.Key[]>([]);
  const [expiryCounts, setExpiryCounts] = useState({ expiring: 0, expired: 0 });
  const [ports, setPorts] = useState<PortRequest[]>([]);
  const [portPage, setPortPage] = useState(1);
  const [portPageSize, setPortPageSize] = useState(10);
  const [portTotal, setPortTotal] = useState(0);
  const [portStatus, setPortStatus] = useState('ALL');
  const [portSearch, setPortSearch] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expiryFilter, setExpiryFilter] = useState<ScopeExpiryFilter>('all');
  const [scopeQuery, setScopeQuery] = useState('');
  const [scopeSearch, setScopeSearch] = useState('');
  useEffect(() => { const timer = window.setTimeout(() => setScopeSearch(scopeQuery.trim()), 300); return () => window.clearTimeout(timer); }, [scopeQuery]);
  const [reloadKey, setReloadKey] = useState(0);
  const [requestOpen, setRequestOpen] = useState(false);
  const [editingScope, setEditingScope] = useState<AuthorizedScope | null>(null);
  const [reviewTarget, setReviewTarget] = useState<ReviewTarget | null>(null);
  const [renewOpen, setRenewOpen] = useState(false);
  const [renewExpiry, setRenewExpiry] = useState('');
  const [busy, setBusy] = useState(false);
  const [requestForm] = Form.useForm<ScopeForm>();
  const [reviewForm] = Form.useForm<ApprovalDecision>();
  const pendingPortReview = reviewTarget?.kind === 'port';
  const hostAssets = useMemo(() => assets.filter(asset => asset.kind === 'host'), [assets]);
  const canRequest = user?.role === 'admin' || user?.role === 'security_engineer';
  const canReview = user?.role === 'admin' || user?.role === 'ops_approver';
  const scopeStatus = (scope: AuthorizedScope): ReviewStatus | 'REVOKED' =>
    scope.status ?? (scope.isActive ? 'APPROVED' : 'PENDING');

  useEffect(() => {
    const controller = new AbortController();
    let inFlight = false;
    const load = (initial = false) => {
      if (inFlight) return;
      inFlight = true;
      if (initial) setLoading(true);
      Promise.all([
        apiClient.scopesPage(scopePage, scopePageSize, expiryFilter, controller.signal, scopeSearch),
        apiClient.portRequestsPage(portPage, portPageSize, { status: portStatus, search: portSearch }, controller.signal),
      ]).then(([scopeResult, portResult]) => {
        if (controller.signal.aborted) return;
        setScopes(scopeResult.items);
        setScopeTotal(scopeResult.total);
        setExpiryCounts({ expiring: scopeResult.expiringCount, expired: scopeResult.expiredCount });
        setPorts(portResult.items);
        setPortTotal(portResult.total);
        setError(null);
      }).catch(cause => {
        if (!controller.signal.aborted) setError(cause instanceof Error ? cause.message : '授权清册服务不可用');
      }).finally(() => {
        inFlight = false;
        if (!controller.signal.aborted) setLoading(false);
      });
    };
    load(true);
    const stop = pollWhileVisible(() => load(), pollIntervals.reference);
    return () => { controller.abort(); stop(); };
  }, [scopePage, scopePageSize, expiryFilter, scopeSearch, portPage, portPageSize, portStatus, portSearch, reloadKey]);

  useEffect(() => { if (scopePage !== 1) setScopePage(1); }, [expiryFilter, scopeSearch]);
  useEffect(() => { if (portPage !== 1) setPortPage(1); }, [portStatus, portSearch]);
  const refresh = () => setReloadKey(value => value + 1);

  const requestScope = async (values: ScopeForm) => {
    if (!canRequest) return;
    setBusy(true);
    try {
      const expiry = new Date(values.expiresAt);
      if (!Number.isFinite(expiry.getTime())) throw new Error('请选择有效的截止时间');
      if (values.start === values.end) throw new Error('开始与结束时间不能相同');
      if (!values.weekdays?.length) throw new Error('请选择允许的星期');
      const windows: TimeWindow[] = [{ weekdays: values.weekdays, start: values.start, end: values.end, timeZone: values.timeZone }];
      const input = { assetId: values.assetId, timeWindows: windows, expiresAt: expiry.toISOString() };
      const result = editingScope ? await apiClient.updateScope(editingScope.id, input) : await apiClient.requestScope(input);
      setScopes(prev => editingScope ? prev.map(scope => scope.id === result.id ? result : scope) : [result, ...prev]);
      setScopePage(1);
      refresh();
      requestForm.resetFields();
      setRequestOpen(false);
      setEditingScope(null);
      message.success(editingScope ? '修改已保存，授权已重置为待审核' : '范围申请已保存，等待另一位审批人审核');
    } catch (e) {
      message.error(e instanceof Error ? e.message : '提交授权申请失败');
    } finally { setBusy(false); }
  };
  const openReview = (target: ReviewTarget) => {
    if (!canReview || target.requestedBy === user?.id) return;
    reviewForm.setFieldsValue({ decision: 'APPROVE', approvalTicket: '', note: '', kind: 'WEB' });
    setReviewTarget(target);
  };
  const editScope = (scope: AuthorizedScope) => {
    const window = scope.timeWindows[0];
    const expiry = new Date(scope.expiresAt);
    requestForm.setFieldsValue({
      assetId: scope.assetId ?? '', weekdays: window?.weekdays ?? [], start: window?.start ?? '09:00', end: window?.end ?? '18:00',
      timeZone: window?.timeZone ?? 'Asia/Shanghai',
      expiresAt: Number.isFinite(expiry.getTime()) ? new Date(expiry.getTime() - expiry.getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '',
    });
    setEditingScope(scope);
    setRequestOpen(true);
  };
  const deleteScope = (scope: AuthorizedScope) => Modal.confirm({
    title: '删除待审核授权', content: '该授权记录会从列表移除。已批准的授权必须先撤销，系统会保留审批审计记录。',
    okText: '删除', okButtonProps: { danger: true }, cancelText: '取消',
    onOk: async () => {
      try { await apiClient.deleteScope(scope.id); setScopes(prev => prev.filter(item => item.id !== scope.id)); refresh(); message.success('授权记录已删除'); }
      catch (cause) { message.error(cause instanceof Error ? cause.message : '删除失败'); throw cause; }
    },
  });
  const revokeScope = (scope: AuthorizedScope) => Modal.confirm({
    title: '撤销已批准授权', content: `撤销后 ${scope.cidrOrHost} 将不再处于授权状态，历史审批记录会保留。`,
    okText: '撤销授权', okButtonProps: { danger: true }, cancelText: '取消',
    onOk: async () => {
      try { const updated = await apiClient.revokeScope(scope.id); setScopes(prev => prev.map(item => item.id === updated.id ? updated : item)); refresh(); message.success('授权已撤销'); }
      catch (cause) { message.error(cause instanceof Error ? cause.message : '撤销失败'); throw cause; }
    },
  });
  const renewScopes = async () => {
    if (!canRequest || selectedScopeIDs.length === 0) return;
    const expiry = new Date(renewExpiry);
    if (!Number.isFinite(expiry.getTime())) {
      message.error('请选择有效的新的截止时间');
      return;
    }
    setBusy(true);
    try {
      const result = await apiClient.renewScopes(selectedScopeIDs.map(String), expiry.toISOString());
      setScopes(previous => previous.map(scope => result.items.find(item => item.id === scope.id) ?? scope));
      setSelectedScopeIDs([]);
      setRenewOpen(false);
      setRenewExpiry('');
      refresh();
      message.success(`已提交 ${result.items.length} 条续期申请，等待重新审批`);
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : '批量续期失败，记录未改变');
    } finally { setBusy(false); }
  };
  const submitReview = async (decision: ApprovalDecision) => {
    if (!canReview || !reviewTarget) return;
    setBusy(true);
    try {
      if (reviewTarget.kind === 'scope') {
        const updated = await apiClient.reviewScope(reviewTarget.id, decision);
        setScopes(prev => prev.map(s => s.id === updated.id ? updated : s));
      } else {
        const updated = await apiClient.reviewPort(reviewTarget.id, reviewTarget.port, decision);
        setPorts(prev => prev.map(p => p.assetId === updated.assetId && p.port === updated.port ? updated : p));
      }
      refresh();
      setReviewTarget(null);
      message.success(decision.decision === 'APPROVE' ? '审批结果已记录' : '驳回结果已记录');
    } catch (e) {
      message.error(e instanceof Error ? e.message : '审批失败，记录未改变');
    } finally { setBusy(false); }
  };
  const renderDecision = (status: ReviewStatus | 'REVOKED', target: ReviewTarget) => (
    <Space>
      <Tag color={status === 'APPROVED' ? 'green' : status === 'REJECTED' ? 'red' : 'gold'}>{statusNames[status]}</Tag>
      {status === 'PENDING' && <Button size="small" disabled={!canReview || target.requestedBy === user?.id} onClick={() => openReview(target)}>审核</Button>}
    </Space>
  );

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <CollectionNotice loading={loading} error={error} />
    {expiryCounts.expired > 0
      ? <Alert showIcon type="error" message={`有 ${expiryCounts.expired} 条已批准授权已过期`} description="过期授权不会被用于扫描；请重新申请并完成审批。" />
      : expiryCounts.expiring > 0
        ? <Alert showIcon type="warning" message={`有 ${expiryCounts.expiring} 条授权将在 7 天内到期`} description="请提前续期并重新完成审批，避免任务因授权失效而无法领取。" />
        : null}
    <Alert showIcon type="warning" message="审批记录不等于扫描执行许可"
      description="当前只保存已登记主机 IP 的授权申请及端口人工审核结果。审批记录用于管理台账；任务按明确登记的端口和任务时间窗执行，跳过端口不会下发。" />
    <Card title="扫描授权范围与执行时间窗" extra={<Space>
      <Text type="secondary">共 {scopeTotal} 条</Text>
      <Input aria-label="授权范围搜索" placeholder="搜索资产地址或 ID" allowClear value={scopeQuery} onChange={event => setScopeQuery(event.target.value)} style={{ width: 200 }} />
      <Select aria-label="授权期限筛选" value={expiryFilter} onChange={setExpiryFilter} style={{ width: 150 }}
        options={[{ value: 'all', label: '全部期限' }, { value: 'expiring', label: '7 天内到期' }, { value: 'expired', label: '已过期' }]} />
      <Button disabled={!canRequest || selectedScopeIDs.length === 0 || busy} onClick={() => setRenewOpen(true)}>批量续期{selectedScopeIDs.length ? `（${selectedScopeIDs.length}）` : ''}</Button>
      <Button type="primary" icon={<PlusOutlined />} disabled={!canRequest} onClick={() => setRequestOpen(true)}>申请范围授权</Button>
    </Space>}>
      <DataTable<AuthorizedScope> dataSource={scopes} rowKey="id" loading={loading} scroll={{ x: 1200 }}
        rowSelection={{
          selectedRowKeys: selectedScopeIDs,
          preserveSelectedRowKeys: true,
          getCheckboxProps: scope => ({ disabled: !canRequest || scopeStatus(scope) !== 'APPROVED' || busy }),
          onChange: keys => setSelectedScopeIDs(keys),
        }}
        pagination={{ current: scopePage, pageSize: scopePageSize, total: scopeTotal, showSizeChanger: true, pageSizeOptions: [10, 20, 50], showTotal: total => `共 ${total} 项`, onChange: (page, size) => { if (size !== scopePageSize) { setScopePageSize(size); setScopePage(1); } else setScopePage(page); } }}
        columns={[
          { title: '目标 IP', dataIndex: 'cidrOrHost', render: (v: string) => <Tag>{v}</Tag> },
          { title: '上限', dataIndex: 'maxTargets', render: (v: number) => v + ' 台' },
          { title: '允许时间', dataIndex: 'timeWindows', render: (windows: TimeWindow[]) => <Space direction="vertical" size={0}>{windows.map((w, i) => <Text key={i}>{w.weekdays.map(day => weekdays.find(d => d.value === day)?.label).join('、')} {' '}{w.start}–{w.end} ({w.timeZone})</Text>)}</Space> },
          { title: '截止时间', dataIndex: 'expiresAt', render: (v: string) => v ? new Date(v).toLocaleString() : '未填写' },
          { title: '审批单', render: (_: unknown, scope: AuthorizedScope) => <Space direction="vertical" size={0}><Text>{scope.approvalTicket || '待审批'}</Text><Text type="secondary">{scope.approvedBy || '无审批人'}</Text></Space> },
          { title: '状态', render: (_: unknown, scope: AuthorizedScope) => <Space direction="vertical">{renderDecision(scopeStatus(scope), { kind: 'scope', id: scope.id, requestedBy: scope.requestedBy })}{(() => { const expiry = scopeExpiryState(scope); return expiry !== 'NOT_APPLICABLE' && <Tag color={expiry === 'EXPIRED' ? 'error' : expiry === 'EXPIRING' ? 'warning' : 'success'}>{scopeExpiryLabel[expiry]}</Tag>; })()}</Space> },
          { title: '操作', width: 200, fixed: 'right', render: (_: unknown, scope: AuthorizedScope) => { const status = scopeStatus(scope); return <Space wrap><Button size="small" disabled={!canRequest || status === 'REJECTED' || status === 'REVOKED'} onClick={() => editScope(scope)}>修改</Button>{status === 'APPROVED' ? <Button size="small" danger disabled={!canRequest && !canReview} onClick={() => revokeScope(scope)}>撤销</Button> : <Button size="small" danger disabled={!canRequest} onClick={() => deleteScope(scope)}>删除</Button>}</Space>; } },
        ]} />
    </Card>
    <Card title="资产端口申请审批" extra={<Space wrap>
      <Input aria-label="端口申请搜索" placeholder="搜索资产地址或 ID" allowClear value={portSearch} onChange={event => setPortSearch(event.target.value)} style={{ width: 200 }} />
      <Select aria-label="端口申请状态筛选" value={portStatus} onChange={setPortStatus} style={{ width: 130 }} options={[{ value: 'ALL', label: '全部状态' }, { value: 'PENDING', label: '待审核' }, { value: 'APPROVED', label: '已批准' }, { value: 'REJECTED', label: '已驳回' }]} />
      <Text type="secondary">共 {portTotal} 条 · 已标记跳过的端口不会派发</Text>
    </Space>}>
      <DataTable<PortRequest> dataSource={ports} loading={loading} rowKey={p => p.assetId + ':' + p.port} scroll={{ x: 1050 }}
        pagination={{ current: portPage, pageSize: portPageSize, total: portTotal, showSizeChanger: true, pageSizeOptions: [10, 20, 50], showTotal: total => `共 ${total} 项`, onChange: (page, size) => { if (size !== portPageSize) { setPortPageSize(size); setPortPage(1); } else setPortPage(page); } }}
        columns={[
          { title: '资产地址', dataIndex: 'address' }, { title: '端口', dataIndex: 'port' }, { title: '端口类型', dataIndex: 'kind', render: (v: string) => v || '待审核' },
          { title: '状态', render: (_: unknown, p: PortRequest) => p.kind === 'EXCLUDED_PROXY' ? <Tag>已跳过</Tag> : renderDecision(p.status, { kind: 'port', id: p.assetId, port: p.port, requestedBy: p.requestedBy }) },
          { title: '审批单', dataIndex: 'approvalTicket', render: (v: string) => v || '—' }, { title: '审核人', dataIndex: 'reviewedBy', render: (v: string) => v || '—' }, { title: '备注', dataIndex: 'reviewNote' },
        ]} />
    </Card>
    <Modal title="批量续期授权范围" open={renewOpen} onCancel={() => { setRenewOpen(false); setRenewExpiry(''); }} onOk={() => void renewScopes()} okButtonProps={{ loading: busy, disabled: selectedScopeIDs.length === 0 }}>
      <Alert type="warning" showIcon message={`将续期 ${selectedScopeIDs.length} 条已批准授权`} description="续期会保留原目标和时间窗，但立即清除原审批并重置为待审核；不会直接延长扫描执行权限。" style={{ marginBottom: 14 }} />
      <Typography.Text strong>新的授权截止时间</Typography.Text>
      <Input style={{ marginTop: 8 }} type="datetime-local" value={renewExpiry} onChange={event => setRenewExpiry(event.target.value)} />
    </Modal>
    <Modal title={editingScope ? '修改授权范围' : '申请扫描授权（单个主机 IP）'} open={requestOpen}
      onCancel={() => { setRequestOpen(false); setEditingScope(null); requestForm.resetFields(); }} onOk={() => requestForm.submit()} okButtonProps={{ loading: busy }}>
      {editingScope?.status === 'APPROVED' && <Alert type="warning" showIcon style={{ marginBottom: 14 }} message="保存修改会立即清除原审批，更新后的授权需要重新审核。" />}
      <Form<ScopeForm> form={requestForm} layout="vertical" onFinish={requestScope} initialValues={{ weekdays: [1, 2, 3, 4, 5], start: '09:00', end: '18:00', timeZone: 'Asia/Shanghai' }}>
        <Form.Item name="assetId" label="从资产台账选择主机" rules={[{ required: true }]}><Select showSearch optionFilterProp="label" options={hostAssets.map(a => ({ value: a.id, label: a.address + ' (' + a.businessGroup + ')' }))} /></Form.Item>
        <Form.Item name="weekdays" label="允许星期" rules={[{ required: true, type: 'array', min: 1 }]}><Select mode="multiple" options={weekdays} /></Form.Item>
        <Space align="start"><Form.Item name="start" label="起始时间" rules={[{ required: true }]}><Input placeholder="09:00" maxLength={5} /></Form.Item><Form.Item name="end" label="结束时间（可跨午夜）" rules={[{ required: true }]}><Input placeholder="18:00" maxLength={5} /></Form.Item></Space>
        <Form.Item name="timeZone" label="时区" rules={[{ required: true }]}><Select options={['Asia/Shanghai', 'Asia/Singapore', 'UTC', 'Asia/Tokyo'].map(z => ({ value: z, label: z }))} /></Form.Item>
        <Form.Item name="expiresAt" label="授权截止时间" rules={[{ required: true }]} extra="必须晚于当前时间；最大有效期为一年"><Input type="datetime-local" /></Form.Item>
      </Form>
    </Modal>
    <Modal title="人工审批" open={!!reviewTarget} onCancel={() => setReviewTarget(null)} onOk={() => reviewForm.submit()} okButtonProps={{ loading: busy }}>
      <Alert type="info" showIcon style={{ marginBottom: 14 }} message="不能审批自己提交的申请；审批需填写记录编号。" />
      <Form form={reviewForm} layout="vertical" onFinish={submitReview}>
        <Form.Item name="decision" label="处理意见" rules={[{ required: true }]}><Select options={[{ value: 'APPROVE', label: '批准' }, { value: 'REJECT', label: '驳回' }]} /></Form.Item>
        {pendingPortReview && <Form.Item name="kind" label="经人工确认的端口类型" rules={[{ required: true }]}><Select options={[{ value: 'WEB', label: 'WEB（明确确认是可扫描 Web 服务）' }, { value: 'NON_WEB', label: '非 Web（Web 扫描器不得扫描）' }]} /></Form.Item>}
        <Form.Item name="approvalTicket" label="审批工单号" rules={[{ required: true, min: 3 }]}><Input maxLength={120} placeholder="如 SEC-2026-001" /></Form.Item>
        <Form.Item name="note" label="审核说明"><Input.TextArea rows={3} maxLength={400} /></Form.Item>
      </Form>
    </Modal>
  </div>;
};
