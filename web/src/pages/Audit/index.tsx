import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, DatePicker, Empty, Input, Space } from 'antd';
import { Mono, StatusPill } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { TitleWithHelp } from '../../components/HelpTip';
import type { Dayjs } from 'dayjs';
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { requestJSON } from '../../api/client';
import type { AuditLog } from '../../types';
import { buildAuditQuery, defaultAuditFilters, type AuditFilters } from './filters';

const pageSize = 50;

export const AuditPage: React.FC = () => {
  const { palette } = useAppTheme();
  const [filters, setFilters] = useState<AuditFilters>(defaultAuditFilters);
  const [draft, setDraft] = useState<AuditFilters>(defaultAuditFilters);
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null]>([null, null]);
  const [items, setItems] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async (signal?: AbortSignal) => {
    setLoading(true);
    try {
      const response = await requestJSON<{ items: AuditLog[]; total: number }>(`/api/v1/audit-logs${buildAuditQuery(filters, pageSize)}`, 'GET', undefined, signal);
      if (!signal?.aborted) { setItems(response.items); setTotal(response.total); setError(null); }
    } catch (cause) {
      if (!signal?.aborted) setError(cause instanceof Error ? cause.message : '审计日志不可用');
    } finally {
      if (!signal?.aborted) setLoading(false);
    }
  }, [filters]);

  useEffect(() => {
    const controller = new AbortController();
    void reload(controller.signal);
    return () => controller.abort();
  }, [reload]);

  const apply = () => {
    setFilters({ ...draft, page: 1 });
    setDraft(current => ({ ...current, page: 1 }));
  };
  const clear = () => {
    setDraft(defaultAuditFilters);
    setFilters(defaultAuditFilters);
    setRange([null, null]);
  };
  const dateChange = (next: [Dayjs | null, Dayjs | null] | null) => {
    const value = next ?? [null, null];
    setRange(value);
    setDraft(current => ({ ...current, from: value[0]?.startOf('day').toISOString() ?? '', to: value[1]?.endOf('day').toISOString() ?? '' }));
  };
  const small = { fontSize: 12, color: palette.textSecondary };
  const columns = useMemo(() => [
    { title: '时间', dataIndex: 'createdAt', width: 180, render: (value: string) => <span style={small}>{new Date(value).toLocaleString()}</span> },
    { title: '操作者', dataIndex: 'actor', width: 180, render: (value: string) => <Mono style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={value}>{value}</Mono> },
    { title: '动作', dataIndex: 'action', width: 220, render: (value: string) => <Mono style={{ fontWeight: 600 }}>{value}</Mono> },
    { title: '对象类型', dataIndex: 'objectType', width: 130, render: (value: string) => value ? <StatusPill tone="neutral">{value}</StatusPill> : <span style={small}>无</span> },
    { title: '对象 ID', dataIndex: 'objectId', render: (value: string) => value ? <Mono style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', ...small }} title={value}>{value}</Mono> : <span style={small}>无</span> },
  ], [palette]);
  const field = (label: string, control: React.ReactNode) => <label style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 12, color: palette.textTertiary, minWidth: 0 }}>{label}{control}</label>;

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <PageHeader title="审计日志" description="谁在何时执行了什么操作；记录只读，不提供删除或编辑" />
    {error && <Alert showIcon type="error" message="审计日志加载失败" description={error} />}
    <Panel title={<TitleWithHelp title="筛选审计记录" helpTitle="只读审计查询" help="仅管理员可查看谁在何时执行了什么操作及关联对象。敏感详情、目标地址和凭据不会通过此查询接口返回。"/>} extra={<Space><Button onClick={clear}>清空</Button><Button icon={<SearchOutlined />} type="primary" onClick={apply}>查询</Button></Space>}>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(190px, 100%), 1fr))', gap: 12 }}>
        {field('操作者', <Input aria-label="操作者" value={draft.actor} onChange={event => setDraft(current => ({ ...current, actor: event.target.value }))} placeholder="用户名或 ID" allowClear onPressEnter={apply} />)}
        {field('动作', <Input aria-label="动作" value={draft.action} onChange={event => setDraft(current => ({ ...current, action: event.target.value }))} placeholder="如 create_asset" allowClear onPressEnter={apply} />)}
        {field('对象类型', <Input aria-label="对象类型" value={draft.objectType} onChange={event => setDraft(current => ({ ...current, objectType: event.target.value }))} placeholder="如 asset" allowClear onPressEnter={apply} />)}
        {field('对象 ID', <Input aria-label="对象 ID" value={draft.objectId} onChange={event => setDraft(current => ({ ...current, objectId: event.target.value }))} allowClear onPressEnter={apply} />)}
        {field('时间范围', <DatePicker.RangePicker aria-label="时间范围" value={range} onChange={dateChange} allowEmpty={[true, true]} />)}
      </div>
    </Panel>
    <Panel flush title={`审计记录（${total.toLocaleString()}）`} extra={<Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button>}>
      <DataTable<AuditLog> rowKey="id" loading={loading} dataSource={items} columns={columns} tableLayout="fixed" locale={{ emptyText: <Empty description="暂无符合条件的审计记录" /> }} pagination={{ current: filters.page, pageSize, total, showSizeChanger: false, showTotal: count => `共 ${count} 条`, onChange: page => setFilters(current => ({ ...current, page })) }} scroll={{ x: 900 }} />
    </Panel>
  </div>;
};
