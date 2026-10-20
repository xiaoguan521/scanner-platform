import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, DatePicker, Empty, Input, Space, Table, Typography } from 'antd';
import type { Dayjs } from 'dayjs';
import { ReloadOutlined, SearchOutlined } from '@ant-design/icons';
import { isDemoMode, requestJSON } from '../../api/client';
import type { AuditLog } from '../../types';
import { buildAuditQuery, defaultAuditFilters, type AuditFilters } from './filters';

const pageSize = 50;

export const AuditPage: React.FC = () => {
  const [filters, setFilters] = useState<AuditFilters>(defaultAuditFilters);
  const [draft, setDraft] = useState<AuditFilters>(defaultAuditFilters);
  const [range, setRange] = useState<[Dayjs | null, Dayjs | null]>([null, null]);
  const [items, setItems] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const reload = useCallback(async (signal?: AbortSignal) => {
    if (isDemoMode) return;
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
  const columns = useMemo(() => [
    { title: '时间', dataIndex: 'createdAt', width: 190, render: (value: string) => new Date(value).toLocaleString() },
    { title: '操作者', dataIndex: 'actor', width: 180, ellipsis: true },
    { title: '动作', dataIndex: 'action', width: 220, ellipsis: true },
    { title: '对象类型', dataIndex: 'objectType', width: 130 },
    { title: '对象 ID', dataIndex: 'objectId', width: 260, ellipsis: true },
  ], []);

  return <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
    <Alert showIcon type="info" message="只读审计查询" description="仅管理员可查看谁在何时执行了什么操作及关联对象。敏感详情、目标地址和凭据不会通过此查询接口返回。" />
    {isDemoMode && <Alert showIcon type="warning" message="演示模式不读取审计日志" description="连接 Server 并使用管理员账号后可查询 SQLite 中的审计记录。" />}
    {!isDemoMode && error && <Alert showIcon type="error" message="审计日志加载失败" description={error} />}
    <Card title="筛选审计记录" extra={<Space><Button onClick={clear}>清空</Button><Button icon={<SearchOutlined />} type="primary" onClick={apply}>查询</Button><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button></Space>}>
      <Space wrap>
        <Input value={draft.actor} onChange={event => setDraft(current => ({ ...current, actor: event.target.value }))} placeholder="操作者" allowClear style={{ width: 180 }} />
        <Input value={draft.action} onChange={event => setDraft(current => ({ ...current, action: event.target.value }))} placeholder="动作，如 create_asset" allowClear style={{ width: 220 }} />
        <Input value={draft.objectType} onChange={event => setDraft(current => ({ ...current, objectType: event.target.value }))} placeholder="对象类型" allowClear style={{ width: 160 }} />
        <DatePicker.RangePicker value={range} onChange={dateChange} allowEmpty={[true, true]} />
      </Space>
    </Card>
    <Card title={`审计记录（${total}）`}>
      <Table<AuditLog> rowKey="id" loading={loading} dataSource={items} columns={columns} locale={{ emptyText: <Empty description="暂无符合条件的审计记录" /> }} pagination={{ current: filters.page, pageSize, total, showSizeChanger: false, onChange: page => setFilters(current => ({ ...current, page })) }} scroll={{ x: 900 }} />
      <Typography.Paragraph type="secondary" style={{ marginBottom: 0, marginTop: 12 }}>审计记录由业务事务写入；本页面不提供删除、编辑或导出敏感详情的入口。</Typography.Paragraph>
    </Card>
  </div>;
};
