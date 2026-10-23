import React, { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Empty, Form, Input, message, Modal, Space, Typography } from 'antd';
import { Mono, StatusPill } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { TitleWithHelp } from '../../components/HelpTip';
import { PlusOutlined, ReloadOutlined } from '@ant-design/icons';
import { DataTable } from '../../components/DataState';
import { apiClient } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import type { BusinessGroup } from '../../types';

export const BusinessGroupsPage: React.FC = () => {
  const { user } = useAuth();
  const canEdit = user?.role === 'admin' || user?.role === 'security_engineer';
  const [items, setItems] = useState<BusinessGroup[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<{ name: string }>();

  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const response = await apiClient.businessGroupsPage(page, pageSize, search);
      setItems(response.items);
      setTotal(response.total);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '业务组读取失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search]);
  useEffect(() => { void reload(); }, [reload]);

  const create = async ({ name }: { name: string }) => {
    setBusy(true);
    try {
      const item = await apiClient.createBusinessGroup(name.trim());
      setPage(1);
      setSearch('');
      setOpen(false);
      form.resetFields();
      message.success('业务组已创建');
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : '业务组创建失败');
    } finally {
      setBusy(false);
    }
  };

  const withAssets = items.filter(item => item.assetCount > 0).length;
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title={<TitleWithHelp title="业务组" helpTitle="业务组是资产登记的归属维度" help="新建资产或导入 CSV 时可复用已有业务组。删除资产不会删除业务组，便于保留组织维度和审计记录。"/>}
        description={`共 ${total} 个业务组${items.length ? ` · 本页 ${withAssets} 个已关联资产` : ''}`}
        extra={<Button type="primary" icon={<PlusOutlined />} disabled={!canEdit} onClick={() => setOpen(true)}>新增业务组</Button>}
      />
      {error && <Alert type="error" showIcon message={error} />}
      <Panel flush title="业务组列表" extra={<Space wrap><Input.Search aria-label="业务组搜索" placeholder="搜索业务组" allowClear value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} style={{ width: 220 }} /><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button></Space>}>
        <DataTable<BusinessGroup>
          rowKey="name"
          dataSource={items}
          loading={loading}
          tableLayout="fixed"
          locale={{ emptyText: <Empty description={search ? '没有符合条件的业务组' : '暂无业务组，请先登记资产或创建业务组'} /> }}
          pagination={{ current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [15, 30, 60], showTotal: count => `共 ${count} 个业务组`, onChange: (nextPage, nextSize) => { if (nextSize !== pageSize) { setPageSize(nextSize); setPage(1); } else setPage(nextPage); } }}
          columns={[
            { title: '业务组', dataIndex: 'name', ellipsis: true, render: (name: string) => <Typography.Text strong>{name}</Typography.Text> },
            { title: '资产数', dataIndex: 'assetCount', width: 140, render: (count: number) => <StatusPill tone={count ? 'running' : 'neutral'}>{count} 台</StatusPill> },
            { title: '创建时间', dataIndex: 'createdAt', width: 220, render: (value: string) => <Mono>{new Date(value).toLocaleString()}</Mono> },
          ]}
        />
      </Panel>
      <Modal title="新增业务组" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={busy} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={create}>
          <Form.Item name="name" label="业务组名称" rules={[{ required: true, whitespace: true, max: 100, message: '请输入 1–100 个字符的业务组名称' }]}>
            <Input autoFocus maxLength={100} placeholder="例如：平台服务" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};
