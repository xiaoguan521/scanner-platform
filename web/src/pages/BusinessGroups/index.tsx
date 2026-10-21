import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Empty, Form, Input, message, Modal, Space, Tag, Typography } from 'antd';
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
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [form] = Form.useForm<{ name: string }>();

  const reload = async () => {
    setLoading(true);
    try {
      const response = await apiClient.businessGroups();
      setItems(response.items);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '业务组读取失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void reload(); }, []);

  const create = async ({ name }: { name: string }) => {
    setBusy(true);
    try {
      const item = await apiClient.createBusinessGroup(name.trim());
      setItems(prev => [...prev, item].sort((a, b) => a.name.localeCompare(b.name)));
      setOpen(false);
      form.resetFields();
      message.success('业务组已创建');
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : '业务组创建失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Alert showIcon type="info" message="业务组是资产登记的归属维度" description="新建资产或导入 CSV 时可复用已有业务组。删除资产不会删除业务组，便于保留组织维度和审计记录。" />
      <Card title="业务组" extra={<Space><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button><Button type="primary" icon={<PlusOutlined />} disabled={!canEdit} onClick={() => setOpen(true)}>新增业务组</Button></Space>}>
        {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
        <DataTable<BusinessGroup>
          rowKey="name"
          dataSource={items}
          loading={loading}
          locale={{ emptyText: <Empty description="暂无业务组，请先登记资产或创建业务组" /> }}
          pagination={{ pageSize: 15, showTotal: total => `共 ${total} 个业务组` }}
          columns={[
            { title: '业务组', dataIndex: 'name', render: (name: string) => <Typography.Text strong>{name}</Typography.Text> },
            { title: '资产数', dataIndex: 'assetCount', width: 140, render: (count: number) => <Tag color={count ? 'blue' : 'default'}>{count} 台</Tag> },
            { title: '创建时间', dataIndex: 'createdAt', width: 220, render: (value: string) => new Date(value).toLocaleString() },
          ]}
        />
      </Card>
      <Modal title="新增业务组" open={open} onCancel={() => setOpen(false)} onOk={() => form.submit()} confirmLoading={busy} destroyOnClose>
        <Form form={form} layout="vertical" onFinish={create}>
          <Form.Item name="name" label="业务组名称" rules={[{ required: true, whitespace: true, max: 100, message: '请输入 1–100 个字符的业务组名称' }]}>
            <Input autoFocus maxLength={100} placeholder="例如：平台服务" />
          </Form.Item>
        </Form>
      </Modal>
    </Space>
  );
};
