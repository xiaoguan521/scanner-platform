import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Empty, Space, Tag } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { DataTable } from '../../components/DataState';
import { apiClient } from '../../api/client';
import type { AssetImportHistory } from '../../types';

export const AssetImportHistoryPage: React.FC = () => {
  const [items, setItems] = useState<AssetImportHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const reload = async () => {
    setLoading(true);
    try {
      const response = await apiClient.assetImportHistory();
      setItems(response.items);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '导入记录读取失败');
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => { void reload(); }, []);
  return (
    <Card title="资产导入记录" extra={<Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button>}>
      <Alert showIcon type="info" message="仅保留审计摘要" description="记录包含操作者、导入数量和时间，不保存 CSV 原文、目标地址或资产清单。最多展示最近 200 次导入。" style={{ marginBottom: 16 }} />
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
      <DataTable<AssetImportHistory>
        rowKey="id"
        dataSource={items}
        loading={loading}
        locale={{ emptyText: <Empty description="暂无导入记录" /> }}
        pagination={{ pageSize: 15, showTotal: total => `共 ${total} 条记录` }}
        columns={[
          { title: '导入时间', dataIndex: 'createdAt', width: 240, render: (value: string) => new Date(value).toLocaleString() },
          { title: '操作者', dataIndex: 'actor', width: 200 },
          { title: '结果', dataIndex: 'imported', render: (value: number, row: AssetImportHistory) => <Space><Tag color="green">成功 {value} 条</Tag><span>共 {row.total} 条</span></Space> },
        ]}
      />
    </Card>
  );
};
