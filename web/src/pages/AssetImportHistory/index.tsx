import React, { useCallback, useEffect, useState } from 'react';
import { Alert, Button, Empty, Input, Space, Typography } from 'antd';
import { Mono, StatusPill } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { TitleWithHelp } from '../../components/HelpTip';
import { ReloadOutlined } from '@ant-design/icons';
import { DataTable } from '../../components/DataState';
import { apiClient } from '../../api/client';
import type { AssetImportHistory } from '../../types';

export const AssetImportHistoryPage: React.FC = () => {
  const [items, setItems] = useState<AssetImportHistory[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const reload = useCallback(async () => {
    setLoading(true);
    try {
      const response = await apiClient.assetImportHistoryPage(page, pageSize, search);
      setItems(response.items);
      setTotal(response.total);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '导入记录读取失败');
    } finally {
      setLoading(false);
    }
  }, [page, pageSize, search]);
  useEffect(() => { void reload(); }, [reload]);
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title={<TitleWithHelp title="资产导入记录" helpTitle="仅保留审计摘要" help="记录包含操作者、导入数量和时间，不保存 CSV 原文、目标地址或资产清单。"/>}
        description={`共 ${total} 次导入 · 不保存 CSV 原文、目标地址或资产清单`}
      />
      {error && <Alert type="error" showIcon message={error} />}
      <Panel flush title="导入历史" extra={<Space wrap><Input.Search aria-label="导入记录搜索" placeholder="搜索操作者" allowClear value={search} onChange={event => { setSearch(event.target.value); setPage(1); }} style={{ width: 220 }} /><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={loading}>刷新</Button></Space>}>
        <DataTable<AssetImportHistory>
          rowKey="id"
          dataSource={items}
          loading={loading}
          tableLayout="fixed"
          locale={{ emptyText: <Empty description={search ? '没有符合条件的导入记录' : '暂无导入记录'} /> }}
          pagination={{ current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [15, 30, 60], showTotal: count => `共 ${count} 条记录`, onChange: (nextPage, nextSize) => { if (nextSize !== pageSize) { setPageSize(nextSize); setPage(1); } else setPage(nextPage); } }}
          columns={[
            { title: '导入时间', dataIndex: 'createdAt', width: 220, render: (value: string) => <Mono>{new Date(value).toLocaleString()}</Mono> },
            { title: '操作者', dataIndex: 'actor', width: 200, ellipsis: true, render: (value: string) => <Mono>{value}</Mono> },
            { title: '结果', dataIndex: 'imported', render: (value: number, row: AssetImportHistory) => <Space size={8}><StatusPill tone={value === row.total ? 'ok' : 'warning'}>成功 {value} 条</StatusPill><Typography.Text type="secondary">共 {row.total} 条</Typography.Text></Space> },
          ]}
        />
      </Panel>
    </div>
  );
};
