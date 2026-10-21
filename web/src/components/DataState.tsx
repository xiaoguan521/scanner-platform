import React from 'react';
import { Alert, Empty, Space, Spin, Table, Typography } from 'antd';
import type { ReactNode } from 'react';
import type { TableProps } from 'antd';

export const LoadingState: React.FC<{ label?: string }> = ({ label = '正在加载…' }) => (
  <div role="status" aria-live="polite" style={{ display: 'flex', justifyContent: 'center', padding: '18px 0' }}>
    <Space>
      <Spin size="small" />
      <Typography.Text type="secondary">{label}</Typography.Text>
    </Space>
  </div>
);

export const ErrorState: React.FC<{ title?: string; description: ReactNode }> = ({
  title = '数据加载失败',
  description,
}) => <Alert showIcon type="warning" message={title} description={description} />;

export const EmptyState: React.FC<{ description?: ReactNode }> = ({ description = '暂无数据' }) => (
  <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description={description} />
);

export function DataTable<RecordType extends object = Record<string, unknown>>(
  props: TableProps<RecordType>,
) {
  const { locale, ...rest } = props;
  return (
    <Table<RecordType>
      {...rest}
      locale={{ emptyText: <EmptyState />, ...locale }}
    />
  );
}
