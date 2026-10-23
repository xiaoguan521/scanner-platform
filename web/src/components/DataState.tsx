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

/** Shared pagination look: size changer, total count, and size options around the page size. */
// A fixed pageSize without onChange cannot change size, so it gets no size changer.
export function tablePaginationDefaults(pagination?: { pageSize?: number; onChange?: unknown }) {
  const pageSize = pagination?.pageSize ?? 10;
  const sizeOptions = [10, 20, 50, 100].includes(pageSize) ? [10, 20, 50, 100] : [pageSize, pageSize * 2, pageSize * 4];
  const resizable = pagination?.pageSize === undefined || Boolean(pagination.onChange);
  return { showSizeChanger: resizable, pageSizeOptions: sizeOptions, showTotal: (total: number) => `共 ${total} 条` };
}

export function DataTable<RecordType extends object = Record<string, unknown>>(
  props: TableProps<RecordType>,
) {
  const { locale, pagination, ...rest } = props;
  return (
    <Table<RecordType>
      {...rest}
      pagination={pagination === false ? false : { ...tablePaginationDefaults(pagination || undefined), ...pagination }}
      locale={{ emptyText: <EmptyState />, ...locale }}
    />
  );
}
