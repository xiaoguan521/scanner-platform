import React from 'react';
import { Alert } from 'antd';
import { ErrorState, LoadingState } from '../components/DataState';
// Server API errors are shown explicitly. The UI never falls back to browser data.
// Once a page has data, the table's own spinner covers reloads, and a failed
// refresh becomes a small notice above the last loaded results.
export const CollectionNotice: React.FC<{ loading: boolean; error: string | null; hasData?: boolean }> = ({ loading, error, hasData = false }) => {
  if (hasData) return error ? <Alert type="warning" showIcon banner message={`数据刷新失败：${error}。当前显示的是上次加载的结果。`} /> : null;
  if (loading) return <LoadingState label="正在读取平台数据…" />;
  if (error) return <ErrorState title="数据加载失败" description={error + '。请稍后刷新页面重试。'} />;
  return null;
};
