import React from 'react';
import { ErrorState, LoadingState } from '../components/DataState';
// Server API errors are shown explicitly. The UI never falls back to browser data.
export const CollectionNotice: React.FC<{ loading: boolean; error: string | null }> = ({ loading, error }) => {
  if (loading) return <LoadingState label="正在读取平台数据…" />;
  if (error) return <ErrorState title="数据加载失败" description={error + '。请稍后刷新页面重试。'} />;
  return null;
};
