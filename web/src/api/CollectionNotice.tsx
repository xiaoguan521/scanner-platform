import React from 'react';
import { ErrorState, LoadingState } from '../components/DataState';
// Server API errors are shown explicitly. The UI never falls back to browser data.
export const CollectionNotice: React.FC<{ loading: boolean; error: string | null }> = ({ loading, error }) => {
  if (loading) return <LoadingState label="正在读取 Server 数据…" />;
  if (error) return <ErrorState title="当前模块 API 尚未可用" description={error + '。相关业务操作保持关闭。'} />;
  return null;
};
