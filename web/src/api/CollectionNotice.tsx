import React from 'react';
import { Alert } from 'antd';
import { isDemoMode } from './client';

// Server mode must be explicit about a missing 501 endpoint. Never use
// fallback mock data after request errors.
export const CollectionNotice: React.FC<{ loading: boolean; error: string | null }> = ({ loading, error }) => {
  if (isDemoMode) return null;
  if (loading) return <Alert type="info" showIcon message="正在读取 Server 数据…" />;
  if (error) return (
    <Alert type="warning" showIcon
      message="当前模块 API 尚未可用"
      description={error + '。没有回退到演示数据；相关业务操作保持关闭。'}
    />
  );
  return null;
};
