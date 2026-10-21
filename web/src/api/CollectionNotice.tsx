import React from 'react';
import { Alert } from 'antd';
// Server API errors are shown explicitly. The UI never falls back to browser data.
export const CollectionNotice: React.FC<{ loading: boolean; error: string | null }> = ({ loading, error }) => {
  if (loading) return <Alert type="info" showIcon message="正在读取 Server 数据…" />;
  if (error) return (
    <Alert type="warning" showIcon
      message="当前模块 API 尚未可用"
      description={error + '。相关业务操作保持关闭。'}
    />
  );
  return null;
};
