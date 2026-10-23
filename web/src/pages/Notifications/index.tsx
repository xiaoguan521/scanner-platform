import React from 'react';
import { Alert, Button, Empty, List, message } from 'antd';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { CheckOutlined, ReloadOutlined } from '@ant-design/icons';
import { apiClient, errorMessage } from '../../api/client';
import { usePageState, useQuery } from '../../api/query';
import { NotificationSeverityTag } from '../../components/Semantic';
import { formatTime } from '../../utils/time';
import type { Notification } from '../../types';

export const NotificationsPage: React.FC = () => {
  const { palette } = useAppTheme();
  const { page, pageSize, onChange: onPageChange } = usePageState(null, 15);
  const list = useQuery(signal => apiClient.notificationsPage(page, pageSize, false, signal), [page, pageSize], { errorFallback: '通知读取失败' });
  const items = list.data?.items ?? [];
  const unreadCount = list.data?.unreadCount ?? 0;
  const total = list.data?.total ?? 0;
  const { loading: busy, reload } = list;
  const error = list.error ?? '';

  const markRead = async (item: Notification) => {
    try {
      await apiClient.markNotificationRead(item.id);
      reload();
    } catch (cause) {
      message.error(errorMessage(cause,'通知状态更新失败'));
    }
  };

  const markAllRead = async () => {
    try {
      await apiClient.markAllNotificationsRead();
      reload();
    } catch (cause) {
      message.error(errorMessage(cause,'通知状态更新失败'));
    }
  };

  const small = { fontSize: 12, color: palette.textSecondary };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader title="通知中心" description={unreadCount ? `${unreadCount} 条未读通知` : '没有未读通知'}
        extra={<><Button icon={<ReloadOutlined />} onClick={reload} loading={busy}>刷新</Button><Button type="primary" icon={<CheckOutlined />} onClick={() => void markAllRead()} disabled={!unreadCount || busy}>全部标记已读</Button></>} />
      {error && <Alert type="error" showIcon message={error} />}
      <Panel flush title={`全部通知（${total.toLocaleString()}）`}>
        <List
          locale={{ emptyText: <Empty description="暂无通知" /> }}
          dataSource={items}
          pagination={{ current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [15, 30, 60], showTotal: count => `共 ${count} 条通知`, onChange: onPageChange, style: { padding: '0 20px 16px' } }}
          renderItem={item => (
            <List.Item style={{ padding: '14px 20px', borderBlockEnd: `1px solid ${palette.borderSubtle}`, background: item.readAt ? undefined : palette.bgSubtle }}
              actions={!item.readAt ? [<Button key="read" type="link" size="small" onClick={() => void markRead(item)}>标记已读</Button>] : []}>
              <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', minWidth: 0 }}>
                <span aria-hidden="true" style={{ width: 8, height: 8, marginTop: 7, borderRadius: '50%', flex: '0 0 auto', background: item.readAt ? 'transparent' : palette.primary }} />
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 0 }}>
                  <span style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 8 }}>
                    <NotificationSeverityTag value={item.severity} />
                    <span style={{ fontWeight: item.readAt ? 400 : 600, color: palette.text }}>{item.title}</span>
                    {!item.readAt && <span style={{ ...small, color: palette.primary }}>未读</span>}
                  </span>
                  <span style={{ color: palette.textSecondary, overflowWrap: 'anywhere' }}>{item.message}</span>
                  <span style={small}>{formatTime(item.createdAt)}</span>
                </div>
              </div>
            </List.Item>
          )}
        />
      </Panel>
    </div>
  );
};
