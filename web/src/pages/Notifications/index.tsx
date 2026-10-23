import React, { useEffect, useState } from 'react';
import { Alert, Button, Empty, List, message } from 'antd';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { CheckOutlined, ReloadOutlined } from '@ant-design/icons';
import { apiClient, errorMessage } from '../../api/client';
import { NotificationSeverityTag } from '../../components/Semantic';
import type { Notification } from '../../types';

export const NotificationsPage: React.FC = () => {
  const { palette } = useAppTheme();
  const [items, setItems] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(15);
  const [total, setTotal] = useState(0);

  const reload = async () => {
    setBusy(true);
    try {
      const next = await apiClient.notificationsPage(page, pageSize);
      setItems(next.items);
      setUnreadCount(next.unreadCount);
      setTotal(next.total);
      setError('');
    } catch (cause) {
      setError(errorMessage(cause,'通知读取失败'));
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { void reload(); }, [page, pageSize]);

  const markRead = async (item: Notification) => {
    try {
      await apiClient.markNotificationRead(item.id);
      await reload();
    } catch (cause) {
      message.error(errorMessage(cause,'通知状态更新失败'));
    }
  };

  const markAllRead = async () => {
    try {
      await apiClient.markAllNotificationsRead();
      await reload();
    } catch (cause) {
      message.error(errorMessage(cause,'通知状态更新失败'));
    }
  };

  const small = { fontSize: 12, color: palette.textSecondary };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader title="通知中心" description={unreadCount ? `${unreadCount} 条未读通知` : '没有未读通知'}
        extra={<><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={busy}>刷新</Button><Button type="primary" icon={<CheckOutlined />} onClick={() => void markAllRead()} disabled={!unreadCount || busy}>全部标记已读</Button></>} />
      {error && <Alert type="error" showIcon message={error} />}
      <Panel flush title={`全部通知（${total.toLocaleString()}）`}>
        <List
          locale={{ emptyText: <Empty description="暂无通知" /> }}
          dataSource={items}
          pagination={{ current: page, pageSize, total, showSizeChanger: true, pageSizeOptions: [15, 30, 60], showTotal: count => `共 ${count} 条通知`, onChange: (nextPage, nextSize) => { if (nextSize !== pageSize) { setPageSize(nextSize); setPage(1); } else setPage(nextPage); }, style: { padding: '0 20px 16px' } }}
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
                  <span style={small}>{new Date(item.createdAt).toLocaleString()}</span>
                </div>
              </div>
            </List.Item>
          )}
        />
      </Panel>
    </div>
  );
};
