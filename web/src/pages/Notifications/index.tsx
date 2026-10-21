import React, { useEffect, useState } from 'react';
import { Alert, Badge, Button, Card, Empty, List, Space, Typography, message } from 'antd';
import { CheckOutlined, ReloadOutlined } from '@ant-design/icons';
import { apiClient } from '../../api/client';
import { NotificationSeverityTag } from '../../components/Semantic';
import type { Notification } from '../../types';

export const NotificationsPage: React.FC = () => {
  const [items, setItems] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const reload = async () => {
    setBusy(true);
    try {
      const next = await apiClient.notifications();
      setItems(next.items);
      setUnreadCount(next.unreadCount);
      setError('');
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : '通知读取失败');
    } finally {
      setBusy(false);
    }
  };

  useEffect(() => { void reload(); }, []);

  const markRead = async (item: Notification) => {
    try {
      await apiClient.markNotificationRead(item.id);
      await reload();
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : '通知状态更新失败');
    }
  };

  const markAllRead = async () => {
    try {
      await apiClient.markAllNotificationsRead();
      await reload();
    } catch (cause) {
      message.error(cause instanceof Error ? cause.message : '通知状态更新失败');
    }
  };

  return (
    <Card
      title={<Space><span>通知中心</span><Badge count={unreadCount} overflowCount={999} /></Space>}
      extra={<Space><Button icon={<ReloadOutlined />} onClick={() => void reload()} loading={busy}>刷新</Button><Button icon={<CheckOutlined />} onClick={() => void markAllRead()} disabled={!unreadCount || busy}>全部标记已读</Button></Space>}
    >
      {error && <Alert type="error" showIcon message={error} style={{ marginBottom: 16 }} />}
      <List
        itemLayout="vertical"
        locale={{ emptyText: <Empty description="暂无通知" /> }}
        dataSource={items}
        renderItem={item => (
          <List.Item
            actions={!item.readAt ? [<Button key="read" type="link" onClick={() => void markRead(item)}>标记已读</Button>] : []}
          >
            <List.Item.Meta
              title={<Space><NotificationSeverityTag value={item.severity} /><Typography.Text strong={!item.readAt}>{item.title}</Typography.Text>{!item.readAt && <Badge status="processing" text="未读" />}</Space>}
              description={<Space direction="vertical" size={4}><Typography.Text>{item.message}</Typography.Text><Typography.Text type="secondary">{new Date(item.createdAt).toLocaleString()}</Typography.Text></Space>}
            />
          </List.Item>
        )}
      />
    </Card>
  );
};
