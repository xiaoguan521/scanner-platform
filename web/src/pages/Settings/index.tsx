import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, List, message, Select, Space, Switch, Tag, Typography } from 'antd';
import { apiClient } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import type { NotificationDeliveryList, NotificationSettings, SystemSettings } from '../../types';

const timeZones: SystemSettings['timeZone'][] = ['Asia/Shanghai', 'UTC', 'America/New_York'];

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const canEdit = user?.role === 'admin';
  const [form] = Form.useForm<SystemSettings>();
  const [notificationForm] = Form.useForm<NotificationSettings>();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [notificationSettings, setNotificationSettings] = useState<NotificationSettings | null>(null);
  const [deliveries, setDeliveries] = useState<NotificationDeliveryList | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const apply = (next: SystemSettings) => {
    setSettings(next);
    form.setFieldsValue(next);
  };

  const applyNotificationSettings = (next: NotificationSettings) => {
    setNotificationSettings(next);
    notificationForm.setFieldsValue(next);
  };

  useEffect(() => {
    let active = true;
    Promise.all([apiClient.systemSettings(), apiClient.notificationSettings(), apiClient.notificationDeliveries()]).then(([next, notification, deliveryList]) => {
      if (active) {
        apply(next);
        applyNotificationSettings(notification);
        setDeliveries(deliveryList);
      }
    }).catch(err => {
      if (active) setError(err instanceof Error ? err.message : '系统设置读取失败');
    });
    return () => { active = false; };
  }, []);

  const save = async (values: SystemSettings) => {
    setBusy(true);
    try {
      const saved = await apiClient.saveSystemSettings(values);
      apply(saved);
      setError('');
      message.success('系统设置已保存；新登录会话将使用新的时长');
    } catch (err) {
      message.error(err instanceof Error ? err.message : '系统设置保存失败');
    } finally {
      setBusy(false);
    }
  };

  const saveNotification = async (values: NotificationSettings) => {
    setBusy(true);
    try {
      const saved = await apiClient.saveNotificationSettings(values);
      applyNotificationSettings(saved);
      const deliveryList = await apiClient.notificationDeliveries();
      setDeliveries(deliveryList);
      setError('');
      message.success(saved.webhookEnabled ? 'Webhook 通知已启用' : 'Webhook 通知已关闭');
    } catch (err) {
      message.error(err instanceof Error ? err.message : 'Webhook 设置保存失败');
    } finally {
      setBusy(false);
    }
  };

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="系统设置" extra={<Tag>{canEdit ? '管理员可编辑' : '只读'}</Tag>}>
        <Alert
          type={error ? 'error' : 'info'}
          showIcon
          message={error || '系统级偏好会影响后续登录和新建任务'}
          description="时区用于后续系统时间展示与计划默认值；修改会话时长只影响新登录会话，已有会话仍按原到期时间失效。通知中心和可选 Webhook 投递都由 Server 管理。"
          style={{ marginBottom: 16 }}
        />
        <Form form={form} layout="vertical" onFinish={save} disabled={!canEdit || !settings}>
          <Form.Item name="timeZone" label="系统时区" rules={[{ required: true, message: '请选择系统时区' }]}>
            <Select options={timeZones.map(value => ({ value, label: value }))} />
          </Form.Item>
          <Form.Item
            name="sessionDurationMinutes"
            label="登录会话时长（分钟）"
            rules={[{ required: true, type: 'number', min: 30, max: 1440, message: '请输入 30–1440 分钟' }]}
            extra="范围 30 分钟至 24 小时；服务端会再次校验。"
          >
            <InputNumber min={30} max={1440} step={30} style={{ width: '100%' }} />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy} disabled={!canEdit || !settings}>保存设置</Button>
        </Form>
      </Card>
      <Card title="外部通知 Webhook" extra={<Tag>{canEdit ? '管理员可编辑' : '只读'}</Tag>}>
        <Alert
          type="info"
          showIcon
          message="默认关闭，发送安全摘要"
          description="启用后，平台内新增的授权、接受风险和扫描失败提醒会异步 POST 到指定地址。请求不包含目标地址、凭据、原始请求/响应或引擎输出；非回环地址必须使用 HTTPS，不跟随重定向。"
          style={{ marginBottom: 16 }}
        />
        <Form form={notificationForm} layout="vertical" onFinish={saveNotification} disabled={!canEdit || !notificationSettings}>
          <Form.Item name="webhookEnabled" label="启用 Webhook" valuePropName="checked">
            <Switch checkedChildren="启用" unCheckedChildren="关闭" />
          </Form.Item>
          <Form.Item
            name="webhookUrl"
            label="Webhook 地址"
            rules={[{ max: 2048, message: '地址不能超过 2048 个字符' }]}
            extra="生产地址使用 HTTPS；本机隔离测试可使用 http://127.0.0.1 或 http://localhost。"
          >
            <Input placeholder="https://notify.example.test/scanner" />
          </Form.Item>
          <Button type="primary" htmlType="submit" loading={busy} disabled={!canEdit || !notificationSettings}>保存 Webhook 设置</Button>
        </Form>
      </Card>
      <Card title="Webhook 投递状态">
        <Typography.Paragraph type="secondary">最近投递共 {deliveries?.total ?? 0} 条；失败只显示受限错误摘要，不显示 Webhook 响应正文。</Typography.Paragraph>
        <List
          size="small"
          locale={{ emptyText: '还没有需要投递的通知' }}
          dataSource={deliveries?.items ?? []}
          renderItem={item => <List.Item>
            <Space wrap>
              <Tag color={item.state === 'DELIVERED' ? 'green' : item.state === 'DEAD' ? 'red' : item.state === 'FAILED' ? 'orange' : 'blue'}>{item.state}</Tag>
              <Typography.Text code>{item.notificationId}</Typography.Text>
              <Typography.Text type="secondary">尝试 {item.attempts} 次</Typography.Text>
              {item.lastError && <Typography.Text type="secondary">{item.lastError}</Typography.Text>}
            </Space>
          </List.Item>}
        />
      </Card>
      <Card title="当前生效范围">
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          系统设置由 Server SQLite 持久化并记录管理员审计。它不会扩大扫描目标、端口范围或引擎权限；扫描授权仍以资产、端口申请和任务确认结果为准。
        </Typography.Paragraph>
      </Card>
    </Space>
  );
};
