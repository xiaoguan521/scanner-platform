import React, { useEffect, useState } from 'react';
import { Alert, Button, Form, Input, InputNumber, message, Select, Switch } from 'antd';
import { DataTable } from '../../components/DataState';
import { Mono, StatusPill } from '../../components/Semantic';
import { AutoGrid, PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { Tone } from '../../theme/palette';
import { TitleWithHelp } from '../../components/HelpTip';
import { apiClient, errorMessage } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import type { NotificationDeliveryList, NotificationSettings, SystemSettings } from '../../types';

const timeZones: SystemSettings['timeZone'][] = ['Asia/Shanghai', 'UTC', 'America/New_York'];

export const SettingsPage: React.FC = () => {
  const { palette } = useAppTheme();
  const { isAdmin } = useAuth();
  const canEdit = isAdmin;
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
      if (active) setError(errorMessage(err,'系统设置读取失败'));
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
      message.error(errorMessage(err,'系统设置保存失败'));
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
      message.error(errorMessage(err,'Webhook 设置保存失败'));
    } finally {
      setBusy(false);
    }
  };

  const deliveryStates: Record<string, { tone: Tone; label: string }> = { DELIVERED: { tone: 'ok', label: '已投递' }, FAILED: { tone: 'warning', label: '重试中' }, DEAD: { tone: 'error', label: '已放弃' }, PENDING: { tone: 'neutral', label: '待投递' }, SENDING: { tone: 'running', label: '投递中' } };
  const small = { fontSize: 12, color: palette.textSecondary };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader title="系统设置" description="系统时区、登录会话和外部通知；设置变更会记录管理员审计"
        extra={<StatusPill tone={canEdit ? 'ok' : 'neutral'}>{canEdit ? '管理员可编辑' : '只读'}</StatusPill>} />
      {error && <Alert type="error" showIcon message={error} />}
      <AutoGrid min={380}>
        <Panel title={<TitleWithHelp title="基础设置" helpTitle="系统级偏好会影响后续登录和新建任务" help="时区用于后续系统时间展示与计划默认值；修改会话时长只影响新登录会话，已有会话仍按原到期时间失效。系统设置不会扩大扫描目标、端口范围或引擎权限；扫描授权仍以资产、端口申请和任务确认结果为准。"/>}>
          <Form form={form} layout="vertical" onFinish={save} disabled={!canEdit || !settings}>
            <Form.Item name="timeZone" label="系统时区" rules={[{ required: true, message: '请选择系统时区' }]}>
              <Select options={timeZones.map(value => ({ value, label: value }))} />
            </Form.Item>
            <Form.Item
              name="sessionDurationMinutes"
              label="登录会话时长（分钟）"
              rules={[{ required: true, type: 'number', min: 30, max: 1440, message: '请输入 30–1440 分钟' }]}
              extra="范围 30 分钟至 24 小时。"
            >
              <InputNumber min={30} max={1440} step={30} style={{ width: '100%' }} />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={busy} disabled={!canEdit || !settings}>保存设置</Button>
          </Form>
        </Panel>
        <Panel title={<TitleWithHelp title="外部通知 Webhook" helpTitle="默认关闭，发送安全摘要" help="启用后，平台内新增的授权、接受风险和扫描失败提醒会异步 POST 到指定地址。请求不包含目标地址、凭据、原始请求/响应或引擎输出；非回环地址必须使用 HTTPS，不跟随重定向。"/>}>
          <Form form={notificationForm} layout="vertical" onFinish={saveNotification} disabled={!canEdit || !notificationSettings}>
            <Form.Item name="webhookEnabled" label="启用 Webhook" valuePropName="checked">
              <Switch checkedChildren="启用" unCheckedChildren="关闭" />
            </Form.Item>
            <Form.Item
              name="webhookUrl"
              label="Webhook 地址"
              rules={[{ max: 2048, message: '地址不能超过 2048 个字符' }]}
              extra="使用 HTTPS 地址；本机隔离测试可使用 http://127.0.0.1 或 http://localhost。"
            >
              <Input placeholder="https://notify.example.test/scanner" />
            </Form.Item>
            <Button type="primary" htmlType="submit" loading={busy} disabled={!canEdit || !notificationSettings}>保存 Webhook 设置</Button>
          </Form>
        </Panel>
      </AutoGrid>
      <Panel flush title={`Webhook 投递记录（${deliveries?.total ?? 0}）`} extra={<span style={small}>失败只显示受限错误摘要，不显示响应正文</span>}>
        <DataTable<NotificationDeliveryList['items'][number]> rowKey="id" dataSource={deliveries?.items ?? []} pagination={false} tableLayout="fixed" locale={{ emptyText: '还没有需要投递的通知' }} columns={[
          { title: '状态', key: 'state', width: 120, render: (_: unknown, item) => { const state = deliveryStates[item.state] ?? { tone: 'neutral' as Tone, label: item.state }; return <StatusPill tone={state.tone}>{state.label}</StatusPill>; } },
          { title: '通知 ID', key: 'id', width: 260, render: (_: unknown, item) => <Mono style={{ display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={item.notificationId}>{item.notificationId}</Mono> },
          { title: '尝试次数', key: 'attempts', width: 100, render: (_: unknown, item) => <Mono>{item.attempts}</Mono> },
          { title: '错误摘要', key: 'error', render: (_: unknown, item) => item.lastError ? <span style={{ overflowWrap: 'anywhere' }}>{item.lastError}</span> : <span style={small}>无</span> },
        ]} />
      </Panel>
    </div>
  );
};
