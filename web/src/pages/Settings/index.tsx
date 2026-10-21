import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Form, InputNumber, message, Select, Space, Tag, Typography } from 'antd';
import { apiClient } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import type { SystemSettings } from '../../types';

const timeZones: SystemSettings['timeZone'][] = ['Asia/Shanghai', 'UTC', 'America/New_York'];

export const SettingsPage: React.FC = () => {
  const { user } = useAuth();
  const canEdit = user?.role === 'admin';
  const [form] = Form.useForm<SystemSettings>();
  const [settings, setSettings] = useState<SystemSettings | null>(null);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);

  const apply = (next: SystemSettings) => {
    setSettings(next);
    form.setFieldsValue(next);
  };

  useEffect(() => {
    let active = true;
    apiClient.systemSettings().then(next => {
      if (active) apply(next);
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

  return (
    <Space direction="vertical" size={16} style={{ width: '100%' }}>
      <Card title="系统设置" extra={<Tag>{canEdit ? '管理员可编辑' : '只读'}</Tag>}>
        <Alert
          type={error ? 'error' : 'info'}
          showIcon
          message={error || '系统级偏好会影响后续登录和新建任务'}
          description="时区用于后续系统时间展示与计划默认值；修改会话时长只影响新登录会话，已有会话仍按原到期时间失效。通知中心和通知投递尚未启用。"
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
      <Card title="当前生效范围">
        <Typography.Paragraph type="secondary" style={{ marginBottom: 0 }}>
          系统设置由 Server SQLite 持久化并记录管理员审计。它不会扩大扫描目标、端口范围或引擎权限；扫描授权仍以资产、端口申请和任务确认结果为准。
        </Typography.Paragraph>
      </Card>
    </Space>
  );
};
