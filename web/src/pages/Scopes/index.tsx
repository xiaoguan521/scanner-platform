import React, { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Modal,
  Form,
  Input,
  InputNumber,
  Select,
  Alert,
  message,
  Typography,
} from 'antd';
import {
  PlusOutlined,
  CalendarOutlined,
  AuditOutlined,
  CheckCircleOutlined,
  ClockCircleOutlined,
} from '@ant-design/icons';
import { mockScopes } from '../../mock/data';
import { AuthorizedScope } from '../../types';

const { Text } = Typography;

export const ScopesPage: React.FC = () => {
  const [scopes, setScopes] = useState<AuthorizedScope[]>(mockScopes);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();

  const handleAddScope = (values: any) => {
    const newScope: AuthorizedScope = {
      id: `scope-${Date.now().toString().slice(-4)}`,
      cidrOrHost: values.cidrOrHost,
      maxTargets: values.maxTargets || 128,
      timeWindows: [
        {
          weekdays: values.weekdays || [1, 2, 3, 4, 5],
          start: values.start || '01:00',
          end: values.end || '05:00',
          timeZone: 'Asia/Shanghai',
        },
      ],
      approvedBy: values.approvedBy,
      approvalTicket: values.approvalTicket,
      expiresAt: values.expiresAt || '2026-12-31 23:59:59',
      isActive: true,
    };
    setScopes([newScope, ...scopes]);
    message.success('授权范围及时间窗审批已登记');
    setIsModalOpen(false);
    form.resetFields();
  };

  const getWeekdayLabels = (weekdays: number[]) => {
    const map = ['周日', '周一', '周二', '周三', '周四', '周五', '周六'];
    return weekdays.map((w) => map[w]).join('、');
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* 调度安全与时间窗合规说明 */}
      <Alert
        message="授权范围与时间窗硬约束"
        description="所有扫描必须严格绑定经审批的 CIDR 范围和审批工单；执行期间 Worker 按目标分块执行，块与块之间严格校验时间窗，到点自然暂停，次日继续。任务具备 Worker 本地强制硬截止时间。"
        type="info"
        showIcon
        icon={<AuditOutlined />}
      />

      <Card
        title="扫描授权范围与执行时间窗"
        bordered={false}
        extra={
          <Button type="primary" icon={<PlusOutlined />} onClick={() => setIsModalOpen(true)}>
            新建范围授权与时间窗
          </Button>
        }
      >
        <Table
          dataSource={scopes}
          rowKey="id"
          columns={[
            { title: '授权 ID', dataIndex: 'id', width: 110 },
            {
              title: '授权范围 / CIDR',
              dataIndex: 'cidrOrHost',
              render: (text: string) => <Tag color="blue">{text}</Tag>,
            },
            {
              title: '规模上限',
              dataIndex: 'maxTargets',
              width: 120,
              render: (val: number) => `${val} 主机`,
            },
            {
              title: '允许扫描时间窗 (Windows)',
              dataIndex: 'timeWindows',
              render: (windows) => {
                if (!windows || windows.length === 0) return <Text type="secondary">全天禁止</Text>;
                return (
                  <Space direction="vertical" size={2}>
                    {windows.map((w: any, idx: number) => (
                      <div key={idx} style={{ fontSize: 13 }}>
                        <ClockCircleOutlined style={{ marginRight: 6, color: '#fa8c16' }} />
                        <span>{getWeekdayLabels(w.weekdays)}</span>
                        <Tag color="orange" style={{ marginLeft: 8 }}>
                          {w.start} ~ {w.end} ({w.timeZone})
                        </Tag>
                      </div>
                    ))}
                  </Space>
                );
              },
            },
            {
              title: '审批凭据 / 工单',
              render: (_, record) => (
                <Space direction="vertical" size={2}>
                  <Text strong>{record.approvalTicket}</Text>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    审批人: {record.approvedBy}
                  </Text>
                </Space>
              ),
            },
            {
              title: '有效期截止',
              dataIndex: 'expiresAt',
              width: 170,
            },
            {
              title: '生效状态',
              dataIndex: 'isActive',
              width: 100,
              render: (active: boolean) => (
                <Tag color={active ? 'success' : 'default'} icon={active ? <CheckCircleOutlined /> : undefined}>
                  {active ? '已生效' : '已归档'}
                </Tag>
              ),
            },
          ]}
        />
      </Card>

      <Modal
        title="新建扫描授权与时间窗"
        open={isModalOpen}
        onCancel={() => setIsModalOpen(false)}
        onOk={() => form.submit()}
      >
        <Form form={form} layout="vertical" onFinish={handleAddScope}>
          <Form.Item
            name="cidrOrHost"
            label="授权目标网段 (CIDR) 或主机"
            rules={[{ required: true, message: '请输入授权网段' }]}
            extra="Worker 不展开 CIDR，由控制面在下发前计算固定为 IP:端口"
          >
            <Input placeholder="例如: 192.0.2.0/24" />
          </Form.Item>
          <Form.Item name="maxTargets" label="最大允许目标数上限" initialValue={128}>
            <InputNumber min={1} max={1024} style={{ width: '100%' }} />
          </Form.Item>
          <Form.Item
            name="approvalTicket"
            label="审批工单编号"
            rules={[{ required: true, message: '必须具备审批工单' }]}
          >
            <Input placeholder="例如: SEC-APPROVAL-202610-120" />
          </Form.Item>
          <Form.Item
            name="approvedBy"
            label="工单审批人"
            rules={[{ required: true, message: '请填写审批人' }]}
          >
            <Input placeholder="例如: 刘主管 (安全运营部)" />
          </Form.Item>
          <Form.Item name="weekdays" label="时间窗允许日期" initialValue={[1, 2, 3, 4, 5]}>
            <Select mode="multiple">
              <Select.Option value={1}>周一</Select.Option>
              <Select.Option value={2}>周二</Select.Option>
              <Select.Option value={3}>周三</Select.Option>
              <Select.Option value={4}>周四</Select.Option>
              <Select.Option value={5}>周五</Select.Option>
              <Select.Option value={6}>周六</Select.Option>
              <Select.Option value={0}>周日</Select.Option>
            </Select>
          </Form.Item>
          <Space style={{ display: 'flex' }}>
            <Form.Item name="start" label="起始时间 (HH:MM)" initialValue="01:00">
              <Input placeholder="01:00" />
            </Form.Item>
            <Form.Item name="end" label="结束时间 (HH:MM)" initialValue="05:00">
              <Input placeholder="05:00" />
            </Form.Item>
          </Space>
        </Form>
      </Modal>
    </div>
  );
};
