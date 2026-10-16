import React, { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Modal,
  Form,
  Select,
  Progress,
  Typography,
  Alert,
  message,
} from 'antd';
import {
  PlayCircleOutlined,
  PauseCircleOutlined,
  FieldTimeOutlined,
  StopOutlined,
  RadarChartOutlined,
  PlusOutlined,
} from '@ant-design/icons';
import { mockTasks, mockScopes } from '../../mock/data';
import { ScanTask, TaskChunk } from '../../types';
import { isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

const { Text } = Typography;

export const TasksPage: React.FC = () => {
  const { data: tasks, setData: setTasks, loading, error } = useCollection('tasks', mockTasks);
  const { data: scopes } = useCollection('scopes', mockScopes);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();

  const handleCreateTask = (values: any) => {
    if (!isDemoMode) return message.warning('真实任务创建和派发尚未开放');
    const scope = scopes.find((s) => s.id === values.scopeId && s.isActive);
    if (!scope) return message.warning('没有有效的演示授权范围');
    const newTask: ScanTask = {
      id: `task-${Date.now().toString().slice(-4)}`,
      scopeId: values.scopeId,
      scopeName: scope ? `${scope.cidrOrHost}` : '自定义目标段',
      engines: values.engines || ['nuclei'],
      status: 'PENDING',
      hardDeadline: new Date(Date.now() + 3600000).toISOString(),
      totalChunks: 0,
      completedChunks: 0,
      targetCount: 0,
      createdAt: new Date().toISOString(),
      chunks: [],
    };
    setTasks((prev) => [newTask, ...prev]);
    message.info('仅演示：添加待处理任务草稿，未分块下发或启动 Worker');
    setIsModalOpen(false);
    form.resetFields();
  };

  const handleStopTask = (taskId: string) => {
    if (!isDemoMode) return message.warning('停止任务必须由 Server 处理');
    Modal.confirm({
      title: '确认手动停止该扫描任务？',
      content: '仅改变演示页面；不会撤销实际租约或停止真实 Worker。',
      okText: '终止任务',
      okType: 'danger',
      onOk: () => {
        setTasks((prev) =>
          prev.map((t) => (t.id === taskId ? { ...t, status: 'CANCELED' } : t))
        );
        message.info(`仅演示：任务 ${taskId} 本地状态已变化，Server 未发生变更`);
      },
    });
  };

  // 展开行：展示每个分块详情
  const expandedRowRender = (record: ScanTask) => {
    const chunkColumns = [
      { title: '分块 ID', dataIndex: 'id', width: 120 },
      {
        title: '分派 Worker',
        dataIndex: 'workerNodeId',
        render: (w?: string) => (w ? <Tag color="geekblue">{w}</Tag> : <Text type="secondary">待领取</Text>),
      },
      {
        title: '已固定目标清单 (纯数字 IP:端口)',
        dataIndex: 'targets',
        render: (targets: string[]) => (
          <Space wrap size={[4, 4]}>
            {targets.map((t) => (
              <Tag key={t}>{t}</Tag>
            ))}
          </Space>
        ),
      },
      {
        title: '分块状态',
        dataIndex: 'status',
        width: 140,
        render: (status: string) => (
          <Tag color={status === 'COMPLETED' ? 'green' : status === 'RUNNING' ? 'processing' : 'default'}>
            {status}
          </Tag>
        ),
      },
      { title: '执行耗时', render: (_: any, r: TaskChunk) => `${r.startedAt || '-'} ~ ${r.finishedAt || '扫描中'}` },
    ];

    return (
      <div style={{ margin: '8px 0', background: 'rgba(0,0,0,0.1)', padding: 12, borderRadius: 6 }}>
        <Text strong style={{ display: 'block', marginBottom: 8 }}>
          任务分块执行明细 (Task Chunks) · 块间自动核验时间窗
        </Text>
        <Table
          columns={chunkColumns}
          dataSource={record.chunks}
          pagination={false}
          rowKey="id"
          size="small"
        />
      </div>
    );
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <CollectionNotice loading={loading} error={error} />
      <Alert
        message="调度策略：按目标分块与时间窗保护"
        description="扫描任务由控制面按目标拆分为若干块下发。Worker 单次只领一个块，每个块绑定本地硬截止时间（Hard Deadline）与租约。若失联超过租约，Worker 立即自终止。"
        type="info"
        showIcon
        icon={<RadarChartOutlined />}
      />

      <Card
        title="扫描任务队列与调度监控"
        bordered={false}
        extra={
          <Button type="primary" icon={<PlusOutlined />} disabled={!isDemoMode}
          onClick={() => setIsModalOpen(true)}>
            新建扫描任务
          </Button>
        }
      >
        <Table
          dataSource={tasks}
          rowKey="id"
          expandable={{ expandedRowRender, defaultExpandedRowKeys: ['task-8091'] }}
          columns={[
            { title: '任务 ID', dataIndex: 'id', width: 110 },
            { title: '目标授权范围', dataIndex: 'scopeName' },
            {
              title: '指定引擎',
              dataIndex: 'engines',
              width: 180,
              render: (engines: string[]) => (
                <Space>
                  {engines.map((e) => (
                    <Tag key={e} color={e === 'nuclei' ? 'purple' : 'cyan'}>
                      {e.toUpperCase()}
                    </Tag>
                  ))}
                </Space>
              ),
            },
            {
              title: '总进度 (完成块/总块)',
              render: (_, record) => (
                <div style={{ width: 160 }}>
                  <Progress
                    percent={record.totalChunks ? Math.round((record.completedChunks / record.totalChunks) * 100) : 0}
                    size="small"
                    status={record.status === 'COMPLETED' ? 'success' : 'active'}
                  />
                  <div style={{ fontSize: 11, color: '#64748b' }}>
                    {record.completedChunks} / {record.totalChunks} 分块 ({record.targetCount} 个目标)
                  </div>
                </div>
              ),
            },
            {
              title: '任务状态',
              dataIndex: 'status',
              width: 140,
              render: (status: string) => {
                const map: Record<string, { color: string; label: string }> = {
                  RUNNING: { color: 'processing', label: '执行中' },
                  WAITING_WINDOW: { color: 'warning', label: '等待时间窗' },
                  COMPLETED: { color: 'success', label: '已完成' },
                  PAUSED_WINDOW: { color: 'default', label: '窗口期暂停' },
                  CANCELED: { color: 'error', label: '已终止' },
                };
                return <Tag color={map[status]?.color || 'default'}>{map[status]?.label || status}</Tag>;
              },
            },
            {
              title: '本地硬截止时间',
              dataIndex: 'hardDeadline',
              width: 180,
              render: (d: string) => (
                <Space size={4}>
                  <FieldTimeOutlined style={{ color: '#fa8c16' }} />
                  <span style={{ fontSize: 12 }}>{d}</span>
                </Space>
              ),
            },
            {
              title: '操作',
              width: 100,
              render: (_, record) =>
                record.status === 'RUNNING' ? (
                  <Button
                    type="link"
                    danger
                    size="small"
                    icon={<StopOutlined />}
                    onClick={() => handleStopTask(record.id)}
                  >
                    停止
                  </Button>
                ) : (
                  <Text type="secondary">-</Text>
                ),
            },
          ]}
        />
      </Card>

      <Modal
        title="演示：创建待处理任务草稿"
        open={isModalOpen}
        onCancel={() => setIsModalOpen(false)}
        onOk={() => form.submit()}
        okButtonProps={{ disabled: !isDemoMode }}
      >
        <Form form={form} layout="vertical" onFinish={handleCreateTask}>
          <Form.Item
            name="scopeId"
            label="选择已审批范围"
            rules={[{ required: true, message: '必须选择经审批的范围' }]}
          >
            <Select placeholder="请选择授权范围">
              {scopes.map((s) => (
                <Select.Option key={s.id} value={s.id} disabled={!s.isActive}>
                  {s.cidrOrHost} (审批单: {s.approvalTicket})
                </Select.Option>
              ))}
            </Select>
          </Form.Item>
          <Form.Item
            name="engines"
            label="指定扫描引擎"
            initialValue={['nuclei']}
            rules={[{ required: true }]}
          >
            <Select mode="multiple">
              <Select.Option value="nuclei">Nuclei (Web/服务漏洞 POC)</Select.Option>
              <Select.Option value="trivy">Trivy (镜像系统与依赖漏洞)</Select.Option>
            </Select>
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};
