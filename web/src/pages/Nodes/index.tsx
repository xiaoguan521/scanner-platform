import React, { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Badge,
  Typography,
  Alert,
  Tooltip,
  Modal,
  message,
} from 'antd';
import {
  ClusterOutlined,
  SafetyCertificateOutlined,
  RollbackOutlined,
  CheckCircleOutlined,
  WarningOutlined,
} from '@ant-design/icons';
import { mockNodes, mockRuleBundles } from '../../mock/data';
import { NodeInfo, RuleBundle } from '../../types';

const { Text } = Typography;

export const NodesPage: React.FC = () => {
  const [nodes] = useState<NodeInfo[]>(mockNodes);
  const [ruleBundles, setRuleBundles] = useState<RuleBundle[]>(mockRuleBundles);

  const handleRollback = (targetVersion: string) => {
    Modal.confirm({
      title: `安全回滚确认：回退至版本 [${targetVersion}]？`,
      content:
        '严格依据架构硬规则 §5 与 §4.4：版本回滚属于高危敏感操作，必须留存审计日志，并在 Worker 确认当前无任务引用该版本后执行 CURRENT 指针原子重定向。',
      okText: '已获审批，确认回滚',
      okType: 'danger',
      cancelText: '取消',
      onOk: () => {
        setRuleBundles((prev) =>
          prev.map((r) => ({
            ...r,
            isCurrent: r.version === targetVersion,
            isBackup: r.isCurrent,
          }))
        );
        message.warning(`规则包指针 CURRENT 已原子切换至 ${targetVersion}，审计日志已记录`);
      },
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <Alert
        message="三权分立与节点安全控制 (架构硬规则 §4)"
        description="所有 Worker 节点均无数据库凭据，仅通过 TLS 节点 API 交互；Worker 拥有私有运行时与独立的 nftables 网络围栏；Updater 为规则目录唯一写入者；CURRENT 为纯文本指针，采用临时文件 fsync + rename 原子切换。"
        type="info"
        showIcon
        icon={<SafetyCertificateOutlined />}
      />

      {/* 节点状态列表 */}
      <Card title="分布式节点拓扑与网络围栏监控" bordered={false}>
        <Table
          dataSource={nodes}
          rowKey="id"
          pagination={false}
          columns={[
            {
              title: '节点标识',
              dataIndex: 'id',
              width: 170,
              render: (id: string, record: NodeInfo) => (
                <Space>
                  <ClusterOutlined />
                  <Text strong>{id}</Text>
                  {record.kind === 'worker' ? (
                    <Tag color="cyan">Worker</Tag>
                  ) : (
                    <Tag color="geekblue">Updater</Tag>
                  )}
                </Space>
              ),
            },
            { title: '内网通信 IP', dataIndex: 'ip', width: 140 },
            {
              title: '节点运行状态',
              dataIndex: 'status',
              width: 120,
              render: (s: string) => {
                if (s === 'BUSY') return <Badge status="processing" text="执行任务中" />;
                if (s === 'ONLINE') return <Badge status="success" text="待命空闲" />;
                return <Badge status="default" text="离线" />;
              },
            },
            {
              title: 'nftables 出站围栏',
              dataIndex: 'fenceStatus',
              width: 170,
              render: (status: string, record: NodeInfo) => (
                <Space>
                  <Tag color={status === 'ACTIVE' ? 'success' : 'default'}>
                    {status === 'ACTIVE' ? '围栏防御生效' : '控制节点免围栏'}
                  </Tag>
                  {record.dropCount > 0 && <Tag color="error">DROP: {record.dropCount}</Tag>}
                </Space>
              ),
            },
            {
              title: '绑定规则库版本',
              dataIndex: 'boundRuleVersion',
              width: 160,
              render: (v: string) => <Tag color="blue">{v}</Tag>,
            },
            {
              title: '凭据与权限隔离',
              render: () => (
                <Tooltip title="Worker 进程运行身份为 uid 10001, 无任何 capabilities, 零数据库凭据">
                  <Tag color="green">无 DB 凭据 · 降权运行</Tag>
                </Tooltip>
              ),
            },
            { title: '最近心跳', dataIndex: 'lastHeartbeat', width: 140 },
          ]}
        />
      </Card>

      {/* 规则包版本与 CURRENT 指针管理 */}
      <Card title="规则库版本管理 (CURRENT 指针与验签审计)" bordered={false}>
        <Table
          dataSource={ruleBundles}
          rowKey="version"
          pagination={false}
          columns={[
            {
              title: '规则包版本',
              dataIndex: 'version',
              width: 180,
              render: (v: string, r: RuleBundle) => (
                <Space>
                  <Text strong>{v}</Text>
                  {r.isCurrent && (
                    <Tag color="success" icon={<CheckCircleOutlined />}>
                      CURRENT 当前生效
                    </Tag>
                  )}
                  {r.isBackup && <Tag color="orange">备用版本</Tag>}
                </Space>
              ),
            },
            {
              title: '发布通道',
              dataIndex: 'channel',
              width: 100,
              render: (c: string) => <Tag>{c.toUpperCase()}</Tag>,
            },
            {
              title: 'Manifest 验签哈希 (SHA256)',
              dataIndex: 'manifestSha256',
              render: (h: string) => <Text code>{h}</Text>,
            },
            {
              title: '任务占用',
              dataIndex: 'inUseByTasks',
              width: 120,
              render: (count: number) =>
                count > 0 ? (
                  <Tag color="processing">{count} 个任务运行中</Tag>
                ) : (
                  <Text type="secondary">无引用 (可回收)</Text>
                ),
            },
            { title: '发布发布时间', dataIndex: 'publishedAt', width: 180 },
            {
              title: '操作',
              width: 120,
              render: (_, record: RuleBundle) =>
                !record.isCurrent ? (
                  <Button
                    type="link"
                    icon={<RollbackOutlined />}
                    danger
                    size="small"
                    onClick={() => handleRollback(record.version)}
                  >
                    回滚至此版本
                  </Button>
                ) : (
                  <Text type="secondary">当前运行中</Text>
                ),
            },
          ]}
        />
      </Card>
    </div>
  );
};
