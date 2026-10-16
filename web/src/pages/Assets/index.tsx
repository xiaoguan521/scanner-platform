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
  Select,
  Alert,
  message,
  Typography,
  Badge,
  Tooltip,
} from 'antd';
import {
  PlusOutlined,
  ExclamationCircleOutlined,
  SafetyCertificateOutlined,
  StopOutlined,
  CheckCircleOutlined,
} from '@ant-design/icons';
import { mockAssets, mockPortQuarantines } from '../../mock/data';
import { Asset, AssetPort } from '../../types';
import { isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

const { Text } = Typography;

export const AssetsPage: React.FC = () => {
  const { data: assets, setData: setAssets, loading: assetsLoading, error: assetsError } = useCollection('assets', mockAssets);
  const { data: quarantines, setData: setQuarantines, loading: quarantinesLoading, error: quarantinesError } = useCollection('port-quarantines', mockPortQuarantines);
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [form] = Form.useForm();

  const handleAddAsset = (values: any) => {
    if (!isDemoMode) return message.warning('Server 尚未开放资产登记 API');
    const newAsset: Asset = {
      id: `asset-${Date.now().toString().slice(-4)}`,
      kind: values.kind,
      address: values.address,
      resolvedIp: values.kind === 'host' ? values.address : undefined,
      businessGroup: values.businessGroup,
      owner: values.owner,
      createdAt: new Date().toISOString(),
      // A typed-in port is never an authorized port grant.
      ports: [],
      quarantinedPorts: [],
    };
    setAssets((prev) => [newAsset, ...prev]);
    message.info('仅演示：新增资产草稿；端口未获授权，Server 未发生变更');
    setIsModalOpen(false);
    form.resetFields();
  };

  const handleReleaseQuarantine = (assetId: string, port: number) => {
    if (!isDemoMode) return message.warning('实际解除隔离必须由 Server 审批');
    Modal.confirm({
      title: `确认解除端口隔离 [${port}]？`,
      content: '仅更改演示页面，不解除 Server 隔离、不恢复扫描。',
      okText: '确认解除',
      okType: 'danger',
      cancelText: '取消',
      onOk: () => {
        setQuarantines(quarantines.filter((q) => !(q.assetId === assetId && q.port === port)));
        setAssets((prev) =>
          prev.map((a) =>
            a.id === assetId
              ? { ...a, quarantinedPorts: a.quarantinedPorts?.filter((p) => p !== port) }
              : a
          )
        );
        message.info(`仅演示：端口 ${port} 本地状态已改变，Server 未发生变更`);
      },
    });
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <CollectionNotice loading={assetsLoading || quarantinesLoading} error={assetsError || quarantinesError} />
      {/* 运维硬性规范提示 */}
      <Alert
        message="端口授权硬规则：未登记端口一律不扫"
        description="所有扫描目标与端口必须显式核准。被判定为四层代理（EXCLUDED_PROXY）或时延突变隔离（Quarantine）的端口将强制跳过，防止经由代理穿透至外部系统。"
        type="warning"
        showIcon
        icon={<ExclamationCircleOutlined />}
      />

      {/* 四层代理与时延隔离警示条 */}
      {quarantines.length > 0 && (
        <Card
          title={
            <Space>
              <StopOutlined style={{ color: '#ff4d4f' }} />
              <span style={{ color: '#ff4d4f' }}>
                疑似四层转发隔离区 (Port Quarantine) · 待人工复核
              </span>
            </Space>
          }
          bordered={false}
          style={{ borderColor: '#ff4d4f' }}
        >
          <Table
            dataSource={quarantines}
            rowKey={(r) => `${r.assetId}-${r.port}`}
            pagination={false}
            size="small"
            columns={[
              { title: '资产地址', dataIndex: 'address', width: 180 },
              {
                title: '受控隔离端口',
                dataIndex: 'port',
                width: 120,
                render: (p: number) => <Tag color="error">:{p} (Quarantined)</Tag>,
              },
              { title: '触发原因 / 探针判定', dataIndex: 'reason' },
              { title: '拦截时间', dataIndex: 'detectedAt', width: 180 },
              {
                title: '操作',
                width: 130,
                render: (_, r) => (
                  <Button
                    type="link"
                    size="small"
                    disabled={!isDemoMode}
                    onClick={() => handleReleaseQuarantine(r.assetId, r.port)}
                  >
                    复核并解除
                  </Button>
                ),
              },
            ]}
          />
        </Card>
      )}

      {/* 资产列表主表 */}
      <Card
        title="资产与端口授权台账"
        bordered={false}
        extra={
          <Button type="primary" icon={<PlusOutlined />} disabled={!isDemoMode}
          onClick={() => setIsModalOpen(true)}>
            登记新资产
          </Button>
        }
      >
        <Table
          dataSource={assets}
          rowKey="id"
          columns={[
            { title: '资产 ID', dataIndex: 'id', width: 120 },
            {
              title: '目标地址',
              dataIndex: 'address',
              render: (addr: string, record: Asset) => (
                <Space direction="vertical" size={2}>
                  <Text strong>{addr}</Text>
                  {record.resolvedIp && record.resolvedIp !== addr && (
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      已固定 IP: {record.resolvedIp}
                    </Text>
                  )}
                </Space>
              ),
            },
            {
              title: '资产类型',
              dataIndex: 'kind',
              width: 120,
              render: (k: string) => (
                <Tag color={k === 'host' ? 'blue' : 'purple'}>
                  {k === 'host' ? '主机资产' : 'Harbor 镜像'}
                </Tag>
              ),
            },
            { title: '所属业务组', dataIndex: 'businessGroup', width: 150 },
            { title: '责任人', dataIndex: 'owner', width: 140 },
            {
              title: '已授权端口 (Port Grants)',
              dataIndex: 'ports',
              render: (ports: AssetPort[], record: Asset) => {
                if (!ports || ports.length === 0) {
                  return <Text type="secondary">无已核准端口 (不可扫)</Text>;
                }
                return (
                  <Space wrap size={[6, 6]}>
                    {ports.map((p) => {
                      const isQuarantined = record.quarantinedPorts?.includes(p.port);
                      if (isQuarantined) {
                        return (
                          <Tooltip key={p.port} title="已被时延探针自动隔离跳过">
                            <Tag color="error">:{p.port} 隔离</Tag>
                          </Tooltip>
                        );
                      }
                      if (p.kind === 'EXCLUDED_PROXY') {
                        return (
                          <Tooltip key={p.port} title="已知 Nginx 四层代理，永久跳过">
                            <Tag color="default">:{p.port} (四层代理)</Tag>
                          </Tooltip>
                        );
                      }
                      if (p.kind === 'WEB') {
                        return (
                          <Tooltip key={p.port} title="WEB 端口 (运行 Web 漏洞 POC)">
                            <Tag color="cyan">:{p.port} WEB</Tag>
                          </Tooltip>
                        );
                      }
                      return (
                        <Tooltip key={p.port} title="NON_WEB 端口 (仅协议指纹扫描)">
                          <Tag color="blue">:{p.port} 协议</Tag>
                        </Tooltip>
                      );
                    })}
                  </Space>
                );
              },
            },
            { title: '登记时间', dataIndex: 'createdAt', width: 170 },
          ]}
        />
      </Card>

      {/* 登记资产对话框 */}
      <Modal
        title="登记新目标资产"
        open={isModalOpen}
        onCancel={() => setIsModalOpen(false)}
        onOk={() => form.submit()}
        okButtonProps={{ disabled: !isDemoMode }}
      >
        <Form form={form} layout="vertical" onFinish={handleAddAsset}>
          <Form.Item name="kind" label="资产形态" initialValue="host" rules={[{ required: true }]}>
            <Select>
              <Select.Option value="host">主机 IP / 独立主机</Select.Option>
              <Select.Option value="image_repo">Harbor 镜像仓库</Select.Option>
            </Select>
          </Form.Item>
          <Form.Item
            name="address"
            label="目标地址 (纯数字 IP 或 镜像仓库名)"
            rules={[{ required: true, message: '请输入目标地址' }]}
            extra="Worker 绝不解析域名或自行展开 CIDR，主机请直接输入纯数字 IPv4/IPv6"
          >
            <Input placeholder="例如: 192.0.2.18" />
          </Form.Item>
          <Form.Item name="businessGroup" label="所属业务组" rules={[{ required: true }]}>
            <Input placeholder="例如: 核心网关组" />
          </Form.Item>
          <Form.Item name="owner" label="安全责任人" rules={[{ required: true }]}>
            <Input placeholder="例如: 张工" />
          </Form.Item>
          <Form.Item
            name="ports"
            label="拟申请端口 (不会自动授权)"
            extra="未填写的端口将被扫描器默认关闭拒绝"
          >
            <Input placeholder="例如: 80, 443, 8080" />
          </Form.Item>
        </Form>
      </Modal>
    </div>
  );
};
