import React from 'react';
import { Row, Col, Card, Statistic, Progress, Table, Tag, Space, Alert, Typography } from 'antd';
import {
  SafetyOutlined,
  AlertOutlined,
  ClockCircleOutlined,
  DatabaseOutlined,
  CheckCircleOutlined,
  FieldTimeOutlined,
} from '@ant-design/icons';
import { mockAssets, mockFindings, mockTasks, mockRuleBundles } from '../../mock/data';

const { Text } = Typography;

export const DashboardPage: React.FC = () => {
  const currentRule = mockRuleBundles.find((r) => r.isCurrent);
  const criticalCount = mockFindings.filter((f) => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highCount = mockFindings.filter((f) => f.severity === 'HIGH' && f.status === 'OPEN').length;
  const totalFindings = mockFindings.length;

  const topRiskGroups = [
    { key: '1', group: '金融支付核心', riskScore: 92, openVulns: 2, owner: '张三' },
    { key: '2', group: '用户与鉴权中台', riskScore: 68, openVulns: 1, owner: '李四' },
    { key: '3', group: '大数据分析平台', riskScore: 35, openVulns: 0, owner: '赵六' },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* 顶部安全合规与运行提示 */}
      <Alert
        message="默认安全运行模式已激活 (Fail-Closed)"
        description="所有 Worker 均受 Linux nftables 出站网络围栏防护，仅放行经 Server 校验的纯数字 IP:端口白名单。引擎以无能力非 root (uid 10001) 运行。"
        type="info"
        showIcon
        icon={<SafetyOutlined />}
      />

      {/* 关键统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="受控资产总数"
              value={mockAssets.length}
              suffix="个"
              prefix={<DatabaseOutlined style={{ color: '#1677ff' }} />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              主机: {mockAssets.filter((a) => a.kind === 'host').length} | 镜像仓:{' '}
              {mockAssets.filter((a) => a.kind === 'image_repo').length}
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="未收敛严重/高危漏洞"
              value={criticalCount + highCount}
              valueStyle={{ color: '#ff4d4f' }}
              prefix={<AlertOutlined />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              严重 (Critical): {criticalCount} | 高危 (High): {highCount}
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="活跃扫描任务 / 分块"
              value={mockTasks.filter((t) => t.status === 'RUNNING').length}
              suffix={`/ ${mockTasks.length}`}
              prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              遵守夜间扫描时间窗，到点自动暂停
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="规则库版本 (CURRENT)"
              value={currentRule?.version || 'N/A'}
              prefix={<CheckCircleOutlined style={{ color: '#13c2c2' }} />}
              valueStyle={{ fontSize: 18 }}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              Manifest SHA256 签名已通过校验
            </div>
          </Card>
        </Col>
      </Row>

      {/* 风险分布与风险业务组 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card title="TOP 风险业务组排名" bordered={false}>
            <Table
              dataSource={topRiskGroups}
              pagination={false}
              size="middle"
              columns={[
                { title: '排名', dataIndex: 'key', width: 60 },
                { title: '业务组名称', dataIndex: 'group' },
                {
                  title: '综合风险指数',
                  dataIndex: 'riskScore',
                  render: (score: number) => (
                    <Progress
                      percent={score}
                      size="small"
                      status={score > 80 ? 'exception' : score > 50 ? 'active' : 'normal'}
                      strokeColor={score > 80 ? '#ff4d4f' : score > 50 ? '#fa8c16' : '#13c2c2'}
                    />
                  ),
                },
                {
                  title: '待修复漏洞',
                  dataIndex: 'openVulns',
                  render: (v: number) => (
                    <Tag color={v > 0 ? 'red' : 'green'}>{v} 个未修复</Tag>
                  ),
                },
                { title: '安全负责人', dataIndex: 'owner', width: 120 },
              ]}
            />
          </Card>
        </Col>

        <Col xs={24} lg={10}>
          <Card title="漏洞风险等级构成" bordered={false}>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text type="danger" strong>
                    严重 (Critical)
                  </Text>
                  <span>{mockFindings.filter((f) => f.severity === 'CRITICAL').length} / {totalFindings}</span>
                </div>
                <Progress percent={25} strokeColor="#ff4d4f" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#fa8c16' }} strong>
                    高危 (High)
                  </Text>
                  <span>{mockFindings.filter((f) => f.severity === 'HIGH').length} / {totalFindings}</span>
                </div>
                <Progress percent={25} strokeColor="#fa8c16" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#faad14' }} strong>
                    中危 (Medium)
                  </Text>
                  <span>{mockFindings.filter((f) => f.severity === 'MEDIUM').length} / {totalFindings}</span>
                </div>
                <Progress percent={25} strokeColor="#faad14" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#1677ff' }} strong>
                    低危 (Low)
                  </Text>
                  <span>{mockFindings.filter((f) => f.severity === 'LOW').length} / {totalFindings}</span>
                </div>
                <Progress percent={25} strokeColor="#1677ff" showInfo={false} />
              </div>
            </div>
          </Card>
        </Col>
      </Row>

      {/* 近期扫描任务执行流 */}
      <Card title="正在执行与近期任务" bordered={false}>
        <Table
          dataSource={mockTasks}
          rowKey="id"
          pagination={false}
          size="middle"
          columns={[
            { title: '任务 ID', dataIndex: 'id', width: 110 },
            { title: '目标范围', dataIndex: 'scopeName' },
            {
              title: '扫描引擎',
              dataIndex: 'engines',
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
              title: '分块进度',
              render: (_, record) => (
                <div style={{ width: 140 }}>
                  <Progress
                    percent={Math.round((record.completedChunks / record.totalChunks) * 100)}
                    size="small"
                  />
                  <span style={{ fontSize: 11, color: '#64748b' }}>
                    {record.completedChunks}/{record.totalChunks} 块完成
                  </span>
                </div>
              ),
            },
            {
              title: '当前状态',
              dataIndex: 'status',
              render: (status: string) => {
                const map: Record<string, { color: string; label: string }> = {
                  RUNNING: { color: 'processing', label: '扫描中 (In Progress)' },
                  WAITING_WINDOW: { color: 'warning', label: '等待时间窗 (Waiting Window)' },
                  COMPLETED: { color: 'success', label: '已完成 (Completed)' },
                  PAUSED_WINDOW: { color: 'default', label: '窗口期暂停 (Paused)' },
                };
                return <Tag color={map[status]?.color || 'default'}>{map[status]?.label || status}</Tag>;
              },
            },
            {
              title: '硬截止时间 (本地强制)',
              dataIndex: 'hardDeadline',
              render: (val: string) => (
                <Space size={4}>
                  <FieldTimeOutlined style={{ color: '#fa8c16' }} />
                  <span style={{ fontSize: 12 }}>{val}</span>
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
};
