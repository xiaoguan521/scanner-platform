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
import { isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

const { Text } = Typography;

export const DashboardPage: React.FC = () => {
  const { data: assets, loading: assetsLoading, error: assetsError } = useCollection('assets', mockAssets);
  const { data: findings, loading: findingsLoading, error: findingsError } = useCollection('findings', mockFindings);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useCollection('tasks', mockTasks);
  const { data: ruleBundles, loading: rulesLoading, error: rulesError } = useCollection('rules', mockRuleBundles);
  const currentRule = ruleBundles.find((r) => r.isCurrent);
  const criticalCount = findings.filter((f) => f.severity === 'CRITICAL' && f.status === 'OPEN').length;
  const highCount = findings.filter((f) => f.severity === 'HIGH' && f.status === 'OPEN').length;
  const totalFindings = findings.length;

  const topRiskGroups = isDemoMode ? [
    { key: '1', group: '金融支付核心', riskScore: 92, openVulns: 2, owner: '张三' },
    { key: '2', group: '用户与鉴权中台', riskScore: 68, openVulns: 1, owner: '李四' },
    { key: '3', group: '大数据分析平台', riskScore: 35, openVulns: 0, owner: '赵六' },
  ] : Array.from(new Set(findings.map(f=>f.businessGroup).filter(Boolean))).map((group,index)=>{
    const items=findings.filter(f=>f.businessGroup===group&&!['FALSE_POSITIVE','FIXED'].includes(f.status));
    return {key:String(index+1),group,riskScore:Math.min(100,items.reduce((sum,f)=>sum+({CRITICAL:30,HIGH:20,MEDIUM:10,LOW:3,INFO:1}[f.severity]),0)),openVulns:items.length,owner:items[0]?.owner||'—'};
  }).sort((a,b)=>b.riskScore-a.riskScore).slice(0,5);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* 顶部安全合规与运行提示 */}
      <CollectionNotice loading={assetsLoading || findingsLoading || tasksLoading || rulesLoading} error={assetsError || findingsError || tasksError || rulesError} />
      <Alert
        message={isDemoMode ? '仅演示：安全规则的设计目标' : '本地业务运行中 · 真实扫描留待验证'}
        description="本地业务数据来自 SQLite。当前任务为模拟执行，不会连接目标；真实扫描结果与修复验证另行接入。"
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
              value={assets.length}
              suffix="个"
              prefix={<DatabaseOutlined style={{ color: '#1677ff' }} />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              主机: {assets.filter((a) => a.kind === 'host').length} | 镜像仓:{' '}
              {assets.filter((a) => a.kind === 'image_repo').length}
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
              value={tasks.filter((t) => t.status === 'RUNNING').length}
              suffix={`/ ${tasks.length}`}
              prefix={<ClockCircleOutlined style={{ color: '#fa8c16' }} />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              任务按指定时间窗等待、执行和恢复
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="规则库版本 (CURRENT)"
              value={currentRule?.version || (isDemoMode?'演示暂无':'尚未导入')}
              prefix={<CheckCircleOutlined style={{ color: '#13c2c2' }} />}
              valueStyle={{ fontSize: 18 }}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              本地 Updater 上报的当前版本；未验签、未验证引擎兼容性
            </div>
          </Card>
        </Col>
      </Row>

      {/* 风险分布与风险业务组 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card title="业务组发现项统计（含明确标注的模拟结果）" bordered={false}>
            <Table
              scroll={{x:600}}
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
                  <span>{findings.filter((f) => f.severity === 'CRITICAL').length} / {totalFindings}</span>
                </div>
                <Progress percent={totalFindings ? Math.round(findings.filter((f) => f.severity === 'CRITICAL').length / totalFindings * 100) : 0} strokeColor="#ff4d4f" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#fa8c16' }} strong>
                    高危 (High)
                  </Text>
                  <span>{findings.filter((f) => f.severity === 'HIGH').length} / {totalFindings}</span>
                </div>
                <Progress percent={totalFindings ? Math.round(findings.filter((f) => f.severity === 'HIGH').length / totalFindings * 100) : 0} strokeColor="#fa8c16" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#faad14' }} strong>
                    中危 (Medium)
                  </Text>
                  <span>{findings.filter((f) => f.severity === 'MEDIUM').length} / {totalFindings}</span>
                </div>
                <Progress percent={totalFindings ? Math.round(findings.filter((f) => f.severity === 'MEDIUM').length / totalFindings * 100) : 0} strokeColor="#faad14" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#1677ff' }} strong>
                    低危 (Low)
                  </Text>
                  <span>{findings.filter((f) => f.severity === 'LOW').length} / {totalFindings}</span>
                </div>
                <Progress percent={totalFindings ? Math.round(findings.filter((f) => f.severity === 'LOW').length / totalFindings * 100) : 0} strokeColor="#1677ff" showInfo={false} />
              </div>
              <div><Text>信息 (Info)：{findings.filter(f=>f.severity==='INFO').length} / {totalFindings}</Text><Progress percent={totalFindings?Math.round(findings.filter(f=>f.severity==='INFO').length/totalFindings*100):0} showInfo={false}/></div>
            </div>
          </Card>
        </Col>
      </Row>

      {/* 近期扫描任务执行流 */}
      <Card title="正在执行与近期任务" bordered={false}>
        <Table
          scroll={{x:1000}}
          dataSource={tasks}
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
                    percent={record.totalChunks ? Math.round((record.completedChunks / record.totalChunks) * 100) : 0}
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
