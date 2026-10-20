import React, { useMemo, useState } from 'react';
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
import { Link } from 'react-router-dom';

import { findingCounts, isVulnerability } from '../Findings/presentation';
import { isActiveVulnerability, riskAssetCount, riskScore, severityDistribution, topRiskAssets, topRiskGroups, vulnerabilityTrend } from './presentation';
const { Text } = Typography;

export const DashboardPage: React.FC = () => {
  const { data: assets, loading: assetsLoading, error: assetsError } = useCollection('assets', mockAssets);
  const { data: findings, loading: findingsLoading, error: findingsError } = useCollection('findings', mockFindings);
  const { data: tasks, loading: tasksLoading, error: tasksError } = useCollection('tasks', mockTasks);
  const { data: ruleBundles, loading: rulesLoading, error: rulesError } = useCollection('rules', mockRuleBundles);
  const currentRule = ruleBundles.find((r) => r.isCurrent);
  const vulnerabilities=findings.filter(isVulnerability);
  const counts=findingCounts(findings);
  const activeVulnerabilities = vulnerabilities.filter(isActiveVulnerability);
  const criticalCount = activeVulnerabilities.filter((f) => f.severity === 'CRITICAL').length;
  const highCount = activeVulnerabilities.filter((f) => f.severity === 'HIGH').length;
  const totalFindings = vulnerabilities.length;
  const [trendDays, setTrendDays] = useState<7 | 30 | 90>(30);
  const currentRiskScore = riskScore(findings);
  const riskyAssets = riskAssetCount(findings);
  const trend = useMemo(() => vulnerabilityTrend(findings, trendDays), [findings, trendDays]);
  const maxTrend = Math.max(1, ...trend.map(point => point.count));
  const distribution = severityDistribution(findings);
  const riskGroups = useMemo(() => topRiskGroups(findings), [findings]);
  const riskAssets = useMemo(() => topRiskAssets(assets, findings), [assets, findings]);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* 顶部安全合规与运行提示 */}
      <CollectionNotice loading={assetsLoading || findingsLoading || tasksLoading || rulesLoading} error={assetsError || findingsError || tasksError || rulesError} />
      <Alert
        message={isDemoMode ? '仅演示：安全规则的设计目标' : '本地业务与扫描任务'}
        description="业务数据来自 SQLite。支持 Nuclei 只读基线、ZAP 被动响应检查和 Trivy 离线输入；模拟记录单独标注，未检出不会自动标记已修复。"
        type="info"
        showIcon
        icon={<SafetyOutlined />}
      />

      <Card title="检测结果口径"><Space wrap>
        <Tag color="red"><Link to="/findings">漏洞总数 {counts.vulnerabilities}</Link></Tag>
        <Tag color="blue"><Link to="/findings?risk=login_entry">登录入口 {counts.loginEntries}</Link></Tag>
        <Tag><Link to="/findings?risk=unknown">历史类型未核实 {counts.unknown}</Link></Tag>
        <Tag color="orange"><Link to="/findings?method=version">版本推断 {counts.version}</Link></Tag>
        <Tag color="green"><Link to="/findings?onlyVerified=true">已验证 {counts.verified}</Link></Tag>
        <Tag>弱口令：本次未启用该检测项</Tag>
      </Space><Typography.Paragraph type="secondary" style={{marginTop:12,marginBottom:0}}>漏洞总数仅含系统漏洞与 Web 漏洞。登录入口单独统计；缺少类型的历史记录不纳入漏洞总数。已验证指原理验证或确定性配置检查。</Typography.Paragraph></Card>
      {/* 关键统计卡片 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="风险评分"
              value={currentRiskScore}
              suffix="/ 100"
              valueStyle={{ color: currentRiskScore >= 70 ? '#ff4d4f' : currentRiskScore >= 40 ? '#fa8c16' : '#13c2c2' }}
              prefix={<SafetyOutlined />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              <Link to="/findings">查看活动漏洞明细</Link>
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="有风险资产数"
              value={riskyAssets}
              suffix="个"
              prefix={<DatabaseOutlined style={{ color: '#1677ff' }} />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              受控资产总数: {assets.length}；<Link to="/assets">查看资产台账</Link>
            </div>
          </Card>
        </Col>

        <Col xs={24} sm={12} lg={6}>
          <Card bordered={false}>
            <Statistic
              title="漏洞总数"
              value={totalFindings}
              valueStyle={{ color: '#ff4d4f' }}
              prefix={<AlertOutlined />}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              <Link to="/findings?severity=CRITICAL">严重 {criticalCount}</Link> · <Link to="/findings?severity=HIGH">高危 {highCount}</Link>
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
              formatter={()=>currentRule?.version || (isDemoMode?'演示暂无':'尚未导入')}
              prefix={<CheckCircleOutlined style={{ color: '#13c2c2' }} />}
              valueStyle={{ fontSize: 18 }}
            />
            <div style={{ marginTop: 8, fontSize: 12, color: '#64748b' }}>
              本地 Updater 上报：{currentRule?.signatureVerified?'签名已验证':'签名未验证'}；{currentRule?.engineValidated?'引擎兼容性已验证':'引擎兼容性未验证'}
            </div>
          </Card>
        </Col>
      </Row>

      <Card title="漏洞趋势" bordered={false} extra={<Space.Compact>
        {[7, 30, 90].map(days => <Tag key={days} color={trendDays === days ? 'blue' : undefined} style={{ cursor: 'pointer' }} onClick={() => setTrendDays(days as 7 | 30 | 90)}>{days} 天</Tag>)}
      </Space.Compact>}>
        <div aria-label={`${trendDays} 天漏洞趋势`} style={{ display: 'flex', alignItems: 'end', gap: 4, minHeight: 150, overflowX: 'auto', padding: '8px 0' }}>
          {trend.map(point => <div key={point.date} title={`${point.date}：${point.count} 个`} style={{ minWidth: trendDays === 90 ? 12 : 24, flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'end', gap: 4 }}>
            <Link to="/findings" aria-label={`${point.date} ${point.count} 个漏洞`} style={{ width: '100%', height: `${Math.max(4, point.count / maxTrend * 112)}px`, background: '#1677ff', borderRadius: '4px 4px 0 0', display: 'block' }} />
            {(trendDays <= 30 || point.date.endsWith('-01') || point.date.endsWith('-15')) && <Text type="secondary" style={{ fontSize: 10, whiteSpace: 'nowrap' }}>{point.label}</Text>}
          </div>)}
        </div>
        <Text type="secondary">趋势按每日结束时仍活动的系统/Web 漏洞数计算，详见风险评分口径。</Text>
      </Card>

      {/* 风险分布与风险业务组 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={14}>
          <Card title="风险最高业务组" bordered={false}>
            <Table
              scroll={{x:600}}
              dataSource={riskGroups}
              pagination={false}
              size="middle"
              columns={[
                { title: '排名', render: (_: unknown, __: unknown, index: number) => index + 1, width: 60 },
                { title: '业务组名称', dataIndex: 'name', render: (name: string) => <Link to={`/findings?businessGroup=${encodeURIComponent(name)}`}>{name}</Link> },
                {
                  title: '综合风险指数',
                  dataIndex: 'score',
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
                  title: '活动漏洞',
                  dataIndex: 'openCount',
                  render: (v: number) => (
                    <Tag color={v > 0 ? 'red' : 'green'}>{v} 个未修复</Tag>
                  ),
                },
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
                    <Link to="/findings?severity=CRITICAL">{distribution.CRITICAL} / {totalFindings}</Link>
                </div>
                <Progress percent={totalFindings ? Math.round(distribution.CRITICAL / totalFindings * 100) : 0} strokeColor="#ff4d4f" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#fa8c16' }} strong>
                    高危 (High)
                  </Text>
                  <Link to="/findings?severity=HIGH">{distribution.HIGH} / {totalFindings}</Link>
                </div>
                <Progress percent={totalFindings ? Math.round(distribution.HIGH / totalFindings * 100) : 0} strokeColor="#fa8c16" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#faad14' }} strong>
                    中危 (Medium)
                  </Text>
                  <Link to="/findings?severity=MEDIUM">{distribution.MEDIUM} / {totalFindings}</Link>
                </div>
                <Progress percent={totalFindings ? Math.round(distribution.MEDIUM / totalFindings * 100) : 0} strokeColor="#faad14" showInfo={false} />
              </div>

              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                  <Text style={{ color: '#1677ff' }} strong>
                    低危 (Low)
                  </Text>
                  <Link to="/findings?severity=LOW">{distribution.LOW} / {totalFindings}</Link>
                </div>
                <Progress percent={totalFindings ? Math.round(distribution.LOW / totalFindings * 100) : 0} strokeColor="#1677ff" showInfo={false} />
              </div>
              <div><Text>信息 (Info)：<Link to="/findings?severity=INFO">{distribution.INFO} / {totalFindings}</Link></Text><Progress percent={totalFindings?Math.round(distribution.INFO/totalFindings*100):0} showInfo={false}/></div>
            </div>
          </Card>
        </Col>
      </Row>

      <Card title="风险最高资产" bordered={false}>
        <Table dataSource={riskAssets} rowKey="id" pagination={false} size="small" columns={[
          { title: '资产', render: (_: unknown, item: { id: string; name: string; address: string }) => <Link to={`/findings?assetId=${encodeURIComponent(item.id)}`}>{item.name}</Link> },
          { title: '地址', dataIndex: 'address' },
          { title: '风险指数', dataIndex: 'score', render: (score: number) => <Progress percent={score} size="small" /> },
          { title: '活动漏洞', dataIndex: 'openCount' },
        ]} locale={{ emptyText: '暂无活动漏洞资产' }} />
      </Card>

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
