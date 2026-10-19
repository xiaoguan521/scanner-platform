import React, { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Select,
  Input,
  Typography,
  Alert,
  Tooltip,
  Checkbox,
  message,
} from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';
import { mockFindings } from '../../mock/data';
import { Finding, FindingSeverity, FindingStatus } from '../../types';
import { isDemoMode } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import { updateFinding } from '../../api/runtime';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

import { riskLabels, methodLabels, confidenceLabels, isVerifiedFinding, findingCounts } from './presentation';
const { Text } = Typography;

export const FindingsPage: React.FC = () => {
  const {user}=useAuth();
  const canWrite=!isDemoMode&&(user?.role==='admin'||user?.role==='security_engineer');
  const { data: findings, setData: setFindings, loading, error } = useCollection('findings', mockFindings);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');
  const [methodFilter,setMethodFilter]=useState('ALL');
  const [confidenceFilter,setConfidenceFilter]=useState('ALL');
  const [riskFilter,setRiskFilter]=useState('ALL');
  const [onlyVerified,setOnlyVerified]=useState(false);
  const counts=findingCounts(findings);
  const [query, setQuery] = useState('');
  const normalizedQuery = query.trim().toLowerCase();

  const filteredFindings = findings.filter((f) => {
    if(methodFilter!=='ALL'&&(f.detectMethod??'unknown')!==methodFilter)return false;
    if(confidenceFilter!=='ALL'&&(f.confidence??'unknown')!==confidenceFilter)return false;
    if(riskFilter!=='ALL'&&(f.riskType??'unknown')!==riskFilter)return false;
    if(onlyVerified&&!isVerifiedFinding(f))return false;
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
    if (normalizedQuery && ![f.target, f.package ?? '', f.templateOrCve, f.title].some(value => value.toLowerCase().includes(normalizedQuery))) return false;
    return true;
  });

  const handleUpdateStatus = async (id: string, newStatus: FindingStatus) => {
    // FIXED is a Server-only decision based on a complete verified scan.
    if (newStatus === 'FIXED') {
      message.warning('FIXED 必须经 Server 确认完整扫描、规则执行和未检出阈值，目前不可操作');
      return;
    }
    if (!isDemoMode) {
      try{const item=await updateFinding(id,newStatus);setFindings(prev=>prev.map(f=>f.id===id?item:f));message.success('状态已保存并记录审计');}catch(e){message.error(String(e));}
      return;
    }
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status: newStatus } : f));
    message.info('仅演示：本地漏洞状态已更新，Server 数据和审计日志没有变化');
  };

  const getSeverityTag = (sev: FindingSeverity) => {
    const map: Record<FindingSeverity, { color: string; label: string }> = {
      CRITICAL: { color: 'magenta', label: '严重 (Critical)' },
      HIGH: { color: 'red', label: '高危 (High)' },
      MEDIUM: { color: 'orange', label: '中危 (Medium)' },
      LOW: { color: 'blue', label: '低危 (Low)' },
      INFO: { color: 'default', label: '信息 (Info)' },
    };
    return <Tag color={map[sev].color}>{map[sev].label}</Tag>;
  };

  const getStatusTag = (status: FindingStatus) => {
    const map: Record<FindingStatus, { color: string; label: string }> = {
      OPEN: { color: 'error', label: '待修复 (OPEN)' },
      REOPENED: { color: 'error', label: '重新出现 (REOPENED)' },
      IN_PROGRESS: { color: 'processing', label: '修复中 (IN_PROGRESS)' },
      FIXED: { color: 'success', label: '已修复 (FIXED)' },
      FALSE_POSITIVE: { color: 'default', label: '误报静默 (FALSE_POSITIVE)' },
      ACCEPTED_RISK: { color: 'warning', label: '接受风险 (ACCEPTED_RISK)' },
    };
    return <Tag color={map[status].color}>{map[status].label}</Tag>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <CollectionNotice loading={loading} error={error} />
      <Alert
        message={isDemoMode ? '演示发现项' : '扫描引擎与模拟任务的发现项'}
        description={isDemoMode ? '本页为演示数据。' : '模拟记录会单独标记。Nuclei 基线和 ZAP 被动发现需结合服务用途判断；Trivy 展示漏洞编号、受影响组件和修复版本。未检出不自动标记已修复。'}
        type="warning"
        showIcon
        icon={<SafetyCertificateOutlined />}
      />

      <Card><Space wrap><Tag color="red">漏洞总数 {counts.vulnerabilities}</Tag><Tag color="blue">登录入口 {counts.loginEntries}</Tag><Tag>未核实类型 {counts.unknown}</Tag><Tag color="orange">版本推断 {counts.version}</Tag><Tag color="green">已验证 {counts.verified}</Tag><Tag>弱口令：本次未启用该检测项</Tag></Space></Card>
      <Space wrap>
        <Select aria-label="检测方式筛选" value={methodFilter} onChange={setMethodFilter} style={{width:210}} options={[{value:'ALL',label:'全部检测方式'},...Object.entries(methodLabels).map(([value,label])=>({value,label}))]}/>
        <Select aria-label="置信度筛选" value={confidenceFilter} onChange={setConfidenceFilter} style={{width:180}} options={[{value:'ALL',label:'全部置信度'},...Object.entries(confidenceLabels).map(([value,label])=>({value,label}))]}/>
        <Select aria-label="风险类型筛选" value={riskFilter} onChange={setRiskFilter} style={{width:190}} options={[{value:'ALL',label:'全部类型'},...Object.entries(riskLabels).map(([value,label])=>({value,label}))]}/>
        <Checkbox checked={onlyVerified} onChange={e=>setOnlyVerified(e.target.checked)}>仅已验证（原理验证 / 配置检查）</Checkbox>
      </Space>
      <Alert showIcon type="info" message="版本推断没有实际验证漏洞。未标注检测方式的历史结果显示为未核实；扫描完整性不等同于原理验证。"/>
      <Input aria-label="按目标、组件或 CVE 筛选" placeholder="按目标、服务器别名、组件或 CVE 筛选" allowClear value={query} onChange={event => setQuery(event.target.value)} style={{maxWidth:480}} />

      <Card
        title="漏洞发现与生命周期闭环看板"
        bordered={false}
        extra={
          <Space>
            <Select
              value={severityFilter}
              onChange={setSeverityFilter}
              style={{ width: 140 }}
              options={[
                { value: 'ALL', label: '全部等级' },
                { value: 'CRITICAL', label: '严重 (Critical)' },
                { value: 'HIGH', label: '高危 (High)' },
                { value: 'MEDIUM', label: '中危 (Medium)' },
                { value: 'LOW', label: '低危 (Low)' },
                { value: 'INFO', label: '信息 (Info)' },
              ]}
            />
            <Select
              value={statusFilter}
              onChange={setStatusFilter}
              style={{ width: 140 }}
              options={[
                { value: 'ALL', label: '全部状态' },
                { value: 'OPEN', label: '待修复 (OPEN)' },
                { value: 'REOPENED', label: '重新出现 (REOPENED)' },
                { value: 'IN_PROGRESS', label: '修复中' },
                { value: 'FIXED', label: '已修复 (FIXED)' },
                { value: 'FALSE_POSITIVE', label: '误报' },
                { value: 'ACCEPTED_RISK', label: '接受风险' },
              ]}
            />
          </Space>
        }
      >
        <Table
          dataSource={filteredFindings}
          rowKey="id"
          pagination={{showTotal:total=>`共 ${total} 项`}}
          scroll={{x:1500}}
          expandable={{expandedRowRender:r=><Space direction="vertical"><Text>{r.description||'暂无补充描述'}</Text><Text>检测方式：{methodLabels[r.detectMethod??'unknown']} · {confidenceLabels[r.confidence??'unknown']}</Text><Text>风险类型：{riskLabels[r.riskType??'unknown']} · 分类：{r.vulnCategory||'未分类'} · CVSS：{r.cvssScore??'未提供'}</Text><Text>影响：{r.impact||'待补充'}</Text><Text style={{whiteSpace:'pre-wrap'}}>修复建议：{r.solution||'待补充'}</Text><Text style={{whiteSpace:'pre-wrap'}}>举证：{r.evidence||'待补充'}</Text>{r.detectMethod==='version'&&<Alert type="warning" showIcon message="该结果基于组件版本推断，建议登录主机核查补丁或使用主机本地扫描。"/>}<Text>外部编号：{Object.entries(r.identifiers??{}).map(([key,values])=>`${key}: ${values.join(', ')}`).join('；')||'未提供'}</Text><Text>参考资料：{r.references?.join('；')||'未提供'}</Text>{r.contentLanguage&&r.contentLanguage!=='zh-CN'&&r.contentLanguage!=='zh'&&<Tag color="orange">内容为原文，待中文化</Tag>}<Text>匹配路径：{r.matchedPath||'—'}</Text>{r.package&&<Text>组件：{r.package}；安装版本：{r.installedVersion||'—'}；修复版本：{r.fixedVersion||'暂无'}</Text>}</Space>}}
          columns={[
            {title:'类型 / 检测依据',width:200,render:(_,r)=><Space direction="vertical" size={3}><Tag>{riskLabels[r.riskType??'unknown']}</Tag><Tag color={isVerifiedFinding(r)?'green':r.detectMethod==='version'?'orange':'default'}>{methodLabels[r.detectMethod??'unknown']}</Tag><Tag>{confidenceLabels[r.confidence??'unknown']}</Tag></Space>},
            {
              title: '等级',
              dataIndex: 'severity',
              width: 130,
              render: (s: FindingSeverity) => getSeverityTag(s),
            },
            {
              title: '漏洞详情与稳定指纹',
              width: 420,
              render: (_, record) => (
                <Space direction="vertical" size={2} style={{width:'100%'}}>
                  <Text strong style={{whiteSpace:'normal',wordBreak:'break-word'}}>{record.title}</Text>
                  {record.synthetic && <Tag color="blue">模拟结果</Tag>}
                  <Space size={8} wrap>
                    <Tag color={record.engine === 'nuclei' ? 'purple' : 'cyan'}>
                      {record.engine.toUpperCase()}
                    </Tag>
                    <Text code style={{whiteSpace:'nowrap'}}>{record.templateOrCve}</Text>
                  </Space>
                  <Tooltip title={`稳定指纹：${record.fingerprint}`}><Text type="secondary" ellipsis style={{maxWidth:330,fontSize:11}}>{record.fingerprint}</Text></Tooltip>
                </Space>
              ),
            },
            {
              title: '目标地址',
              dataIndex: 'target',
              width: 220,
              render: (t: string) => <Text code>{t}</Text>,
            },
            {
              title: '业务归属',
              width: 160,
              render: (_, r) => (
                <Space direction="vertical" size={2}>
                  <Text>{r.businessGroup}</Text>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    负责人: {r.owner}
                  </Text>
                </Space>
              ),
            },
            {
              title: '生命周期状态',
              dataIndex: 'status',
              width: 140,
              render: (s: FindingStatus) => getStatusTag(s),
            },
            {
              title: '最近检出 / 未检出计数',
              width: 230,
              render: (_, r) => (
                <Space direction="vertical" size={1} style={{ fontSize: 12 }}>
                  <span>最近: {r.lastSeen}</span>
                  {r.status === 'FIXED' ? (
                    <Text type="success">连续未检出: {r.consecutiveMisses} 次</Text>
                  ) : (
                    <Text type="secondary">初见: {r.firstSeen}</Text>
                  )}
                </Space>
              ),
            },
            {
              title: '状态流转',
              width: 150,
              render: (_, r) => (
                <Space size={4} wrap>
                  {r.status!=='OPEN'&&r.status!=='FIXED'&&<Button type="link" size="small" disabled={!isDemoMode&&!canWrite} onClick={()=>void handleUpdateStatus(r.id,'OPEN')}>恢复待处理</Button>}
                  {r.status === 'OPEN' && (
                    <Button
                      type="link"
                      size="small"
                      disabled={!isDemoMode&&!canWrite}
                      onClick={() => handleUpdateStatus(r.id, 'IN_PROGRESS')}
                    >
                      标记处理中
                    </Button>
                  )}
                  {r.status === 'IN_PROGRESS' && (
                    <Button
                      type="link"
                      size="small"
                      style={{ color: '#13c2c2' }}
                      disabled
                      onClick={() => handleUpdateStatus(r.id, 'FIXED')}
                    >
                      标记修复
                    </Button>
                  )}
                  {r.status !== 'FALSE_POSITIVE' && r.status !== 'FIXED' && (
                    <Button
                      type="link"
                      size="small"
                      danger
                      disabled={!isDemoMode&&!canWrite}
                      onClick={() => handleUpdateStatus(r.id, 'FALSE_POSITIVE')}
                    >
                      误报
                    </Button>
                  )}
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
};
