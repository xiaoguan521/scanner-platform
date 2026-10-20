import React, { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
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
  Descriptions,
  Drawer,
  Timeline,
  message,
} from 'antd';
import { SafetyCertificateOutlined } from '@ant-design/icons';
import { mockFindings } from '../../mock/data';
import { Finding, FindingEvent, FindingSeverity, FindingStatus } from '../../types';
import { isDemoMode } from '../../api/client';
import { useAuth } from '../../auth/AuthProvider';
import { updateFinding, fetchFindingEvents } from '../../api/runtime';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

import { riskLabels, methodLabels, confidenceLabels, isVerifiedFinding, findingCounts } from './presentation';
import { FindingFilters, readFindingFilters, writeFindingFilters } from './filters';
import { detailText, detailList, detailIdentifiers, selectedFindingForDrawer } from './drawer';
import { canAcceptRisk, acceptanceInput } from './disposition';
const { Text } = Typography;

export const FindingsPage: React.FC = () => {
  const {user}=useAuth();
  const canWrite=!isDemoMode&&(user?.role==='admin'||user?.role==='security_engineer');
  const { data: findings, setData: setFindings, loading, error } = useCollection('findings', mockFindings);
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = readFindingFilters(searchParams);
  const { severity: severityFilter, status: statusFilter, method: methodFilter,
    confidence: confidenceFilter, risk: riskFilter, onlyVerified } = filters;
  const search = searchParams.toString();
  useEffect(() => {
    const canonical = writeFindingFilters(searchParams, readFindingFilters(searchParams));
    if (canonical.toString() !== search) {
      setSearchParams(current => writeFindingFilters(current, readFindingFilters(current)), { replace: true });
    }
  }, [search, searchParams, setSearchParams]);
  const updateFilters = (patch: Partial<FindingFilters>) => {
    setSearchParams(current => writeFindingFilters(current, { ...readFindingFilters(current), ...patch }), { replace: true });
  };
  const counts=findingCounts(findings);
  const [query, setQuery] = useState('');
  const normalizedQuery = query.trim().toLowerCase();
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const detailTrigger = useRef<HTMLElement | null>(null);
  const [acceptReason,setAcceptReason]=useState('');
  const [acceptUntil,setAcceptUntil]=useState('');
  const [saving,setSaving]=useState(false);
  const [events,setEvents]=useState<FindingEvent[]>([]);
  const [eventsError,setEventsError]=useState('');
  const [eventRevision,setEventRevision]=useState(0);
  useEffect(()=>{
    setAcceptReason('');setAcceptUntil('');setEvents([]);setEventsError('');
    if(!selectedFindingId || isDemoMode)return;
    const controller=new AbortController();
    const load=()=>fetchFindingEvents(selectedFindingId,controller.signal).then(result=>{if(!controller.signal.aborted){setEvents(result.items);setEventsError('')}}).catch(()=>{if(!controller.signal.aborted)setEventsError('状态记录加载失败，请稍后重试')});
    void load();const timer=window.setInterval(()=>void load(),10000);
    return ()=>{controller.abort();window.clearInterval(timer)};
  },[selectedFindingId,eventRevision]);

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
  const selectedFinding = selectedFindingForDrawer(findings, filteredFindings, selectedFindingId);
  useEffect(() => {
    if (selectedFindingId && !selectedFinding) setSelectedFindingId(null);
  }, [selectedFindingId, selectedFinding]);
  const openFindingDetails = (finding: Finding, trigger: HTMLElement) => {
    detailTrigger.current = trigger;
    setSelectedFindingId(finding.id);
  };
  const closeFindingDetails = () => setSelectedFindingId(null);
  const restoreDetailFocus = (open: boolean) => {
    if (!open) {
      if (detailTrigger.current?.isConnected) detailTrigger.current.focus();
      detailTrigger.current = null;
    }
  };

  const handleUpdateStatus = async (id: string, newStatus: FindingStatus, acceptance?:{reason:string;acceptedUntil:string}) => {
    // FIXED is a Server-only decision based on a complete verified scan.
    if (newStatus === 'FIXED') {
      message.warning('FIXED 必须经 Server 确认完整扫描、规则执行和未检出阈值，目前不可操作');
      return;
    }
    if (!isDemoMode) {
      setSaving(true);try{const item=await updateFinding(id,newStatus,acceptance);setFindings(prev=>prev.map(f=>f.id===id?item:f));setEventRevision(n=>n+1);message.success('状态已保存并记录审计');}catch(e){message.error(String(e));}finally{setSaving(false)}
      return;
    }
    message.info('仅演示：该操作不会保存，Server 数据和审计日志没有变化');
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
        <Select aria-label="检测方式筛选" value={methodFilter} onChange={method => updateFilters({ method })} style={{width:210}} options={[{value:'ALL',label:'全部检测方式'},...Object.entries(methodLabels).map(([value,label])=>({value,label}))]}/>
        <Select aria-label="置信度筛选" value={confidenceFilter} onChange={confidence => updateFilters({ confidence })} style={{width:180}} options={[{value:'ALL',label:'全部置信度'},...Object.entries(confidenceLabels).map(([value,label])=>({value,label}))]}/>
        <Select aria-label="风险类型筛选" value={riskFilter} onChange={risk => updateFilters({ risk })} style={{width:190}} options={[{value:'ALL',label:'全部类型'},...Object.entries(riskLabels).map(([value,label])=>({value,label}))]}/>
        <Checkbox checked={onlyVerified} onChange={e=>updateFilters({ onlyVerified: e.target.checked })}>仅已验证（原理验证 / 配置检查）</Checkbox>
      </Space>
      <Alert showIcon type="info" message="版本推断没有实际验证漏洞。未标注检测方式的历史结果显示为未核实；扫描完整性不等同于原理验证。"/>
      <Input aria-label="按目标、组件或 CVE 筛选" placeholder="按目标、服务器别名、组件或 CVE 筛选" allowClear value={query} onChange={event => setQuery(event.target.value)} style={{maxWidth:480}} />

      <Card
        title="漏洞发现与生命周期闭环看板"
        bordered={false}
        extra={
          <Space>
            <Select
              aria-label="严重度筛选"
              value={severityFilter}
              onChange={severity => updateFilters({ severity })}
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
              aria-label="状态筛选"
              value={statusFilter}
              onChange={status => updateFilters({ status })}
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
          scroll={{x:1600}}
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
              title: '详情 / 状态流转',
              width: 180,
              render: (_, r) => (
                <Space size={4} wrap>
                  <Button
                    size="small"
                    aria-label={`查看详情：${r.title}`}
                    onClick={event => {
                      event.stopPropagation();
                      openFindingDetails(r, event.currentTarget);
                    }}
                  >查看详情</Button>
                  {r.status!=='OPEN'&&r.status!=='FIXED'&&<Button type="link" size="small" disabled={!isDemoMode&&!canWrite} onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'OPEN'); }}>恢复待处理</Button>}
                  {r.status === 'OPEN' && (
                    <Button
                      type="link"
                      size="small"
                      disabled={!isDemoMode&&!canWrite}
                      onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'IN_PROGRESS'); }}
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
                      onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'FIXED'); }}
                    >
                      标记修复
                    </Button>
                  )}
                  {r.status !== 'FALSE_POSITIVE' && r.status !== 'FIXED' && r.status !== 'ACCEPTED_RISK' && (
                    <Button
                      type="link"
                      size="small"
                      danger
                      disabled={!isDemoMode&&!canWrite}
                      onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'FALSE_POSITIVE'); }}
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
      <Drawer
        title="发现项详情"
        open={Boolean(selectedFinding)}
        onClose={closeFindingDetails}
        afterOpenChange={restoreDetailFocus}
        width="min(760px, 100vw)"
        keyboard
        maskClosable
        styles={{ body: { overflowX: 'hidden' } }}
      >
        {selectedFinding && (
          <Space direction="vertical" size={20} style={{ width: '100%', minWidth: 0 }}>
            <Typography.Title level={4} style={{ margin: 0, overflowWrap: 'anywhere' }}>
              {detailText(selectedFinding.title)}
            </Typography.Title>
            <Space wrap>
              {getSeverityTag(selectedFinding.severity)}
              {getStatusTag(selectedFinding.status)}
              <Tag color={selectedFinding.synthetic ? 'blue' : 'default'}>
                {selectedFinding.synthetic == null ? '模拟标记：未提供' : selectedFinding.synthetic ? '模拟结果' : '非模拟结果'}
              </Tag>
            </Space>
            {selectedFinding.detectMethod === 'version' && <Alert type="warning" showIcon message="该结果基于组件版本推断，建议登录主机核查补丁或使用主机本地扫描。" />}
            {selectedFinding.contentLanguage && !['zh-CN', 'zh'].includes(selectedFinding.contentLanguage) && <Tag color="orange">内容为原文，待中文化</Tag>}
            <Descriptions title="目标与检测依据" column={1} size="small" bordered
              styles={{ content: { overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' } }}
              items={[
                { label: '目标地址', children: detailText(selectedFinding.target) },
                { label: '端口', children: detailText(selectedFinding.port) },
                { label: '业务组', children: detailText(selectedFinding.businessGroup) },
                { label: '负责人', children: detailText(selectedFinding.owner) },
                { label: '引擎', children: detailText(selectedFinding.engine) },
                { label: '模板 / CVE', children: detailText(selectedFinding.templateOrCve) },
                { label: '检测方式', children: detailText(selectedFinding.detectMethod && methodLabels[selectedFinding.detectMethod]) },
                { label: '置信度', children: detailText(selectedFinding.confidence && confidenceLabels[selectedFinding.confidence]) },
                { label: '风险类型', children: detailText(selectedFinding.riskType && riskLabels[selectedFinding.riskType]) },
                { label: '漏洞分类', children: detailText(selectedFinding.vulnCategory) },
                { label: 'CVSS', children: detailText(selectedFinding.cvssScore) },
                { label: '组件', children: detailText(selectedFinding.component) },
                { label: '软件包', children: detailText(selectedFinding.package) },
                { label: '安装版本', children: detailText(selectedFinding.installedVersion) },
                { label: '修复版本', children: detailText(selectedFinding.fixedVersion) },
                { label: '内容语言', children: detailText(selectedFinding.contentLanguage) },
              ].map((item, key) => ({ ...item, key }))}
            />
            {[
              { label: '描述', value: detailText(selectedFinding.description) },
              { label: '影响', value: detailText(selectedFinding.impact) },
              { label: '修复建议', value: detailText(selectedFinding.solution) },
              { label: '证据', value: detailText(selectedFinding.evidence) },
              { label: '匹配路径', value: detailText(selectedFinding.matchedPath) },
              { label: '外部编号', value: detailIdentifiers(selectedFinding.identifiers) },
              { label: '参考资料', value: detailList(selectedFinding.references) },
            ].map(field => (
              <section key={field.label} style={{ width: '100%', minWidth: 0 }}>
                <Typography.Title level={5} style={{ marginTop: 0 }}>{field.label}</Typography.Title>
                <div tabIndex={0} role="region" aria-label={`${field.label}全文`}
                  style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 240, overflowY: 'auto', padding: 12, background: '#fafafa', border: '1px solid #f0f0f0', borderRadius: 6 }}>
                  {field.value}
                </div>
              </section>
            ))}
            <Descriptions title="时间与未检出计数" column={1} size="small" bordered
              styles={{ content: { overflowWrap: 'anywhere' } }}
              items={[
                { label: '首次检出', children: detailText(selectedFinding.firstSeen) },
                { label: '最近检出', children: detailText(selectedFinding.lastSeen) },
                { label: '修复时间', children: detailText(selectedFinding.resolvedAt) },
                { label: '连续未检出次数', children: detailText(selectedFinding.consecutiveMisses) },
              ].map((item, key) => ({ ...item, key }))}
            />
            <section style={{width:'100%'}}>
              <Typography.Title level={5}>风险处置</Typography.Title>
              {selectedFinding.status==='ACCEPTED_RISK' && <Space direction="vertical" style={{width:'100%'}}>
                <Text style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>接受原因：{detailText(selectedFinding.acceptedReason)}</Text>
                <Text>到期时间：{detailText(selectedFinding.acceptedUntil)}</Text>
                <Button loading={saving} disabled={!isDemoMode&&!canWrite} onClick={()=>void handleUpdateStatus(selectedFinding.id,'OPEN')}>撤销接受风险</Button>
              </Space>}
              {canAcceptRisk(selectedFinding.status)&&<Space direction="vertical" style={{width:'100%'}}>
                <label htmlFor="accept-risk-reason">接受原因（最多 500 UTF-8 字节）</label>
                <Input.TextArea id="accept-risk-reason" value={acceptReason} onChange={e=>setAcceptReason(e.target.value)} autoSize={{minRows:2,maxRows:6}} disabled={saving||(!isDemoMode&&!canWrite)} />
                <label htmlFor="accept-risk-until">到期时间（本地时间，未来 365 天内）</label>
                <Input id="accept-risk-until" type="datetime-local" value={acceptUntil} onChange={e=>setAcceptUntil(e.target.value)} disabled={saving||(!isDemoMode&&!canWrite)} />
                <Button loading={saving} disabled={!isDemoMode&&!canWrite} onClick={()=>{try{void handleUpdateStatus(selectedFinding.id,'ACCEPTED_RISK',acceptanceInput(acceptReason,acceptUntil))}catch(e){message.error(e instanceof Error?e.message:'接受风险输入无效')}}}>接受风险</Button>
              </Space>}
              {selectedFinding.status==='FIXED'&&<Text type="secondary">修复状态由完整扫描判定。</Text>}
            </section>
            <section style={{width:'100%'}}>
              <Typography.Title level={5}>状态变更记录</Typography.Title>
              {eventsError&&<Alert type="error" message={eventsError} />}
              {events.length?<Timeline items={events.map(event=>({key:event.id,children:<Space direction="vertical" size={2}><Text>{event.fromStatus} → {event.toStatus}</Text><Text type="secondary">{event.createdAt} · {event.actor}</Text>{event.reason&&<Text style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{event.reason}</Text>}</Space>}))}/>:<Text type="secondary">{isDemoMode?'演示模式没有服务端状态记录':'暂无状态变更记录'}</Text>}
            </section>
            <Descriptions title="关联标识" column={1} size="small" bordered
              styles={{ content: { overflowWrap: 'anywhere', whiteSpace: 'pre-wrap' } }}
              items={[
                { label: '发现项 ID', children: detailText(selectedFinding.id) },
                { label: '稳定指纹', children: detailText(selectedFinding.fingerprint) },
                { label: '资产 ID', children: detailText(selectedFinding.assetId) },
                { label: '任务 ID', children: detailText(selectedFinding.taskId) },
                { label: '制品 ID', children: detailText(selectedFinding.artifactId) },
              ].map((item, key) => ({ ...item, key }))}
            />
          </Space>
        )}
      </Drawer>
    </div>
  );
};
