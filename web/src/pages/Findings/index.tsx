import React, { useCallback, useEffect, useRef, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { useSearchParams } from 'react-router-dom';
import {
  Button,
  Space,
  Typography,
  Tooltip,
  Segmented,
  message,
} from 'antd';
import { Finding, FindingSeverity, FindingStatus } from '../../types';
import { FindingStatusTag, Mono, SeverityTag } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { useAuth } from '../../auth/AuthProvider';
import { updateFinding } from '../../api/runtime';
import { apiClient, errorMessage } from '../../api/client';
import type { FindingQueryOptions } from '../../api/client';
import { CollectionNotice } from '../../api/CollectionNotice';
import { TitleWithHelp } from '../../components/HelpTip';
import { usePageState, useQuery } from '../../api/query';

import { riskLabels, methodLabels, confidenceLabels, isVerifiedFinding } from './presentation';
import { FindingFilters, FindingSort, FindingView, readFindingFilters, writeFindingFilters } from './filters';
import { FindingFilterBar } from './FilterBar';
import { FindingGroups } from './FindingGroups';
import { selectedFindingForDrawer } from './drawer';
import { FindingSelection, updateBatchSelection } from './batch';
import { formatDate, formatTime } from '../../utils/time';
import { FindingDrawer } from './FindingDrawer';
import { BatchBar } from './BatchBar';
const { Text } = Typography;

export const FindingsPage: React.FC = () => {
  const {canWrite}=useAuth();
  const {palette}=useAppTheme();
  const [findingRevision,setFindingRevision]=useState(0);
  const [searchParams, setSearchParams] = useSearchParams();
  const filters = readFindingFilters(searchParams);
  const { severity: severityFilter, status: statusFilter, method: methodFilter,
    confidence: confidenceFilter, risk: riskFilter, onlyVerified, businessGroup, assetId } = filters;
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
  // Free text stays local (it often holds target addresses) and is debounced.
  const [query, setQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  useEffect(() => { const timer = window.setTimeout(() => setDebouncedQuery(query.trim()), 300); return () => window.clearTimeout(timer); }, [query]);
  const queryOptions: FindingQueryOptions = { search: debouncedQuery, severity: severityFilter, status: statusFilter, method: methodFilter, confidence: confidenceFilter, risk: riskFilter, engine: filters.engine, onlyVerified, fixable: filters.fixable, businessGroup, assetId, cve: filters.cve, package: filters.package, taskId: filters.taskId };
  const optionsKey = JSON.stringify(queryOptions);
  const view = filters.view;
  const sort = filters.sort;
  const [groupSummary, setGroupSummary] = useState<{ findings: number; counts: typeof findingCountsSummary } | null>(null);
  const [groupError, setGroupError] = useState<string | null>(null);
  const onGroupSummary = useCallback((summary: { findings: number; counts: typeof findingCountsSummary } | null, error: string | null) => { setGroupSummary(summary); setGroupError(error); }, []);
  const [groupFindings, setGroupFindings] = useState<Finding[]>([]);
  const onGroupFindingsLoaded = useCallback((items: Finding[]) => setGroupFindings(previous => {
    const next = new Map(previous.map(item => [item.id, item]));
    for (const item of items) next.set(item.id, item);
    return [...next.values()];
  }), []);
  useEffect(() => { setGroupFindings([]); }, [view, optionsKey]);
  const [businessGroups, setBusinessGroups] = useState<string[]>([]);
  useEffect(() => { void apiClient.businessGroups().then(result => setBusinessGroups(result.items.map(item => item.name))).catch(() => setBusinessGroups([])); }, []);
  const emptyCounts={vulnerabilities:0,loginEntries:0,unknown:0,version:0,verified:0};
  const {page:findingPage,pageSize:findingPageSize,onChange:onFindingPageChange}=usePageState([optionsKey,sort],10);
  const findingList=useQuery(signal=>apiClient.findingsPage(findingPage,findingPageSize,{...queryOptions,sort},signal),[findingPage,findingPageSize,optionsKey,sort,findingRevision],{enabled:view==='flat',errorFallback:'漏洞清册加载失败',emptyValue:{items:[],total:0,page:1,pageSize:findingPageSize,counts:emptyCounts}});
  const findings=findingList.data?.items??[];const findingTotal=findingList.data?.total??0;const findingCountsSummary=findingList.data?.counts??emptyCounts;const findingLoading=findingList.loading;const findingError=findingList.error;
  // Saved edits replace rows in place until the next refetch.
  const setFindings=(update:(previous:Finding[])=>Finding[])=>findingList.setData(current=>current&&{...current,items:update(current.items)});
  const [selectedFindingId, setSelectedFindingId] = useState<string | null>(null);
  const detailTrigger = useRef<HTMLElement | null>(null);
  const [saving,setSaving]=useState(false);
  const [eventRevision,setEventRevision]=useState(0);
  const [batchSelection,setBatchSelection]=useState<FindingSelection[]>([]);
  const [batchSaving,setBatchSaving]=useState(false);

  const filteredFindings = findings;
  // Grouped views open the same drawer for findings loaded by expanded rows.
  const drawerFindings = view === 'flat' ? findings : groupFindings;
  const selectedFinding = selectedFindingForDrawer(drawerFindings, view === 'flat' ? filteredFindings : groupFindings, selectedFindingId);
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
      message.warning('FIXED 必须经平台确认完整扫描、规则执行和未检出阈值，目前不可操作');
      return;
    }
    setSaving(true);try{const item=await updateFinding(id,newStatus,acceptance);setFindings(prev=>prev.map(f=>f.id===id?item:f));setGroupFindings(prev=>prev.map(f=>f.id===id?item:f));setFindingRevision(n=>n+1);setEventRevision(n=>n+1);message.success('状态已保存并记录审计');}catch(e){message.error(errorMessage(e));}finally{setSaving(false)}
  };

  const summaryCounts = view === 'flat' ? findingCountsSummary : groupSummary?.counts ?? findingCountsSummary;
  const summaryTotal = view === 'flat' ? findingTotal : groupSummary?.findings ?? 0;
  const sortOrder = (key: string) => sort === key ? 'ascend' as const : sort === '-' + key ? 'descend' as const : null;
  const muted = { color: palette.textSecondary };
  const drill = (key: string) => updateFilters(view === 'cve' ? { view: 'flat', cve: key, package: '' } : { view: 'flat', package: key, cve: '' });

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <PageHeader
        title="漏洞列表"
        description={view === 'flat' ? '每条发现项单独一行；按 CVE 或软件包查看可以合并重复项' : view === 'cve' ? '按漏洞编号合并：同一 CVE 落在多个二进制包上时只算一组' : '按软件包合并：一次升级可以修复的漏洞放在一起'}
        extra={<Segmented aria-label="漏洞视图" value={view} onChange={value => updateFilters({ view: value as FindingView })} options={[{ label: '平铺', value: 'flat' }, { label: '按 CVE', value: 'cve' }, { label: '按软件包', value: 'package' }]} />}
      />
      <CollectionNotice loading={view === 'flat' && findingLoading} error={view === 'flat' ? findingError : groupError} hasData={view === 'flat' ? findings.length > 0 : groupSummary !== null} />
      <FindingFilterBar filters={filters} query={query} businessGroups={businessGroups} onQuery={setQuery} onChange={updateFilters} />
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px 20px', alignItems: 'baseline', fontSize: 13, ...muted }}>
        <span>当前筛选结果 <Mono style={{ color: palette.text, fontWeight: 600 }}>{summaryTotal.toLocaleString()}</Mono> 项</span>
        <span>其中漏洞 <Mono style={{ color: palette.text }}>{summaryCounts.vulnerabilities.toLocaleString()}</Mono></span>
        <span>版本推断 <Mono style={{ color: palette.text }}>{summaryCounts.version.toLocaleString()}</Mono></span>
        <span>已验证 <Mono style={{ color: palette.text }}>{summaryCounts.verified.toLocaleString()}</Mono></span>
        <span>登录入口 <Mono style={{ color: palette.text }}>{summaryCounts.loginEntries.toLocaleString()}</Mono></span>
        {summaryCounts.unknown > 0 && <span>未核实类型 <Mono style={{ color: palette.text }}>{summaryCounts.unknown.toLocaleString()}</Mono></span>}
      </div>

      {view !== 'flat' && <Panel flush title={view === 'cve' ? '按漏洞编号聚合' : '按软件包聚合'} extra={<span style={muted}>按最高严重级别排序 · 点击行展开明细</span>}>
        <FindingGroups by={view} options={queryOptions} revision={findingRevision} onDrill={drill} onOpen={openFindingDetails} onLoaded={onGroupFindingsLoaded} onSummary={onGroupSummary} />
      </Panel>}

      {view === 'flat' && <Panel flush title="漏洞发现与生命周期闭环看板" extra={<TitleWithHelp title={<span style={muted}>检测依据说明</span>} helpTitle="如何理解检测依据" help="Web 基线检查结果需结合服务用途判断；系统包结果展示漏洞编号、受影响组件和修复版本。版本推断没有实际验证漏洞；未标注检测方式的历史结果显示为未核实。未检出不会自动标记为已修复。"/>}>
        <BatchBar selection={batchSelection} onSelectionChange={setBatchSelection} findings={findings} canWrite={canWrite} onBusyChange={setBatchSaving}
          onUpdated={(items, kind) => { const updated = new Map(items.map(item => [item.id, item])); setFindings(previous => previous.map(item => updated.get(item.id) ?? item)); if (kind === 'status') { setFindingRevision(n => n + 1); setEventRevision(n => n + 1); } }} />
        <DataTable<Finding>
          dataSource={filteredFindings}
          loading={findingLoading}
          rowKey="id"
          rowSelection={{
            selectedRowKeys:batchSelection.map(item=>item.id),
            preserveSelectedRowKeys:true,
            onChange:keys=>setBatchSelection(previous=>updateBatchSelection(previous,keys,findings)),
            getCheckboxProps:record=>({'aria-label':`选择 ${record.title}`,disabled:batchSaving||!canWrite||record.status==='FIXED'||(batchSelection.length>=100&&!batchSelection.some(item=>item.id===record.id))}),
          }}
          onChange={(_pagination,_filters,sorter,extra)=>{
            if(extra.action!=='sort')return;
            const current=Array.isArray(sorter)?sorter[0]:sorter;
            const key=String(current?.columnKey??'');
            updateFilters({sort:(current?.order?(current.order==='ascend'?key:'-'+key):'-severity') as FindingSort});
          }}
          pagination={{current:findingPage,pageSize:findingPageSize,total:findingTotal,showSizeChanger:true,pageSizeOptions:[10,20,50,100],showTotal:total=>`共 ${total} 项`,onChange:onFindingPageChange}}
          scroll={{x:1210}}
          columns={[
            {title:'等级',key:'severity',dataIndex:'severity',width:96,sorter:true,sortOrder:sortOrder('severity'),sortDirections:['descend','ascend'],render:(s: FindingSeverity)=><SeverityTag value={s} />},
            {title:'漏洞',key:'title',width:340,sorter:true,sortOrder:sortOrder('title'),render:(_,record)=>(
              <div style={{display:'flex',flexDirection:'column',gap:3,minWidth:0}}>
                <Text strong style={{whiteSpace:'normal',wordBreak:'break-word'}}>{record.title}</Text>
                <span style={{display:'flex',flexWrap:'wrap',gap:6,alignItems:'center',fontSize:12,...muted}}>
                  <Mono style={{color:palette.text}}>{record.templateOrCve}</Mono>
                  <span>{record.engine==='trivy'?'系统包 / 依赖':record.engine==='nuclei'?'Web 基线':record.engine}</span>
                  <Tooltip title={`${riskLabels[record.riskType??'unknown']} · ${confidenceLabels[record.confidence??'unknown']}`}><span style={{color:isVerifiedFinding(record)?palette.success:record.detectMethod==='version'?palette.warning:palette.textTertiary}}>{methodLabels[record.detectMethod??'unknown']}</span></Tooltip>
                  {record.synthetic&&<span style={{color:palette.primary}}>模拟结果</span>}
                </span>
              </div>
            )},
            {title:'软件包 / 版本',key:'package',width:250,render:(_,record)=>record.package?(
              <div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}>
                <Mono>{record.package}</Mono>
                <span style={{fontSize:12,display:'flex',flexWrap:'wrap',gap:4}}><Mono style={muted}>{record.installedVersion||'—'}</Mono><span style={{color:palette.textTertiary}}>→</span>{record.fixedVersion?<Mono style={{color:palette.success}}>{record.fixedVersion}</Mono>:<span style={{color:palette.textTertiary}}>暂无修复版本</span>}</span>
              </div>
            ):<span style={{color:palette.textTertiary}}>—</span>},
            {title:'目标',key:'target',dataIndex:'target',width:190,sorter:true,sortOrder:sortOrder('target'),render:(t:string,record)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><Mono>{t}</Mono><span style={{fontSize:12,...muted}}>{record.businessGroup}{record.owner?` · ${record.owner}`:''}</span></div>},
            {title:'状态',key:'status',dataIndex:'status',width:130,render:(s: FindingStatus,record)=><div style={{display:'flex',flexDirection:'column',gap:4,alignItems:'flex-start'}}><FindingStatusTag value={s} />{(record.assigneeName||record.assigneeId)&&<span style={{fontSize:12,...muted}}>{record.assigneeName||record.assigneeId}</span>}</div>},
            {title:'最近检出',key:'last_seen',width:150,sorter:true,sortOrder:sortOrder('last_seen'),sortDirections:['descend','ascend'],render:(_,r)=><div style={{display:'flex',flexDirection:'column',gap:2,fontSize:12}}><span>{formatTime(r.lastSeen,'—')}</span>{r.status==='FIXED'?<Text type="success" style={{fontSize:12}}>连续未检出 {r.consecutiveMisses} 次</Text>:<span style={muted}>首次 {r.firstSeen?formatDate(r.firstSeen):'—'}</span>}</div>},
            {
              title: '操作',
              key: 'actions',
              width: 210,
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
                  {r.status!=='OPEN'&&r.status!=='FIXED'&&<Button type="link" size="small" disabled={!canWrite} onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'OPEN'); }}>恢复待处理</Button>}
                  {r.status === 'OPEN' && (
                    <Button
                      type="link"
                      size="small"
                      disabled={!canWrite}
                      onClick={event => { event.stopPropagation(); void handleUpdateStatus(r.id, 'IN_PROGRESS'); }}
                    >
                      标记处理中
                    </Button>
                  )}
                  {r.status === 'IN_PROGRESS' && (
                    <Button
                      type="link"
                      size="small"
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
                      disabled={!canWrite}
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
      </Panel>}
      <FindingDrawer selectedFinding={selectedFinding ?? null} canWrite={canWrite} saving={saving} eventRevision={eventRevision}
        onClose={closeFindingDetails} afterOpenChange={restoreDetailFocus} onUpdateStatus={handleUpdateStatus}
        onFindingUpdated={item => { setFindings(previous => previous.map(f => f.id === item.id ? item : f)); setGroupFindings(previous => previous.map(f => f.id === item.id ? item : f)); if (view !== 'flat') setFindingRevision(n => n + 1); }} />
    </div>
  );
};
