import React, { useCallback, useEffect, useRef, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { useSearchParams } from 'react-router-dom';
import {
  Button,
  Space,
  Select,
  Input,
  Typography,
  Tooltip,
  Modal,
  Segmented,
  message,
} from 'antd';
import { Finding, FindingAssignee, FindingSeverity, FindingStatus } from '../../types';
import { FindingStatusTag, Mono, SeverityTag } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { useAuth } from '../../auth/AuthProvider';
import { batchAssignFindings, batchFindingDisposition, updateFinding, fetchFindingAssignees } from '../../api/runtime';
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
import { acceptanceInput } from './disposition';
import { FindingSelection, batchAssignmentSelectionChanged, batchSelectionChanged, batchTransitionAllowed, updateBatchSelection } from './batch';
import { FindingDrawer } from './FindingDrawer';
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
  const [batchAssignees,setBatchAssignees]=useState<FindingAssignee[]>([]);
  const [batchAssigneeError,setBatchAssigneeError]=useState('');
  useEffect(()=>{
    if(!canWrite){setBatchAssignees([]);setBatchAssigneeError('');return}
    const controller=new AbortController();
    void fetchFindingAssignees(controller.signal).then(result=>{if(!controller.signal.aborted){setBatchAssignees(result.items);setBatchAssigneeError('')}}).catch(()=>{if(!controller.signal.aborted)setBatchAssigneeError('批量指派候选加载失败')});
    return()=>controller.abort();
  },[canWrite]);
  const [batchSelection,setBatchSelection]=useState<FindingSelection[]>([]);
  const [batchStatus,setBatchStatus]=useState<FindingStatus>('IN_PROGRESS');
  const [batchOpen,setBatchOpen]=useState(false);
  const [batchReason,setBatchReason]=useState('');
  const [batchUntil,setBatchUntil]=useState('');
  const [batchSaving,setBatchSaving]=useState(false);
  const [batchAssignOpen,setBatchAssignOpen]=useState(false);
  const [batchAssigneeId,setBatchAssigneeId]=useState('');
  const [batchAssignSaving,setBatchAssignSaving]=useState(false);
  const selectionChanged=batchSelectionChanged(batchSelection,findings,true);
  const batchAllowed=batchSelection.length>0&&batchSelection.length<=100&&!selectionChanged&&batchSelection.every(item=>batchTransitionAllowed(item.expectedStatus,batchStatus));
  const assignmentSelectionChanged=batchAssignmentSelectionChanged(batchSelection,findings,true);
  const batchAssignmentAllowed=canWrite&&batchSelection.length>0&&batchSelection.length<=100&&!assignmentSelectionChanged&&!batchAssigneeError&&batchAssigneeId!=='';
  const saveBatch=async()=>{
    if(!canWrite||!batchAllowed)return;
    try{
      const acceptance=batchStatus==='ACCEPTED_RISK'?acceptanceInput(batchReason,batchUntil):undefined;
      setBatchSaving(true);
      const result=await batchFindingDisposition(batchSelection,batchStatus,acceptance);
      const updated=new Map(result.items.map(item=>[item.id,item]));
      setFindings(previous=>previous.map(item=>updated.get(item.id)??item));setFindingRevision(n=>n+1);
      setBatchSelection([]);setBatchOpen(false);setBatchReason('');setBatchUntil('');setEventRevision(n=>n+1);
      message.success(`已更新 ${result.updated} 项并记录审计`);
    }catch(e){message.error(`${errorMessage(e)}；整批未保存，请核对当前状态后重新选择`)}finally{setBatchSaving(false)}
  };
  const saveBatchAssignment=async()=>{
    if(!batchAssignmentAllowed)return;
    setBatchAssignSaving(true);
    try{
      const result=await batchAssignFindings(batchSelection.map(item=>({id:item.id,expectedAssigneeId:item.expectedAssigneeId??''})),batchAssigneeId);
      const updated=new Map(result.items.map(item=>[item.id,item]));
      setFindings(previous=>previous.map(item=>updated.get(item.id)??item));
      setBatchSelection([]);setBatchAssignOpen(false);setBatchAssigneeId('');
      message.success(`已批量指派 ${result.updated} 项并记录审计`);
    }catch(e){message.error(`${errorMessage(e)}；整批未保存，请核对当前指派状态后重试`)}finally{setBatchAssignSaving(false)}
  };

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
      <CollectionNotice loading={view === 'flat' && findingLoading && findings.length === 0} error={view === 'flat' ? findingError : groupError} />
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
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '12px 20px', borderTop: `1px solid ${palette.borderSubtle}`, borderBottom: `1px solid ${palette.borderSubtle}`, background: batchSelection.length ? palette.bgElevated : undefined }}>
          <Text>已选择 {batchSelection.length} 项（最多 100 项，包含其他分页和筛选中的已选项）</Text>
          <Select aria-label="批量处置状态" value={batchStatus} disabled={batchSaving} onChange={setBatchStatus} style={{width:150}} options={[
            {value:'IN_PROGRESS',label:'标记修复中'}, {value:'FALSE_POSITIVE',label:'标记误报'}, {value:'ACCEPTED_RISK',label:'接受风险'}, {value:'OPEN',label:'恢复待处理'},
          ]}/>
          <Button type="primary" disabled={!canWrite||!batchAllowed||batchSaving} onClick={()=>{setBatchReason('');setBatchUntil('');setBatchOpen(true)}}>批量处置</Button>
          <Select aria-label="批量指派对象" allowClear placeholder="批量指派给" value={batchAssigneeId||undefined} onChange={value=>setBatchAssigneeId(value??'')} disabled={!canWrite||batchAssignSaving||Boolean(batchAssigneeError)} style={{width:150}} options={batchAssignees.map(item=>({value:item.id,label:item.name}))}/>
          <Button disabled={!batchAssignmentAllowed||batchAssignSaving} onClick={()=>setBatchAssignOpen(true)}>批量指派</Button>
          <Button disabled={!batchSelection.length||batchSaving} onClick={()=>setBatchSelection([])}>清空选择</Button>
          {batchSelection.length>0&&!batchAllowed&&<Text type="warning">{selectionChanged?'已选记录状态已变化，请清空后重新选择':'选中记录包含不允许的状态流转，请调整选择或目标状态'}</Text>}
          {batchSelection.length>0&&assignmentSelectionChanged&&<Text type="warning">已选记录的指派状态已变化，请清空后重新选择</Text>}
          {batchAssigneeError&&<Text type="warning">{batchAssigneeError}</Text>}
        </div>
        <DataTable<Finding>
          dataSource={filteredFindings}
          loading={findingLoading}
          rowKey="id"
          rowSelection={{
            selectedRowKeys:batchSelection.map(item=>item.id),
            preserveSelectedRowKeys:true,
            onChange:keys=>setBatchSelection(previous=>updateBatchSelection(previous,keys,findings)),
            getCheckboxProps:record=>({disabled:batchSaving||!canWrite||record.status==='FIXED'||(batchSelection.length>=100&&!batchSelection.some(item=>item.id===record.id))}),
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
            {title:'最近检出',key:'last_seen',width:150,sorter:true,sortOrder:sortOrder('last_seen'),sortDirections:['descend','ascend'],render:(_,r)=><div style={{display:'flex',flexDirection:'column',gap:2,fontSize:12}}><span>{r.lastSeen?new Date(r.lastSeen).toLocaleString():'—'}</span>{r.status==='FIXED'?<Text type="success" style={{fontSize:12}}>连续未检出 {r.consecutiveMisses} 次</Text>:<span style={muted}>首次 {r.firstSeen?new Date(r.firstSeen).toLocaleDateString():'—'}</span>}</div>},
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
      <Modal title="确认批量处置" open={batchOpen} onCancel={()=>{if(!batchSaving)setBatchOpen(false)}} onOk={()=>void saveBatch()} confirmLoading={batchSaving} okText="确认保存" cancelText="取消" okButtonProps={{disabled:!batchAllowed}} cancelButtonProps={{disabled:batchSaving}} closable={!batchSaving} maskClosable={!batchSaving}>
        <Space direction="vertical" style={{width:'100%'}}>
          <Text>将以下 {batchSelection.length} 项统一更新为 {batchStatus}。任一记录状态发生变化或不允许流转时，整批不保存。</Text>
          <div style={{maxHeight:180,overflowY:'auto',overflowWrap:'anywhere'}}>{batchSelection.map(item=><div key={item.id}><Text code>{item.id}</Text> · {item.expectedStatus}</div>)}</div>
          {batchStatus==='ACCEPTED_RISK'&&<>
            <Input.TextArea aria-label="批量接受风险原因" placeholder="统一接受原因（1–500 UTF-8 字节）" value={batchReason} onChange={e=>setBatchReason(e.target.value)} disabled={batchSaving}/>
            <Input aria-label="批量接受风险到期时间" type="datetime-local" value={batchUntil} onChange={e=>setBatchUntil(e.target.value)} disabled={batchSaving}/>
          </>}
        </Space>
      </Modal>
      <Modal title="确认批量指派" open={batchAssignOpen} onCancel={()=>{if(!batchAssignSaving)setBatchAssignOpen(false)}} onOk={()=>void saveBatchAssignment()} confirmLoading={batchAssignSaving} okText="确认指派" cancelText="取消" okButtonProps={{disabled:!batchAssignmentAllowed}} cancelButtonProps={{disabled:batchAssignSaving}} closable={!batchAssignSaving} maskClosable={!batchAssignSaving}>
        <Space direction="vertical" style={{width:'100%'}}>
          <Text>将以下 {batchSelection.length} 项统一指派给 {batchAssignees.find(item=>item.id===batchAssigneeId)?.name??batchAssigneeId}。任一记录指派状态发生变化时，整批不保存。</Text>
          <div style={{maxHeight:180,overflowY:'auto',overflowWrap:'anywhere'}}>{batchSelection.map(item=><div key={item.id}><Text code>{item.id}</Text> · 当前 {item.expectedAssigneeId||'未指派'}</div>)}</div>
        </Space>
      </Modal>
      <FindingDrawer selectedFinding={selectedFinding ?? null} canWrite={canWrite} saving={saving} eventRevision={eventRevision}
        onClose={closeFindingDetails} afterOpenChange={restoreDetailFocus} onUpdateStatus={handleUpdateStatus}
        onFindingUpdated={item => { setFindings(previous => previous.map(f => f.id === item.id ? item : f)); setGroupFindings(previous => previous.map(f => f.id === item.id ? item : f)); if (view !== 'flat') setFindingRevision(n => n + 1); }} />
    </div>
  );
};
