import React, { useCallback, useEffect, useRef, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { useSearchParams } from 'react-router-dom';
import {
  Tag,
  Button,
  Space,
  Select,
  Input,
  Typography,
  Alert,
  Tooltip,
  Descriptions,
  Drawer,
  Timeline,
  Modal,
  Segmented,
  message,
  theme,
} from 'antd';
import { Finding, FindingAssignmentEvent, FindingEvent, FindingAssignee, FindingNote, FindingRetest, FindingSeverity, FindingStatus } from '../../types';
import { FindingStatusTag, Mono, SeverityTag } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import { useAuth } from '../../auth/AuthProvider';
import { batchAssignFindings, batchFindingDisposition, updateFinding, fetchFindingEvents, fetchFindingAssignees, fetchFindingAssignments, assignFinding, fetchFindingNotes, addFindingNote, createFindingRetest, fetchFindingRetests } from '../../api/runtime';
import { apiClient } from '../../api/client';
import type { FindingQueryOptions } from '../../api/client';
import { CollectionNotice } from '../../api/CollectionNotice';
import { TitleWithHelp } from '../../components/HelpTip';
import { pollWhileVisible } from '../../api/polling';

import { riskLabels, methodLabels, confidenceLabels, isVerifiedFinding } from './presentation';
import { FindingFilters, FindingSort, FindingView, readFindingFilters, writeFindingFilters } from './filters';
import { FindingFilterBar } from './FilterBar';
import { FindingGroups } from './FindingGroups';
import { detailText, detailList, detailIdentifiers, selectedFindingForDrawer } from './drawer';
import { canAcceptRisk, acceptanceInput } from './disposition';
import { findingNoteInput } from './work';
import { FindingSelection, batchAssignmentSelectionChanged, batchSelectionChanged, batchTransitionAllowed, updateBatchSelection } from './batch';
import { retestIsActive, retestStatusLabel } from './retest';
const { Text } = Typography;

export const FindingsPage: React.FC = () => {
  const {user}=useAuth();
  const {token}=theme.useToken();
  const {palette}=useAppTheme();
  const canWrite=user?.role==='admin'||user?.role==='security_engineer';
  const [findings,setFindings]=useState<Finding[]>([]);const [findingLoading,setFindingLoading]=useState(true);const [findingError,setFindingError]=useState<string|null>(null);const [findingPage,setFindingPage]=useState(1);const [findingPageSize,setFindingPageSize]=useState(10);const [findingTotal,setFindingTotal]=useState(0);const [findingCountsSummary,setFindingCountsSummary]=useState({vulnerabilities:0,loginEntries:0,unknown:0,version:0,verified:0});const [findingRevision,setFindingRevision]=useState(0);
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
  useEffect(()=>{
    if(view!=='flat')return;
    const controller=new AbortController();
    setFindingLoading(true);
    apiClient.findingsPage(findingPage,findingPageSize,{...queryOptions,sort},controller.signal).then(result=>{
      if(!controller.signal.aborted){setFindings(result.items);setFindingTotal(result.total);setFindingCountsSummary(result.counts);setFindingError(null);}
    }).catch(cause=>{if(!controller.signal.aborted){setFindings([]);setFindingTotal(0);setFindingCountsSummary({vulnerabilities:0,loginEntries:0,unknown:0,version:0,verified:0});setFindingError(cause instanceof Error?cause.message:'漏洞清册加载失败');}}).finally(()=>{if(!controller.signal.aborted)setFindingLoading(false)});
    return()=>controller.abort();
  // queryOptions is compared through optionsKey.
  },[view,findingPage,findingPageSize,optionsKey,sort,findingRevision]);
  useEffect(()=>{if(findingPage!==1)setFindingPage(1)},[optionsKey,sort]);
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
    if(!selectedFindingId)return;
    const controller=new AbortController();
    const load=()=>fetchFindingEvents(selectedFindingId,controller.signal).then(result=>{if(!controller.signal.aborted){setEvents(result.items);setEventsError('')}}).catch(()=>{if(!controller.signal.aborted)setEventsError('状态记录加载失败，请稍后重试')});
    void load();const stop=pollWhileVisible(()=>void load(),10000);
    return ()=>{controller.abort();stop()};
  },[selectedFindingId,eventRevision]);

  const [retests,setRetests]=useState<FindingRetest[]>([]);
  const [retestError,setRetestError]=useState('');
  const [retestSaving,setRetestSaving]=useState(false);
  const [retestRevision,setRetestRevision]=useState(0);
  useEffect(()=>{
    setRetests([]);setRetestError('');
    if(!selectedFindingId)return;
    const controller=new AbortController();
    void fetchFindingRetests(selectedFindingId,controller.signal).then(result=>{if(!controller.signal.aborted)setRetests(result.items)}).catch(()=>{if(!controller.signal.aborted)setRetestError('复测记录加载失败，请稍后重试')});
    return()=>controller.abort();
  },[selectedFindingId,retestRevision]);

  const [assignees,setAssignees]=useState<FindingAssignee[]>([]);
  const [assignmentEvents,setAssignmentEvents]=useState<FindingAssignmentEvent[]>([]);
  const [assigneeId,setAssigneeId]=useState('');
  const [notes,setNotes]=useState<FindingNote[]>([]);
  const [noteBody,setNoteBody]=useState('');
  const [workError,setWorkError]=useState('');
  const [workSaving,setWorkSaving]=useState(false);
  const [workRevision,setWorkRevision]=useState(0);
  useEffect(()=>{
    setNotes([]);setNoteBody('');setAssignees([]);setAssignmentEvents([]);setWorkError('');
    if(!selectedFindingId)return;
    const controller=new AbortController();
    void Promise.all([canWrite?fetchFindingAssignees(controller.signal):Promise.resolve({items:[] as FindingAssignee[],total:0}),fetchFindingNotes(selectedFindingId,controller.signal),fetchFindingAssignments(selectedFindingId,controller.signal)]).then(([users,result,history])=>{
      if(!controller.signal.aborted){setAssignees(users.items);setNotes(result.items);setAssignmentEvents(history.items)}
    }).catch(()=>{if(!controller.signal.aborted)setWorkError('指派候选或备注加载失败，请关闭详情后重试')});
    return()=>controller.abort();
  },[selectedFindingId,workRevision,canWrite]);

  const [batchAssignees,setBatchAssignees]=useState<FindingAssignee[]>([]);
  const [batchAssigneeError,setBatchAssigneeError]=useState('');
  useEffect(()=>{
    if(!canWrite){setBatchAssignees([]);setBatchAssigneeError('');return}
    const controller=new AbortController();
    void fetchFindingAssignees(controller.signal).then(result=>{if(!controller.signal.aborted){setBatchAssignees(result.items);setBatchAssigneeError('')}}).catch(()=>{if(!controller.signal.aborted)setBatchAssigneeError('批量指派候选加载失败')});
    return()=>controller.abort();
  },[canWrite]);
  const saveAssignment=async(id:string)=>{
    setWorkSaving(true);
    try{const item=await assignFinding(id,assigneeId);setFindings(previous=>previous.map(f=>f.id===id?item:f));setGroupFindings(previous=>previous.map(f=>f.id===id?item:f));if(view!=='flat')setFindingRevision(n=>n+1);message.success('指派已保存并记录审计')}
    catch(e){message.error(String(e))}finally{setWorkSaving(false)}
  };
  const saveNote=async(id:string)=>{
    try{const body=findingNoteInput(noteBody);setWorkSaving(true);await addFindingNote(id,body);setWorkRevision(n=>n+1);message.success('备注已追加并记录审计')}
    catch(e){message.error(e instanceof Error?e.message:String(e))}finally{setWorkSaving(false)}
  };

  const startRetest=async(id:string)=>{
    Modal.confirm({
      title:'确认重新扫描该漏洞？',
      content:'平台会复用原扫描任务的冻结目标和授权范围，并创建一条新的扫描任务。',
      okText:'创建复测任务',cancelText:'取消',
      onOk:async()=>{
        setRetestSaving(true);
        try{const result=await createFindingRetest(id);setRetests(previous=>[...previous,result.retest]);setRetestRevision(n=>n+1);message.success(`复测任务已创建：${result.task.id}`)}
        catch(e){message.error(e instanceof Error?e.message:String(e));throw e}
        finally{setRetestSaving(false)}
      },
    });
  };

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
    }catch(e){message.error(`${e instanceof Error?e.message:String(e)}；整批未保存，请核对当前状态后重新选择`)}finally{setBatchSaving(false)}
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
    }catch(e){message.error(`${e instanceof Error?e.message:String(e)}；整批未保存，请核对当前指派状态后重试`)}finally{setBatchAssignSaving(false)}
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
    setAssigneeId(finding.assigneeId??'');
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
    setSaving(true);try{const item=await updateFinding(id,newStatus,acceptance);setFindings(prev=>prev.map(f=>f.id===id?item:f));setGroupFindings(prev=>prev.map(f=>f.id===id?item:f));setFindingRevision(n=>n+1);setEventRevision(n=>n+1);message.success('状态已保存并记录审计');}catch(e){message.error(String(e));}finally{setSaving(false)}
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
          pagination={{current:findingPage,pageSize:findingPageSize,total:findingTotal,showSizeChanger:true,pageSizeOptions:[10,20,50,100],showTotal:total=>`共 ${total} 项`,onChange:(page,size)=>{if(size!==findingPageSize){setFindingPageSize(size);setFindingPage(1)}else setFindingPage(page)}}}
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
              <SeverityTag value={selectedFinding.severity} />
              <FindingStatusTag value={selectedFinding.status} />
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
                  style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', maxHeight: 240, overflowY: 'auto', padding: 12, background: token.colorFillQuaternary, border: `1px solid ${token.colorBorderSecondary}`, borderRadius: token.borderRadius }}>
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
              <Button loading={saving} disabled={!canWrite} onClick={()=>void handleUpdateStatus(selectedFinding.id,'OPEN')}>撤销接受风险</Button>
              </Space>}
              {canAcceptRisk(selectedFinding.status)&&<Space direction="vertical" style={{width:'100%'}}>
                <label htmlFor="accept-risk-reason">接受原因（最多 500 UTF-8 字节）</label>
                <Input.TextArea id="accept-risk-reason" value={acceptReason} onChange={e=>setAcceptReason(e.target.value)} autoSize={{minRows:2,maxRows:6}} disabled={saving||!canWrite} />
                <label htmlFor="accept-risk-until">到期时间（本地时间，未来 365 天内）</label>
                <Input id="accept-risk-until" type="datetime-local" value={acceptUntil} onChange={e=>setAcceptUntil(e.target.value)} disabled={saving||!canWrite} />
                <Button loading={saving} disabled={!canWrite} onClick={()=>{try{void handleUpdateStatus(selectedFinding.id,'ACCEPTED_RISK',acceptanceInput(acceptReason,acceptUntil))}catch(e){message.error(e instanceof Error?e.message:'接受风险输入无效')}}}>接受风险</Button>
              </Space>}
              {selectedFinding.status==='FIXED'&&<Text type="secondary">修复状态由完整扫描判定。</Text>}
            </section>
            <section style={{width:'100%'}}>
              <Typography.Title level={5}>漏洞指派与备注</Typography.Title>
              <Space direction="vertical" style={{width:'100%'}}>
                <Text>当前处置人：{selectedFinding.assigneeName||selectedFinding.assigneeId||'未指派'}</Text>
                {workError&&<Alert type="error" message={workError} />}
                <label htmlFor="finding-assignee">处置人（可清除指派）</label>
                <Select id="finding-assignee" aria-label="漏洞处置人" allowClear style={{width:'100%'}} value={assigneeId||undefined} onChange={value=>setAssigneeId(value??'')} options={assignees.map(item=>({value:item.id,label:item.name}))} disabled={workSaving||!canWrite||Boolean(workError)} placeholder="未指派" />
                <Button loading={workSaving} disabled={!canWrite||Boolean(workError)||assigneeId===(selectedFinding.assigneeId??'')} onClick={()=>void saveAssignment(selectedFinding.id)}>保存指派</Button>
                {assignmentEvents.length?<Timeline items={assignmentEvents.map(event=>({key:event.id,children:<Space direction="vertical" size={2}><Text>指派：{event.fromAssigneeId||'未指派'} → {event.toAssigneeId||'未指派'}</Text><Text type="secondary">{event.createdAt} · 操作者 {event.actor}</Text></Space>}))}/>:<Text type="secondary">暂无指派历史</Text>}
                <label htmlFor="finding-note">追加备注（最多 2000 UTF-8 字节，单行纯文本）</label>
                <Input id="finding-note" value={noteBody} onChange={event=>setNoteBody(event.target.value)} disabled={workSaving||!canWrite} />
                <Button loading={workSaving} disabled={!canWrite||!noteBody.trim()} onClick={()=>void saveNote(selectedFinding.id)}>追加备注</Button>
                {notes.length?<Timeline items={notes.map(note=>({key:note.id,children:<Space direction="vertical" size={2}><Text type="secondary">{note.createdAt} · {note.actorName||note.actor}</Text><Text style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{note.body}</Text></Space>}))}/>:<Text type="secondary">暂无备注</Text>}
              </Space>
            </section>
            <section style={{width:'100%'}}>
              <Typography.Title level={5}>漏洞复测</Typography.Title>
              {retestError&&<Alert type="error" message={retestError} />}
              <Space direction="vertical" style={{width:'100%'}}>
                <Text type="secondary">复测只复用原任务冻结的目标、端口策略和授权，不会接受新的扫描目标。</Text>
                <Button type="primary" loading={retestSaving} disabled={!canWrite||selectedFinding.synthetic===true||selectedFinding.status==='FALSE_POSITIVE'||retests.some(retestIsActive)} onClick={()=>void startRetest(selectedFinding.id)}>重新扫描该漏洞</Button>
                {retests.length?<Timeline items={retests.map(item=>({key:item.id,children:<Space direction="vertical" size={2}><Text>{retestStatusLabel(item.status)} · 任务 {item.taskId}</Text><Text type="secondary">{item.createdAt} · {item.actor}</Text></Space>}))}/>:<Text type="secondary">暂无复测记录</Text>}
              </Space>
            </section>
            <section style={{width:'100%'}}>
              <Typography.Title level={5}>状态变更记录</Typography.Title>
              {eventsError&&<Alert type="error" message={eventsError} />}
              {events.length?<Timeline items={events.map(event=>({key:event.id,children:<Space direction="vertical" size={2}><Text>{event.fromStatus} → {event.toStatus}</Text><Text type="secondary">{event.createdAt} · {event.actor}</Text>{event.reason&&<Text style={{whiteSpace:'pre-wrap',overflowWrap:'anywhere'}}>{event.reason}</Text>}</Space>}))}/>:<Text type="secondary">暂无状态变更记录</Text>}
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
