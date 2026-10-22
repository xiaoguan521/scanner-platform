import { AssetImport } from './AssetImport';
import React, { useEffect, useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Tag, Typography, Drawer, Descriptions, Checkbox, Row, Col } from 'antd';
import type { FormInstance } from 'antd';
import { DownloadOutlined, PlusOutlined } from '@ant-design/icons';
import type { Asset, AssetProfile, Finding } from '../../types';
import { apiClient } from '../../api/client';
import type { AssetInsight } from '../../api/client';
import { pollIntervals, pollWhileVisible } from '../../api/polling';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { TitleWithHelp } from '../../components/HelpTip';
import { Link } from 'react-router-dom';
import { useAuth } from '../../auth/AuthProvider';
import { FindingStatusTag, Mono, SeverityTag, StatCard, StatusPill, TaskStatusTag } from '../../components/Semantic';
import { AutoGrid, PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { Tone } from '../../theme/palette';

import { compressPorts, summarizePorts, expandPortRanges } from '../Tasks/policy';
const { Text } = Typography;
type AssetForm = AssetProfile & {kind:'host'|'image_repo';address:string;businessGroup:string;owner:string;requestedPorts?:string;skippedPorts?:string};
type CandidateRow = {port:number;status:string;requestable:boolean};
function parsePorts(text?: string): number[] {
  if (!text?.trim()) return [];
  const tokens = text.split(',').map(v => v.trim());
  if (tokens.length > 50 || tokens.some(v => !/^[0-9]{1,5}$/.test(v))) throw new Error('端口请用英文逗号分隔，最多 50 个');
  const ports = tokens.map(Number);
  if (ports.some(v => v < 1 || v > 65535) || new Set(ports).size !== ports.length) {
    throw new Error('端口范围必须为 1–65535，不能重复');
  }
  return ports;
}
const profileFields: {key:keyof AssetProfile;label:string}[]=[{key:'name',label:'资产名称'},{key:'department',label:'所属部门'},{key:'phone',label:'联系电话'},{key:'mac',label:'MAC 地址'},{key:'osName',label:'操作系统名称'},{key:'osFamily',label:'操作系统族'},{key:'deviceType',label:'设备类型'},{key:'deviceSubtype',label:'设备小类'},{key:'vendor',label:'厂商'},{key:'model',label:'型号'}];
const ProfileFields:React.FC=()=> <><Row gutter={12}>{profileFields.map(f=><Col span={12} key={f.key}><Form.Item name={f.key} label={f.label}><Input maxLength={160}/></Form.Item></Col>)}</Row><Form.Item name="isCore" valuePropName="checked"><Checkbox>核心资产</Checkbox></Form.Item></>;
const profileInput=(input:AssetProfile):AssetProfile=>Object.fromEntries([...profileFields.map(f=>[f.key,input[f.key]??'']),['isCore',Boolean(input.isCore)]]);
const boolLabel=(v:boolean|null|undefined)=>v===true?'是':v===false?'否':'未知';
export const AssetsPage: React.FC = () => {
  const {user} = useAuth();
  const {palette} = useAppTheme();
  const canEdit = user?.role === 'admin' || user?.role === 'security_engineer';
  const [filter,setFilter] = useState('');
  const [assetPage,setAssetPage] = useState(1);
  const [assetPageSize,setAssetPageSize] = useState(10);
  const [assetTotal,setAssetTotal] = useState(0);
  const [assets,setAssets] = useState<Asset[]>([]);
  const [assetLoading,setAssetLoading] = useState(true);
  const [assetError,setAssetError] = useState<string|null>(null);
  const [assetRevision,setAssetRevision] = useState(0);
  const {data:quarantines,setData:setQuarantines} = useCollection('port-quarantines');
  const [detailId,setDetailId]=useState('');const detailAsset=assets.find(a=>a.id===detailId);
  const [releaseTarget,setReleaseTarget]=useState<{assetId:string;port:number}|null>(null);const [releaseReason,setReleaseReason]=useState('');
  const [createOpen,setCreateOpen] = useState(false);
  const [editing,setEditing] = useState<Asset|null>(null);
  const [candidateAsset,setCandidateAsset] = useState<Asset|null>(null);
  const [selectedCandidatePorts,setSelectedCandidatePorts] = useState<React.Key[]>([]);
  const [candidateFilter,setCandidateFilter] = useState('');
  const [saving,setSaving] = useState(false);
  const [requestingCandidates,setRequestingCandidates] = useState(false);
  const [checkingAsset,setCheckingAsset] = useState('');
  const [exporting,setExporting] = useState(false);
  const [createForm] = Form.useForm<AssetForm>();
  const [editForm] = Form.useForm<AssetForm>();
  const createKind = Form.useWatch('kind',createForm) ?? 'host';
  const [testingForm,setTestingForm] = useState<'create'|'edit'|''>('');
  useEffect(()=>{
    const controller=new AbortController();
    setAssetLoading(true);
    void apiClient.assetsPage(assetPage,assetPageSize,filter,'-created_at',controller.signal).then(result=>{
      if(controller.signal.aborted)return;
      setAssets(result.items);setAssetTotal(result.total);setAssetError(null);
    }).catch(cause=>{
      if(!controller.signal.aborted){setAssets([]);setAssetTotal(0);setAssetError(cause instanceof Error?cause.message:'资产清册加载失败');}
    }).finally(()=>{if(!controller.signal.aborted)setAssetLoading(false)});
    return()=>controller.abort();
  },[assetPage,assetPageSize,filter,assetRevision]);
  useEffect(()=>{if(assetPage!==1)setAssetPage(1)},[filter]);
  // Per-asset scan and finding summaries come from the Server for the current page only.
  const [insights,setInsights] = useState<Map<string,AssetInsight>>(new Map());
  const [insightLoading,setInsightLoading] = useState(false);
  const [insightError,setInsightError] = useState<string|null>(null);
  const assetIds = assets.map(asset=>asset.id).join(',');
  useEffect(()=>{
    if(!assetIds){setInsights(new Map());setInsightError(null);return;}
    const controller=new AbortController();let inFlight=false;
    const load=(initial=false)=>{
      if(inFlight)return;
      inFlight=true;if(initial)setInsightLoading(true);
      apiClient.assetInsights(assetIds.split(','),controller.signal).then(result=>{
        if(!controller.signal.aborted){setInsights(new Map(result.items.map(item=>[item.assetId,item])));setInsightError(null);}
      }).catch(cause=>{if(!controller.signal.aborted)setInsightError(cause instanceof Error?cause.message:'资产扫描摘要加载失败');}).finally(()=>{inFlight=false;if(!controller.signal.aborted)setInsightLoading(false);});
    };
    load(true);const stop=pollWhileVisible(()=>load(),pollIntervals.assetInsights);
    return()=>{controller.abort();stop();};
  },[assetIds]);
  const detailInsight = detailAsset?insights.get(detailAsset.id):undefined;
  const rows = assets;
  const checkReachability = async(asset:Asset) => {
    if(asset.kind!=='host')return;
    setCheckingAsset(asset.id);
    try {
      const result=await apiClient.checkAssetReachability(asset.id);
      setAssets(prev=>prev.map(item=>item.id===asset.id?{...item,reachabilityStatus:result.status,reachabilityCheckedAt:result.checkedAt}:item));
      message[result.status==='REACHABLE'?'success':'warning'](result.status==='REACHABLE'?'收到目标 Ping 响应':'未收到 Ping 响应；目标可能屏蔽 ICMP');
    } catch(cause) {
      message.error(cause instanceof Error?cause.message:'可达性检测失败');
    } finally {setCheckingAsset('');}
  };
  const testFormAddress = async(form:FormInstance<AssetForm>,kind:AssetForm['kind'],source:'create'|'edit') => {
    const address=String(form.getFieldValue('address')??'').trim();
    if(!address){message.warning('请先填写资产地址');return;}
    if(kind!=='host'){message.info('镜像仓库不支持 ICMP Ping');return;}
    setTestingForm(source);
    try {
      const result=await apiClient.testAssetAddress(address);
      const text=result.status==='REACHABLE'?'收到目标 Ping 响应':result.status==='NO_RESPONSE'?'未收到 Ping 响应；目标可能屏蔽 ICMP':'Ping 检测不可用';
      message[result.status==='REACHABLE'?'success':'warning'](`${text}（${address}）`);
    } catch(cause) {message.error(cause instanceof Error?cause.message:'连通性测试失败');}
    finally {setTestingForm('');}
  };
  const deleteAsset = (asset:Asset) => Modal.confirm({
    title:'删除资产',
    content:`确定删除 ${asset.address}？仍有关联授权范围时，需要先撤销或删除授权。`,
    okText:'删除',okButtonProps:{danger:true},cancelText:'取消',
    onOk:async()=>{
      try {
        await apiClient.deleteAsset(asset.id);
        setAssetRevision(value=>value+1);
        if(candidateAsset?.id===asset.id)setCandidateAsset(null);
        message.success('资产已删除');
      } catch(cause) {message.error(cause instanceof Error?cause.message:'删除失败');throw cause;}
    },
  });
  const candidateRows = useMemo<CandidateRow[]>(()=>{
    if(!candidateAsset)return [];
    const probe=insights.get(candidateAsset.id)?.latestProbe;
    if(!probe||probe.status!=='COMPLETED')return [];
    const classifications=new Map((candidateAsset.ports??[]).map(item=>[item.port,item.kind]));
    const skippedPorts=new Set([...(candidateAsset.skippedPorts??[]),...(candidateAsset.quarantinedPorts??[])]);
    const requestedPorts=new Set(candidateAsset.requestedPorts??[]);
    return [...new Set(probe.openPorts)].sort((a,b)=>a-b).map(port=>{
      const classification=classifications.get(port);
      const skipped=skippedPorts.has(port)||classification==='EXCLUDED_PROXY';
      const requested=requestedPorts.has(port);
      const requestable=!skipped&&!requested&&!classification;
      const status=skipped?'已跳过 / 隔离':classification==='WEB'?'已审批 · Web':classification==='NON_WEB'?'已审批 · 非 Web':requested?'已提交申请':'待申请';
      return {port,status,requestable};
    });
  },[candidateAsset,insights]);
  const filteredCandidateRows = useMemo(()=>candidateRows.filter(row=>!candidateFilter||String(row.port).includes(candidateFilter.trim())),[candidateRows,candidateFilter]);
  const exportAssets = async() => {
    setExporting(true);
    try {
      const blob=await apiClient.exportAssets(filter);
      const url=URL.createObjectURL(blob);
      const link=document.createElement('a');
      link.href=url;
      link.download=`assets-${new Date().toISOString().slice(0,10)}.csv`;
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(()=>URL.revokeObjectURL(url),0);
      message.success(filter.trim()?'已导出当前筛选资产':'已导出资产清单');
    } catch(cause) {message.error(cause instanceof Error?cause.message:'资产导出失败');}
    finally {setExporting(false);}
  };

  const create = async (input: AssetForm) => {
    setSaving(true);
    try {
      const requestedPorts=parsePorts(input.requestedPorts);
      const skippedPorts=expandPortRanges(input.skippedPorts);
      const asset=await apiClient.createAsset({...input,requestedPorts,skippedPorts});
      message.success('资产与明确输入的端口已保存；跳过端口不会下发给 Worker');
      setAssetRevision(value=>value+1);setCreateOpen(false);createForm.resetFields();
      if(asset.kind==='host') void checkReachability(asset);
    } catch(e) {message.error(e instanceof Error?e.message:'登记失败');}
    finally {setSaving(false);}
  };
  const update = async (input: AssetForm) => {
    if (!editing) return;
    setSaving(true);
    try {
      const address=input.address!.trim();
      const addressChanged=address!==editing.address;
      const patch={...profileInput(input),address,businessGroup:input.businessGroup!,owner:input.owner!,requestedPorts:parsePorts(input.requestedPorts),skippedPorts:expandPortRanges(input.skippedPorts)};
      const result=await apiClient.updateAsset(editing.id,patch);
      setAssets(prev=>prev.map(a=>a.id===editing.id?result:a));
      setEditing(null);
      message.success(addressChanged?'资产 IP 已更新；旧授权已撤销，需重新申请审批':'资产信息已保存；原有端口审批已重置');
      if(addressChanged&&result.kind==='host') void checkReachability(result);
    }catch(e){message.error(e instanceof Error?e.message:'更新失败');}
    finally{setSaving(false);}
  };
  const releaseQuarantine=async()=>{
    if(!releaseTarget||!releaseReason.trim())return;
    setSaving(true);
    try {
      await apiClient.releaseQuarantine(releaseTarget.assetId,releaseTarget.port,releaseReason.trim());
      setQuarantines(prev=>prev.map(q=>q.assetId===releaseTarget.assetId&&q.port===releaseTarget.port?{...q,status:'RELEASED'}:q));
      setAssets(prev=>prev.map(a=>a.id===releaseTarget.assetId?{...a,quarantinedPorts:a.quarantinedPorts?.filter(p=>p!==releaseTarget.port),services:a.services?.map(s=>s.port===releaseTarget.port?{...s,quarantined:false}:s)}:a));
      setReleaseTarget(null);setReleaseReason('');message.success('隔离已解除并记录审计；排除和扫描授权仍独立生效');
    }catch(e){message.error(e instanceof Error?e.message:'解除失败');}finally{setSaving(false);}
  };
  const requestSelectedCandidates = async() => {
    if(!candidateAsset)return;
    const selected=new Set(selectedCandidatePorts.map(Number));
    const ports=candidateRows.filter(row=>row.requestable&&selected.has(row.port)).map(row=>row.port);
    if(ports.length===0){message.info('请选择待申请的开放端口');return;}
    setRequestingCandidates(true);
    try {
      await apiClient.requestAssetPorts(candidateAsset.id,ports);
      const requestedPorts=[...new Set([...(candidateAsset.requestedPorts??[]),...ports])].sort((a,b)=>a-b);
      setAssets(prev=>prev.map(item=>item.id===candidateAsset.id?{...item,requestedPorts}:item));
      setCandidateAsset({...candidateAsset,requestedPorts});
      setSelectedCandidatePorts([]);
      message.success(`已提交 ${ports.length} 个端口申请，请到“授权与时间窗”由运维审批`);
    } catch(cause) {message.error(cause instanceof Error?cause.message:'端口申请失败');}
    finally {setRequestingCandidates(false);}
  };

  const reachability = (asset: Asset): { tone: Tone; label: string } => {
    if (asset.kind !== 'host') return { tone: 'neutral', label: '主机地址适用' };
    const status = checkingAsset === asset.id ? 'CHECKING' : asset.reachabilityStatus ?? 'UNCHECKED';
    return ({ UNCHECKED: { tone: 'neutral', label: '未检测' }, CHECKING: { tone: 'running', label: '检测中' }, REACHABLE: { tone: 'ok', label: 'Ping 可达' }, NO_RESPONSE: { tone: 'warning', label: '未收到响应' }, CHECK_FAILED: { tone: 'neutral', label: '检测不可用' } } as Record<string, { tone: Tone; label: string }>)[status] ?? { tone: 'neutral', label: status };
  };
  const portCounts = (asset: Asset) => {
    const counts = { WEB: 0, NON_WEB: 0, EXCLUDED_PROXY: 0 };
    for (const port of asset.ports ?? []) if (port.kind in counts) counts[port.kind as keyof typeof counts]++;
    return counts;
  };
  const openEdit = (asset: Asset) => {
    editForm.setFieldsValue({ ...profileInput(asset), address: asset.address, businessGroup: asset.businessGroup, owner: asset.owner, requestedPorts: asset.requestedPorts?.join(', ') ?? '', skippedPorts: compressPorts(asset.skippedPorts) });
    setEditing(asset);
  };
  const muted = { color: palette.textSecondary };
  const small = { fontSize: 12, ...muted };
  const activeQuarantines = quarantines.filter(q => q.status === 'ACTIVE');
  const pageRisky = rows.filter(asset => (insights.get(asset.id)?.activeFindingCount ?? 0) > 0).length;
  const detailReach = detailAsset ? reachability(detailAsset) : null;
  const detailProbe = detailInsight?.latestProbe;
  const detailLatest = detailInsight?.recentTasks[0];

  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <PageHeader
      title="资产列表"
      description={`共 ${assetTotal.toLocaleString()} 个已登记资产${rows.length ? ` · 本页 ${pageRisky} 个有活动漏洞` : ''} · 只对登记并授权的资产执行检查`}
      extra={<>
        <Button icon={<DownloadOutlined/>} loading={exporting} onClick={()=>void exportAssets()}>导出 CSV</Button>
        <AssetImport disabled={!canEdit} onImported={async()=>{setAssetRevision(value=>value+1)}}/>
        <Button type="primary" icon={<PlusOutlined/>} disabled={!canEdit} onClick={()=>setCreateOpen(true)}>登记资产</Button>
      </>}
    />
    <CollectionNotice loading={assetLoading&&rows.length===0} error={assetError}/>

    {activeQuarantines.length > 0 && <Panel flush title={<span style={{ display: 'flex', alignItems: 'center', gap: 8 }}>疑似四层转发隔离区 <StatusPill tone="warning">{activeQuarantines.length} 个端口</StatusPill></span>} extra={<span style={small}>隔离端口在探测和扫描时始终跳过</span>}>
      <DataTable rowKey={q=>q.assetId+'-'+q.port} dataSource={activeQuarantines} size="small" pagination={false}
        columns={[
          {title:'地址',dataIndex:'address',render:(value:string)=><Mono>{value}</Mono>},{title:'端口',dataIndex:'port',width:100,render:(value:number)=><Mono>{value}</Mono>},{title:'原因',dataIndex:'reason'},
          {title:'操作',width:120,render:(_:unknown,q:typeof quarantines[number])=><Button type="link" size="small" disabled={user?.role!=='admin'}
            onClick={()=>{setReleaseTarget({assetId:q.assetId,port:q.port});setReleaseReason('');}}>人工解除</Button>}
        ]}/>
    </Panel>}

    <Panel flush title={<TitleWithHelp title="资产登记台账" helpTitle="端口探测只针对已登记的单台主机" help="在任务中心可选择常用 TCP 端口或输入范围（支持 1-65535），也可填写排除端口。资产中已标记跳过或隔离的端口会自动排除。开放端口只作候选；提交申请并经运维审批后，才会出现在漏洞扫描目标中。"/>}
      extra={<Input.Search aria-label="资产搜索" placeholder="搜索地址、名称、业务组或负责人" allowClear value={filter} onChange={e=>setFilter(e.target.value)} style={{width:280}}/>}>
      <DataTable<Asset> rowKey="id" dataSource={rows} loading={assetLoading||insightLoading} tableLayout="fixed" scroll={{x:990}} pagination={{current:assetPage,pageSize:assetPageSize,total:assetTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 个资产`,onChange:(page,size)=>{if(size!==assetPageSize){setAssetPageSize(size);setAssetPage(1)}else setAssetPage(page)}}}
        columns={[
          {title:'资产',key:'address',width:190,render:(_:unknown,asset:Asset)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}>
            <Button type="link" style={{padding:0,height:'auto',textAlign:'left',alignSelf:'flex-start'}} aria-label={`查看资产画像：${asset.address}`} onClick={()=>setDetailId(asset.id)}><Mono>{asset.address}</Mono></Button>
            <span style={{...small,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{asset.name||'未命名'} · {asset.kind==='host'?'主机':'镜像仓库'}{asset.isCore?' · 核心资产':''}</span>
          </div>},
          {title:'归属',key:'owner',width:130,render:(_:unknown,asset:Asset)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><span style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>{asset.businessGroup}</span><span style={small}>{asset.owner}</span></div>},
          {title:'端口',key:'ports',width:150,render:(_:unknown,asset:Asset)=>{
            const counts=portCounts(asset);
            return <div style={{display:'flex',flexWrap:'wrap',gap:4}}>
              {counts.WEB>0&&<StatusPill tone="ok">Web {counts.WEB}</StatusPill>}
              {counts.NON_WEB>0&&<StatusPill tone="neutral">非 Web {counts.NON_WEB}</StatusPill>}
              {counts.EXCLUDED_PROXY>0&&<StatusPill tone="warning">跳过 {counts.EXCLUDED_PROXY}</StatusPill>}
              {asset.requestedPorts?.length?<StatusPill tone="running">待审 {asset.requestedPorts.length}</StatusPill>:null}
              {!asset.ports?.length&&!asset.requestedPorts?.length&&<span style={small}>暂无登记端口</span>}
            </div>;
          }},
          {title:'最近扫描',key:'scan',width:200,render:(_:unknown,asset:Asset)=>{
            if(insightError)return <Text type="secondary">未知</Text>;
            const insight=insights.get(asset.id);
            const latest=insight?.recentTasks[0];
            const probe=insight?.latestProbe;
            if(!latest&&!probe)return <span style={small}>尚未扫描</span>;
            const candidates=probe?.status==='COMPLETED'?probe.openPorts.length:0;
            return <div style={{display:'flex',flexDirection:'column',gap:4,alignItems:'flex-start'}}>
              {latest&&<span style={{display:'flex',alignItems:'center',gap:6}}><TaskStatusTag value={latest.status}/><span style={small}>{new Date(latest.finishedAt??latest.createdAt).toLocaleString()}</span></span>}
              {probe&&probe.status!=='COMPLETED'&&!latest&&<TaskStatusTag value={probe.status}/>}
              {candidates>0&&<Button type="link" size="small" style={{padding:0,height:'auto'}} onClick={()=>{setCandidateAsset(asset);setCandidateFilter('');setSelectedCandidatePorts([]);}}>{candidates} 个开放候选 · 查看与批量申请</Button>}
            </div>;
          }},
          {title:'当前风险数',key:'risk',width:96,render:(_:unknown,asset:Asset)=>{
            if(insightError)return <Text type="secondary">未知</Text>;
            const count=insights.get(asset.id)?.activeFindingCount??0;
            return count?<Link to={`/findings?assetId=${encodeURIComponent(asset.id)}`} aria-label={`${asset.address} 活动漏洞 ${count} 项`}><Mono style={{fontSize:16,fontWeight:600,color:palette.severity.HIGH.fg}}>{count.toLocaleString()}</Mono></Link>:<Mono style={{color:palette.success}}>0</Mono>;
          }},
          {title:<TitleWithHelp title="可达性" helpTitle="资产可达性（ICMP）" help="新增或编辑表单可测试当前填写的数字 IP，不保存测试结果。平台启动后立即探测清册中的主机，此后每轮完成后间隔 60 秒继续；无响应不等于主机离线，也不会跳过 TCP 探测。"/>,key:'reach',width:120,render:(_:unknown,asset:Asset)=>{
            const reach=reachability(asset);
            return <div style={{display:'flex',flexDirection:'column',gap:2,alignItems:'flex-start'}}><StatusPill tone={reach.tone}>{reach.label}</StatusPill>{asset.reachabilityCheckedAt&&<span style={small}>{new Date(asset.reachabilityCheckedAt).toLocaleString()}</span>}</div>;
          }},
          {title:'操作',key:'actions',width:110,fixed:'right',render:(_:unknown,asset:Asset)=><Space size={0}>
            <Button type="link" size="small" disabled={!canEdit} onClick={()=>openEdit(asset)}>编辑</Button>
            <Button type="link" size="small" danger disabled={!canEdit} onClick={()=>deleteAsset(asset)}>删除</Button>
          </Space>}
        ]}/>
    </Panel>

    <Drawer title={`资产画像 · ${detailAsset?.name||detailAsset?.address||''}`} open={!!detailAsset} onClose={()=>setDetailId('')} width="min(1040px, 100vw)">
      {detailAsset&&<div style={{display:'flex',flexDirection:'column',gap:16}}>
        {insightError&&<Alert type="warning" showIcon message="漏洞摘要和扫描历史暂时不可用" description="请刷新资产页后重试；资产登记和端口授权仍可查看。"/>}
        <div style={{display:'flex',flexWrap:'wrap',alignItems:'center',justifyContent:'space-between',gap:12}}>
          <div style={{display:'flex',flexDirection:'column',gap:4}}>
            <span style={{display:'flex',flexWrap:'wrap',alignItems:'center',gap:8,fontSize:18,fontWeight:600,color:palette.text}}><Mono>{detailAsset.address}</Mono>{detailAsset.isCore&&<StatusPill tone="warning">核心资产</StatusPill>}</span>
            <span style={small}>{detailAsset.name||'未命名'} · {detailAsset.kind==='host'?'主机':'镜像仓库'} · {detailAsset.businessGroup} · {detailAsset.owner} · 登记于 {new Date(detailAsset.createdAt).toLocaleDateString()}</span>
          </div>
          <Space wrap>
            {detailAsset.kind==='host'&&<Button loading={checkingAsset===detailAsset.id} onClick={()=>void checkReachability(detailAsset)}>检测可达性</Button>}
            <Button disabled={!canEdit} onClick={()=>openEdit(detailAsset)}>编辑资产</Button>
            {(detailInsight?.activeFindingCount??0)>0&&<Link to={`/findings?assetId=${encodeURIComponent(detailAsset.id)}`}><Button type="primary">查看 {detailInsight?.activeFindingCount} 项活动漏洞</Button></Link>}
          </Space>
        </div>
        <AutoGrid min={180} gap={12}>
          <StatCard title="活动漏洞" value={insightError?'—':(detailInsight?.activeFindingCount??0).toLocaleString()} valueColor={(detailInsight?.activeFindingCount??0)>0?palette.severity.HIGH.fg:palette.success}/>
          <StatCard title="开放端口候选" value={detailProbe?.status==='COMPLETED'?detailProbe.openPorts.length:'—'} footer={detailProbe?.status==='COMPLETED'?(compressPorts(detailProbe.openPorts)||'无'):'尚未完成探测'}/>
          <StatCard title="最近扫描" value={detailLatest?<TaskStatusTag value={detailLatest.status}/>:'—'} footer={detailLatest?new Date(detailLatest.finishedAt??detailLatest.createdAt).toLocaleString():'尚未扫描'}/>
          <StatCard title="可达性" value={detailReach?<StatusPill tone={detailReach.tone}>{detailReach.label}</StatusPill>:'—'} footer={detailAsset.reachabilityCheckedAt?new Date(detailAsset.reachabilityCheckedAt).toLocaleString():'无响应不代表离线'}/>
        </AutoGrid>
        <Panel title="基本信息">
          <dl style={{margin:0,display:'grid',gridTemplateColumns:'repeat(auto-fit, minmax(260px, 1fr))',gap:'10px 24px',fontSize:13}}>
            {[...profileFields.map(f=>({key:f.key,label:f.label,value:String(detailAsset[f.key]||'未提供')})),{key:'core',label:'核心资产',value:boolLabel(detailAsset.isCore)},{key:'business',label:'业务组',value:detailAsset.businessGroup},{key:'owner',label:'责任人',value:detailAsset.owner}].map(item=><div key={item.key} style={{display:'grid',gridTemplateColumns:'96px minmax(0, 1fr)',gap:12}}><dt style={{color:palette.textTertiary}}>{item.label}</dt><dd style={{margin:0,color:palette.text,overflowWrap:'anywhere'}}>{item.value}</dd></div>)}
          </dl>
        </Panel>
        <Panel title="资产排除与隔离" extra={<Button size="small" disabled={!canEdit} onClick={()=>openEdit(detailAsset)}>编辑排除端口</Button>}>
          <div style={{display:'flex',flexDirection:'column',gap:8,fontSize:13}}>
            <span><span style={{color:palette.textTertiary}}>排除端口：</span><Mono>{summarizePorts(detailAsset.skippedPorts)}</Mono></span>
            <span><span style={{color:palette.textTertiary}}>隔离端口：</span><Mono>{summarizePorts(detailAsset.quarantinedPorts)}</Mono></span>
            <span style={small}>系统、资产与任务排除取并集；解除隔离不会撤销排除或授予漏洞扫描权限。</span>
          </div>
        </Panel>
        <Panel flush title="服务与技术栈"><DataTable dataSource={detailAsset.services??[]} rowKey={r=>`${r.port}-${r.protocol??'tcp'}`} size="small" scroll={{x:900}} pagination={(detailAsset.services?.length??0)>10?{pageSize:10}:false} locale={{emptyText:'尚未识别出服务'}} columns={[
          {title:'端口 / 协议',width:110,render:(_,r)=><Mono>{`${r.port} / ${r.protocol||'TCP'}`}</Mono>},{title:'服务 / 状态',width:170,render:(_,r)=><div style={{display:'flex',flexDirection:'column',gap:2,alignItems:'flex-start'}}><span>{r.serviceName||r.kind||'未知'} · {r.state||'未知'}</span>{r.excluded&&<StatusPill tone="warning">已排除</StatusPill>}{r.quarantined&&<StatusPill tone="error">已隔离</StatusPill>}</div>},
          {title:'软件 / 版本',width:160,render:(_,r)=>[r.software,r.version].filter(Boolean).join(' ')||'未识别'},
          {title:'技术栈',render:(_,r)=>[r.middleware,r.language,r.framework,r.database,r.application].filter(Boolean).join(' / ')||'未识别'},
          {title:'网站',width:220,render:(_,r)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><Mono style={{overflowWrap:'anywhere'}}>{r.url||'—'}</Mono><span style={small}>{r.title||'无标题'} · TLS {boolLabel(r.tls)}</span></div>},
          {title:'最近发现',width:160,dataIndex:'lastSeen',render:(v:string)=><span style={small}>{v?new Date(v).toLocaleString():'未知'}</span>},
        ]}/></Panel>
        <Panel flush title="SSH 运行态服务与容器" extra={<TitleWithHelp title={<span style={small}>采集范围</span>} helpTitle="SSH 只读采集范围" help="仅展示明确授权主机通过 SSH 只读采集到的服务单元、进程名和本机 Docker/Podman 容器名、镜像引用与运行状态，不包含 PID、命令行、参数、容器内容、卷或集群工作负载。"/>}><DataTable dataSource={detailAsset.runtimeServices??[]} rowKey={r=>`${r.manager}-${r.runtime??''}-${r.name}`} size="small" pagination={(detailAsset.runtimeServices?.length??0)>10?{pageSize:10}:false} locale={{emptyText:'本次 SSH 采集没有返回运行态服务或容器'}} columns={[
          {title:'名称',dataIndex:'name',width:240,render:(v:string)=><Mono>{v}</Mono>},{title:'管理方式',dataIndex:'manager',width:140,render:(v:string)=>v==='systemd'?'systemd':v==='init'?'init 脚本':v==='process'?'进程表':'容器运行时'},{title:'运行时 / 镜像',render:(_,r)=>r.manager==='container'?<Mono>{[r.runtime,r.image].filter(Boolean).join(' · ')||'未提供'}</Mono>:'—'},{title:'状态',dataIndex:'state',width:110,render:(v:string)=>v==='running'?<StatusPill tone="ok">运行中</StatusPill>:v==='stopped'?<StatusPill tone="warning">已停止</StatusPill>:<StatusPill tone="neutral">已安装</StatusPill>},
        ]}/></Panel>
        <Panel flush title={<TitleWithHelp title="登录入口（单独统计）" helpTitle="登录入口" help="发现登录入口不代表存在弱口令；平台不进行口令猜测。"/>}><DataTable dataSource={detailAsset.loginEntries??[]} rowKey={r=>`${r.type}-${r.port}-${r.url??r.name}`} size="small" scroll={{x:750}} pagination={false} locale={{emptyText:'未发现登录入口'}} columns={[
          {title:'名称 / 类型',render:(_,r)=>`${r.name} · ${r.type==='web'?'Web':'系统'}`},{title:'端口',dataIndex:'port',width:80,render:(v:number)=><Mono>{v}</Mono>}, {title:'URL',dataIndex:'url',render:(v:string)=>v?<Mono style={{overflowWrap:'anywhere'}}>{v}</Mono>:'—'},
          {title:'安全属性',width:150,render:(_,r)=><div style={{display:'flex',flexDirection:'column',fontSize:12}}><span>HTTPS：{boolLabel(r.https)}</span><span>验证码：{boolLabel(r.captcha)}</span><span>防爆破：{boolLabel(r.antiBruteForce)}</span></div>}, {title:'举证',dataIndex:'evidence'},
        ]}/></Panel>
        <Panel flush title="漏洞摘要" extra={detailInsight&&detailInsight.activeFindingCount>0&&<Link to={`/findings?assetId=${encodeURIComponent(detailAsset.id)}`}>{detailInsight.activeFindingCount>detailInsight.activeFindings.length?`共 ${detailInsight.activeFindingCount} 项，按严重度显示前 ${detailInsight.activeFindings.length} 项 · `:''}在漏洞页查看全部</Link>}><DataTable<AssetInsight['activeFindings'][number]> dataSource={detailInsight?.activeFindings??[]} rowKey="id" loading={insightLoading} locale={{emptyText:'当前没有活动漏洞记录'}} pagination={(detailInsight?.activeFindings.length??0)>10?{pageSize:10}:false} tableLayout="fixed" scroll={{x:800}} columns={[
          {title:'严重度',dataIndex:'severity',width:96,render:(value:string)=><SeverityTag value={value as Finding['severity']}/>},
          {title:'漏洞',key:'title',render:(_,item)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><Mono>{item.templateOrCve}</Mono><span style={{...small,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}} title={item.title}>{item.title}</span></div>},
          {title:'状态',dataIndex:'status',width:120,render:(value:string)=><FindingStatusTag value={value as Finding['status']}/>},
          {title:'最近发现',dataIndex:'lastSeen',width:170,render:(value:string)=><span style={small}>{new Date(value).toLocaleString()}</span>},
        ]}/></Panel>
        <Panel flush title="扫描历史"><DataTable<AssetInsight['recentTasks'][number]> dataSource={detailInsight?.recentTasks??[]} rowKey="id" loading={insightLoading} locale={{emptyText:'尚未发起扫描'}} pagination={{pageSize:5,hideOnSinglePage:true}} scroll={{x:800}} columns={[
          {title:'任务',dataIndex:'id',width:220,ellipsis:true,render:(value:string)=><Mono>{value}</Mono>},
          {title:'执行方式',render:(_,item)=>item.engines[0]==='auto'?'自动综合扫描':item.engines[0]==='trivy'?'离线输入扫描':item.engines.join(' / ')||'未知'},
          {title:'状态',dataIndex:'status',width:120,render:(value:string)=><TaskStatusTag value={value}/>},
          {title:'发现数',dataIndex:'findingCount',width:90,render:(value:number)=><Mono>{value}</Mono>},
          {title:'创建时间',dataIndex:'createdAt',width:170,render:(value:string)=><span style={small}>{new Date(value).toLocaleString()}</span>},
        ]}/></Panel>
      </div>}
    </Drawer>
    <Modal title="人工解除端口隔离" open={!!releaseTarget} onCancel={()=>setReleaseTarget(null)} onOk={()=>void releaseQuarantine()} confirmLoading={saving} okButtonProps={{disabled:!releaseReason.trim()}} okText="解除并记录审计">
      <Alert type="warning" showIcon message={`解除端口 ${releaseTarget?.port??''} 的疑似转发隔离前，请确认已人工核查服务与转发配置。`} style={{marginBottom:16}}/>
      <Input.TextArea aria-label="解除原因" value={releaseReason} onChange={e=>setReleaseReason(e.target.value)} maxLength={1000} rows={3} placeholder="必填：人工核查依据和解除原因"/>
    </Modal>
    <Modal title="登记新资产" open={createOpen} width={720}
      onCancel={()=>setCreateOpen(false)} onOk={()=>createForm.submit()} okButtonProps={{loading:saving||testingForm==='create'}}>
      <Form form={createForm} layout="vertical" onFinish={create} autoComplete="off">
        <Form.Item name="kind" label="资产类型" initialValue="host" rules={[{required:true}]}>
          <Select options={[{label:'主机（纯数字 IPv4/IPv6）',value:'host'},{label:'镜像仓库',value:'image_repo'}]}/>
        </Form.Item>
        <Form.Item name="address" label="资产地址" rules={[{required:true}]} extra="主机只接受数字 IP，不展开 CIDR 或域名；测试只检查当前输入，不会保存资产或测试状态。">
          <Input placeholder="例如 192.0.2.18" addonAfter={createKind==='host'&&<Button type="link" size="small" disabled={!canEdit} loading={testingForm==='create'} onClick={()=>void testFormAddress(createForm,createKind,'create')}>测试连接</Button>}/>
        </Form.Item>
        <ProfileFields/><Form.Item name="businessGroup" label="所属业务组" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="owner" label="责任人" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="requestedPorts" label="已知端口申请（可留空）" extra="仅填写已知端口，如 80,443；未知端口请留空，在任务中心探测后可从本页批量申请。填写此处不会直接授权扫描。">
          <Input placeholder="80, 443"/>
        </Form.Item>
        <Form.Item name="skippedPorts" label="资产排除端口" extra="支持端口或范围，英文逗号分隔，如 3306,9000-9100；被排除的端口不会发起连接"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={'编辑资产：'+(editing?.address??'')} open={!!editing} width={720}
      onCancel={()=>setEditing(null)} onOk={()=>editForm.submit()} okButtonProps={{loading:saving||testingForm==='edit'}}>
      <Alert type="warning" showIcon style={{marginBottom:16}} message="保存会重置已有端口审批；修改主机 IP 会撤销该资产的授权范围，并重新检查 Ping。" />
      <Form form={editForm} layout="vertical" onFinish={update}>
        <Form.Item name="address" label="资产地址" rules={[{required:true,message:'请输入资产地址'}]} extra={editing?.kind==='host'?'主机仅接受数字 IP，不支持 CIDR 或域名；修改后需重新申请授权。测试只检查当前输入，不保存测试状态。':'镜像仓库地址按仓库格式校验。'}><Input maxLength={255} addonAfter={editing?.kind==='host'&&<Button type="link" size="small" disabled={!canEdit} loading={testingForm==='edit'} onClick={()=>void testFormAddress(editForm,'host','edit')}>测试连接</Button>}/></Form.Item>
        <ProfileFields/><Form.Item name="businessGroup" label="业务组" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="owner" label="责任人" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="requestedPorts" label="拟申请端口" extra="只是申请记录，不是扫描授权"><Input/></Form.Item>
        <Form.Item name="skippedPorts" label="资产排除端口" extra="支持端口或范围，英文逗号分隔，如 3306,9000-9100；被排除的端口不会发起连接"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={`开放端口候选${candidateAsset?` · ${candidateAsset.address}`:''}`} open={!!candidateAsset} width={720}
      onCancel={()=>{setCandidateAsset(null);setSelectedCandidatePorts([]);setCandidateFilter('');}}
      footer={<Space style={{width:'100%',justifyContent:'space-between'}}><Text type="secondary">已选 {selectedCandidatePorts.length} 个 · 每次最多申请 1024 个</Text><Space><Button onClick={()=>{setCandidateAsset(null);setSelectedCandidatePorts([]);setCandidateFilter('');}}>关闭</Button><Button type="primary" disabled={!canEdit||selectedCandidatePorts.length===0} loading={requestingCandidates} onClick={()=>void requestSelectedCandidates()}>申请选中端口</Button></Space></Space>}>
      <Alert type="info" showIcon style={{marginBottom:12}} message={`本次探测发现 ${candidateRows.length} 个开放候选。开放结果只是候选；所选端口会逐个提交给运维审批。`} />
      <Input.Search allowClear placeholder="按端口号筛选" value={candidateFilter} onChange={event=>setCandidateFilter(event.target.value)} style={{marginBottom:12,maxWidth:280}}/>
      <DataTable<CandidateRow> rowKey="port" size="small" dataSource={filteredCandidateRows} pagination={{pageSize:25,showSizeChanger:true,pageSizeOptions:[25,50,100],showTotal:(total)=>`共 ${total} 个候选`}} scroll={{y:420}}
        rowSelection={{selectedRowKeys:selectedCandidatePorts,preserveSelectedRowKeys:true,getCheckboxProps:row=>({disabled:!row.requestable||!canEdit}),onChange:keys=>{
          if(keys.length>1024){message.warning('一次最多选择 1024 个端口申请');setSelectedCandidatePorts(keys.slice(0,1024));return;}
          setSelectedCandidatePorts(keys);
        }}}
        columns={[{title:'TCP 端口',dataIndex:'port',width:140,sorter:(a,b)=>a.port-b.port},{title:'状态',dataIndex:'status',render:(status:string,row:CandidateRow)=><Tag color={row.requestable?'blue':status.startsWith('已跳过')?'orange':'default'}>{status}</Tag>}]} />
    </Modal>
  </div>;
};
