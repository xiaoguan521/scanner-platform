import React, { useEffect, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Descriptions, Form, Input, List, message, Modal, Select, Space, Tabs, Tag, Typography } from 'antd';
import { apiClient } from '../../api/client';
import { CollectionNotice } from '../../api/CollectionNotice';
import { TitleWithHelp } from '../../components/HelpTip';
import { pollIntervals, pollWhileVisible } from '../../api/polling';
import { useAuth } from '../../auth/AuthProvider';
import { Mono, SeverityTag, StatCard, StatusPill, severityMeta } from '../../components/Semantic';
import { AutoGrid, PageHeader, Panel } from '../../components/Page';
import { useAppTheme } from '../../context/ThemeContext';
import type { Tone } from '../../theme/palette';
import { activateRules, createCustomRule, deleteCustomRule, fetchRules, importRules, updateCustomRule } from '../../api/runtime';
import type { CustomRule, NodeCredential, NodeInfo, NodeLifecycle, NodeLifecycleEvent, RuleBundle, RuleJob } from '../../types';

import { ScanPolicySettings } from './ScanPolicySettings';
type CustomRuleForm={id:string;name:string;severity:CustomRule['severity'];description:string;matchType:CustomRule['matchType'];path:string;part:'header'|'body';valuesText:string;statusCodesText:string;enabled:boolean};
type NodeRegistrationForm=Pick<NodeLifecycle,'id'|'kind'|'hostId'>;
const formatNodeTime=(value?:string)=>value?new Date(value).toLocaleString():'—';
const lifecycleStatusLabel=(value:NodeLifecycle['status'])=>({REGISTERED:'已登记',ONLINE:'在线',OFFLINE:'离线',REVOKED:'已吊销'}[value]);
const lifecycleEventLabel=(value:NodeLifecycleEvent['kind'])=>({REGISTERED:'登记',ONLINE:'上线',OFFLINE:'离线',RECOVERED:'恢复',REVOKED:'吊销'}[value]);

export const NodesPage:React.FC=()=>{
  const {palette}=useAppTheme();
  const {user}=useAuth();const canWrite=user?.role==='admin'||user?.role==='security_engineer';const canAdmin=user?.role==='admin';
  const [nodes,setNodes]=useState<NodeInfo[]>([]);const [nodePage,setNodePage]=useState(1);const [nodePageSize,setNodePageSize]=useState(10);const [nodeTotal,setNodeTotal]=useState(0);const [nodeSearch,setNodeSearch]=useState('');
  const [bundles,setBundles]=useState<RuleBundle[]>([]);const [rulePage,setRulePage]=useState(1);const [rulePageSize,setRulePageSize]=useState(10);const [ruleTotal,setRuleTotal]=useState(0);const [ruleSearch,setRuleSearch]=useState('');
  const [jobs,setJobs]=useState<RuleJob[]>([]);const [jobPage,setJobPage]=useState(1);const [jobPageSize,setJobPageSize]=useState(10);const [jobTotal,setJobTotal]=useState(0);const [jobSearch,setJobSearch]=useState('');const [jobStatus,setJobStatus]=useState('ALL');const [jobKind,setJobKind]=useState('ALL');
  const [customRules,setCustomRules]=useState<CustomRule[]>([]);const [customPage,setCustomPage]=useState(1);const [customPageSize,setCustomPageSize]=useState(10);const [customTotal,setCustomTotal]=useState(0);const [customSearch,setCustomSearch]=useState('');const [customSeverity,setCustomSeverity]=useState('ALL');const [customEnabled,setCustomEnabled]=useState('ALL');
  const [systemLoading,setSystemLoading]=useState(true);const [systemError,setSystemError]=useState<string|null>(null);
  const [file,setFile]=useState<File|null>(null);const [busy,setBusy]=useState(false);const [fetchOpen,setFetchOpen]=useState(false);const [form]=Form.useForm();
  const [ruleOpen,setRuleOpen]=useState(false);const [editingRule,setEditingRule]=useState<CustomRule|null>(null);const [ruleForm]=Form.useForm<CustomRuleForm>();
  const [nodeRegisterOpen,setNodeRegisterOpen]=useState(false);const [nodeDetailsOpen,setNodeDetailsOpen]=useState(false);const [nodeDetail,setNodeDetail]=useState<NodeLifecycle|null>(null);const [nodeEvents,setNodeEvents]=useState<NodeLifecycleEvent[]>([]);const [nodeDetailLoading,setNodeDetailLoading]=useState(false);const [nodeBusy,setNodeBusy]=useState(false);const [nodeCredential,setNodeCredential]=useState<NodeCredential|null>(null);const [nodeCredentialOpen,setNodeCredentialOpen]=useState(false);const [nodeForm]=Form.useForm<NodeRegistrationForm>();
  const ruleMatchType=Form.useWatch('matchType',ruleForm)??'word';
  useEffect(()=>{const controller=new AbortController();let inFlight=false;const load=(initial=false)=>{if(inFlight)return;inFlight=true;if(initial)setSystemLoading(true);Promise.all([apiClient.nodesPage<NodeInfo>(nodePage,nodePageSize,{search:nodeSearch},controller.signal),apiClient.rulesPage<RuleBundle>(rulePage,rulePageSize,{search:ruleSearch},controller.signal),apiClient.ruleJobsPage<RuleJob>(jobPage,jobPageSize,{search:jobSearch,status:jobStatus,kind:jobKind},controller.signal),apiClient.customRulesPage<CustomRule>(customPage,customPageSize,{search:customSearch,severity:customSeverity,enabled:customEnabled},controller.signal)]).then(([nextNodes,nextRules,nextJobs,nextCustomRules])=>{if(!controller.signal.aborted){setNodes(nextNodes.items);setNodeTotal(nextNodes.total);setBundles(nextRules.items);setRuleTotal(nextRules.total);setJobs(nextJobs.items);setJobTotal(nextJobs.total);setCustomRules(nextCustomRules.items);setCustomTotal(nextCustomRules.total);setSystemError(null);}}).catch(cause=>{if(!controller.signal.aborted)setSystemError(cause instanceof Error?cause.message:'系统清册服务不可用');}).finally(()=>{inFlight=false;if(!controller.signal.aborted)setSystemLoading(false);});};load(true);const stop=pollWhileVisible(()=>load(),pollIntervals.activeTask);return()=>{controller.abort();stop();};},[nodePage,nodePageSize,nodeSearch,rulePage,rulePageSize,ruleSearch,jobPage,jobPageSize,jobSearch,jobStatus,jobKind,customPage,customPageSize,customSearch,customSeverity,customEnabled]);
  useEffect(()=>{if(nodePage!==1)setNodePage(1);},[nodeSearch]);
  useEffect(()=>{if(rulePage!==1)setRulePage(1);},[ruleSearch]);
  useEffect(()=>{if(jobPage!==1)setJobPage(1);},[jobSearch,jobStatus,jobKind]);
  useEffect(()=>{if(customPage!==1)setCustomPage(1);},[customSearch,customSeverity,customEnabled]);
  const run=async(action:()=>Promise<unknown>)=>{setBusy(true);try{await action();message.success('操作已排队，等待本地 Updater 处理；请查看操作记录');return true;}catch(e){message.error(e instanceof Error?e.message:String(e));return false;}finally{setBusy(false);}};
  const showNodeLifecycle=async(id:string)=>{setNodeDetailsOpen(true);setNodeDetailLoading(true);try{const [detail,events]=await Promise.all([apiClient.nodeLifecycle(id),apiClient.nodeLifecycleEvents(id)]);setNodeDetail(detail);setNodeEvents(events.items);}catch(e){setNodeDetail(null);setNodeEvents([]);message.error(e instanceof Error?e.message:String(e));}finally{setNodeDetailLoading(false);}};
  const submitNodeRegistration=async(values:NodeRegistrationForm)=>{setNodeBusy(true);try{await apiClient.registerNode(values);message.success('节点已登记');setNodeRegisterOpen(false);nodeForm.resetFields();}catch(e){message.error(e instanceof Error?e.message:String(e));}finally{setNodeBusy(false);}};
  const issueNodeCredential=async(node:NodeInfo)=>{setNodeBusy(true);try{const credential=await apiClient.issueNodeCredential(node.id);setNodeCredential(credential);setNodeCredentialOpen(true);}catch(e){message.error(e instanceof Error?e.message:String(e));}finally{setNodeBusy(false);}};
  const confirmNodeCredentialRotation=(node:NodeInfo)=>Modal.confirm({title:`轮换节点“${node.id}”令牌？`,content:'旧令牌会立即失效，新的令牌只显示一次；请确认节点可以在本次操作后及时替换 owner-only 凭据文件。该操作会写入审计记录。',okText:'轮换',cancelText:'取消',onOk:async()=>{setNodeBusy(true);try{const credential=await apiClient.rotateNodeCredential(node.id);setNodeCredential(credential);setNodeCredentialOpen(true);message.success('节点令牌已轮换，旧令牌已失效');}catch(e){message.error(e instanceof Error?e.message:String(e));throw e;}finally{setNodeBusy(false);}}});
  const confirmNodeRevoke=(node:NodeInfo)=>Modal.confirm({title:`吊销节点“${node.id}”？`,content:'吊销后，启用节点令牌认证的 Worker/Updater 请求会被拒绝；该操作会写入审计记录。',okText:'吊销',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await apiClient.revokeNode(node.id);message.success('节点已吊销');if(nodeDetail?.id===node.id)await showNodeLifecycle(node.id);}catch(e){message.error(e instanceof Error?e.message:String(e));throw e;}}});
  const saveRule=async(values:CustomRuleForm)=>{setBusy(true);try{const input:Omit<CustomRule,'template'>={id:values.id.trim().toLowerCase(),name:values.name.trim(),severity:values.severity,description:values.description??'',path:(values.path??'').trim()||undefined,matchType:values.matchType,enabled:values.enabled??true,...(values.matchType==='status'?{statusCodes:values.statusCodesText.split(',').map(v=>Number(v.trim()))}:{part:values.part,values:values.valuesText.split('\n').map(v=>v.trim()).filter(Boolean)})};const saved=editingRule?await updateCustomRule(editingRule.id,input):await createCustomRule(input);setCustomRules(prev=>editingRule?prev.map(item=>item.id===saved.id?saved:item):[saved,...prev]);setCustomPage(1);message.success(editingRule?'自定义规则已更新':'自定义规则已创建');setRuleOpen(false);setEditingRule(null);ruleForm.resetFields();}catch(e){message.error(e instanceof Error?e.message:String(e));}finally{setBusy(false);}};
  const editRule=(rule:CustomRule)=>{setEditingRule(rule);ruleForm.setFieldsValue({id:rule.id,name:rule.name,severity:rule.severity,description:rule.description,path:rule.path??'',matchType:rule.matchType,part:rule.part??'body',valuesText:rule.values?.join('\n')??'',statusCodesText:rule.statusCodes?.join(', ')??'',enabled:rule.enabled});setRuleOpen(true);};
  const removeRule=(rule:CustomRule)=>Modal.confirm({title:'删除自定义规则',content:`删除“${rule.name}”后新建任务将不再使用它；已创建任务保留创建时的规则快照。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteCustomRule(rule.id);setCustomRules(prev=>prev.filter(item=>item.id!==rule.id));setCustomPage(1);message.success('自定义规则已删除');}catch(e){message.error(e instanceof Error?e.message:String(e));throw e;}}});
  const muted={color:palette.textSecondary};
  const small={fontSize:12,...muted};
  const nodeState=(node:NodeInfo):{tone:Tone;label:string}=>{
    if(node.lifecycleStatus==='REVOKED')return {tone:'error',label:'已吊销'};
    if(node.lifecycleStatus==='ONLINE'||node.status==='ONLINE')return {tone:'ok',label:'在线'};
    if(node.status==='BUSY')return {tone:'running',label:'处理中'};
    if(node.lifecycleStatus==='OFFLINE'||node.status==='OFFLINE')return {tone:'neutral',label:'离线'};
    if(node.lifecycleStatus==='REGISTERED')return {tone:'warning',label:'已登记'};
    return {tone:'neutral',label:'未知'};
  };
  const fenceState=(status?:string):{tone:Tone;label:string}=>status==='ACTIVE'||status==='ENFORCED'?{tone:'ok',label:'已启用'}:status==='NOT_VERIFIED'?{tone:'warning',label:'未验证'}:{tone:'neutral',label:'未启用'};
  const jobLabels:Record<string,string>={IMPORT:'离线导入',FETCH:'下载导入',ACTIVATE:'版本切换'};
  const jobStates:Record<string,{tone:Tone;label:string}>={PENDING:{tone:'neutral',label:'排队中'},RUNNING:{tone:'running',label:'执行中'},COMPLETED:{tone:'ok',label:'已完成'},FAILED:{tone:'error',label:'失败'}};
  const engines=nodes.flatMap(n=>(n.engines??[]).map(e=>({...e,nodeId:n.id,online:n.status!=='OFFLINE'})));
  const onlineNodes=nodes.filter(node=>nodeState(node).tone==='ok'||nodeState(node).tone==='running').length;
  const readyEngines=engines.filter(e=>e.online&&e.ready).length;
  const currentBundle=bundles.find(bundle=>bundle.isCurrent);

  const nodesTab=<div style={{display:'flex',flexDirection:'column',gap:16}}>
    <Panel flush title="节点心跳" extra={<Input aria-label="节点搜索" placeholder="搜索节点 ID、类型或主机 ID" allowClear value={nodeSearch} onChange={event=>setNodeSearch(event.target.value)} style={{width:240}}/>}>
      <DataTable<NodeInfo> dataSource={nodes} loading={systemLoading} rowKey="id" tableLayout="fixed" pagination={{current:nodePage,pageSize:nodePageSize,total:nodeTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 项`,onChange:(page,size)=>{if(size!==nodePageSize){setNodePageSize(size);setNodePage(1);}else setNodePage(page);}}} scroll={{x:980}} locale={{emptyText:'还没有节点上报心跳'}} columns={[
        {title:'节点',key:'id',width:200,render:(_,node)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><Mono style={{fontWeight:600}}>{node.id}</Mono><span style={small}>{node.kind==='worker'?'Worker':'Updater'} · 主机 {node.hostId}</span></div>},
        {title:'状态',key:'status',width:110,render:(_,node)=>{const state=nodeState(node);return <StatusPill tone={state.tone}>{state.label}</StatusPill>;}},
        {title:'当前任务',key:'task',width:200,render:(_,node)=>node.currentTask?<Mono style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',display:'block'}} title={node.currentTask}>{node.currentTask}</Mono>:<span style={small}>空闲</span>},
        {title:'最近心跳',key:'heartbeat',width:170,render:(_,node)=><span style={small}>{node.lifecycleStatus&&node.lifecycleStatus!=='ONLINE'?'—':formatNodeTime(node.lastHeartbeat)}</span>},
        {title:'网络围栏',key:'fence',width:150,render:(_,node)=>{const fence=fenceState(node.fenceStatus);return <div style={{display:'flex',flexDirection:'column',gap:2,alignItems:'flex-start'}}><StatusPill tone={node.dropCount?'warning':fence.tone}>{fence.label}</StatusPill>{node.dropCount?<span style={small}>拦截 {node.dropCount} 次</span>:null}</div>;}},
        {title:'生命周期',key:'lifecycle',render:(_,node)=><Space size={0} wrap>{node.lifecycleStatus&&<Button type="link" size="small" onClick={()=>void showNodeLifecycle(node.id)}>查看状态</Button>}{canAdmin&&node.lifecycleStatus&&node.lifecycleStatus!=='REVOKED'&&<><Button type="link" size="small" loading={nodeBusy} onClick={()=>void issueNodeCredential(node)}>签发令牌</Button><Button type="link" size="small" loading={nodeBusy} onClick={()=>confirmNodeCredentialRotation(node)}>轮换令牌</Button><Button type="link" size="small" danger onClick={()=>confirmNodeRevoke(node)}>吊销</Button></>}{!node.lifecycleStatus&&<span style={small}>未登记</span>}</Space>},
      ]}/>
    </Panel>
    <Panel flush title="扫描引擎"><DataTable dataSource={engines} rowKey={e=>e.nodeId+'-'+e.name} pagination={false} tableLayout="fixed" locale={{emptyText:'节点尚未上报引擎状态'}} columns={[
      {title:'引擎',dataIndex:'name',width:140,render:(v:string)=><span style={{fontWeight:600}}>{v.toUpperCase()}</span>},
      {title:'固定版本',dataIndex:'version',width:160,render:(v:string)=><Mono>{v||'—'}</Mono>},
      {title:'节点',dataIndex:'nodeId',width:180,render:(v:string)=><Mono>{v}</Mono>},
      {title:'状态',key:'state',width:170,render:(_,e)=><StatusPill tone={!e.online?'neutral':e.ready?'ok':e.installed?'warning':'error'}>{!e.online?'节点离线':e.ready?'本地就绪':e.installed?'缺少数据 / 运行环境':'未安装'}</StatusPill>},
      {title:'说明',dataIndex:'message',render:(v:string)=><span style={small}>{v||'—'}</span>},
    ]}/></Panel>
  </div>;

  const rulesTab=<div style={{display:'flex',flexDirection:'column',gap:16}}>
    <Panel flush title={<TitleWithHelp title="规则包版本" helpTitle="规则包验签与激活" help="只有 Updater 写入规则目录。外部规则包导入和激活需要受信任公钥验证签名，并检查文件 SHA-256；未验签的历史版本可查看，不能通过此页面激活。真实任务在执行前校验固定规则版本。"/>} extra={<Space wrap>
      <Input aria-label="规则包搜索" placeholder="搜索版本或渠道" allowClear value={ruleSearch} onChange={event=>setRuleSearch(event.target.value)} style={{width:180}}/>
      <input aria-label="选择离线规则包" type="file" accept=".zip" disabled={!canWrite} onChange={e=>setFile(e.target.files?.[0]??null)} style={{fontSize:12,color:palette.textSecondary,maxWidth:200}}/>
      <Button disabled={!canWrite||!file} loading={busy} onClick={()=>void run(()=>importRules(file!))}>离线导入 ZIP</Button>
      <Button disabled={!canWrite} onClick={()=>setFetchOpen(true)}>从规则源下载</Button>
    </Space>}>
      <div style={{padding:'0 20px 12px',...small}}>网页上传 ZIP 上限为 256 MiB，须包含 manifest.json、manifest.json.sig 和 nuclei/、trivy/ 下声明的规则文件。更大的漏洞库制品请在 Updater 所在机器运行 <Mono>sec-updater --import-bundle-file /路径/vulnerability-data.zip</Mono> 后重启 Updater，再在此处激活或显式回滚。</div>
      <DataTable<RuleBundle> dataSource={bundles} loading={systemLoading} rowKey="version" tableLayout="fixed" scroll={{x:1000}} pagination={{current:rulePage,pageSize:rulePageSize,total:ruleTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 项`,onChange:(page,size)=>{if(size!==rulePageSize){setRulePageSize(size);setRulePage(1);}else setRulePage(page);}}} locale={{emptyText:'还没有导入规则包'}} columns={[
        {title:'版本',key:'version',width:200,render:(_,b)=><span style={{display:'flex',flexWrap:'wrap',alignItems:'center',gap:6}}><Mono style={{fontWeight:600}}>{b.version}</Mono>{b.isCurrent&&<StatusPill tone="ok">当前版本</StatusPill>}</span>},
        {title:'引擎数据',key:'engines',width:130,render:(_,b)=>b.engines?.join('、')||'—'},
        {title:'校验',key:'checks',width:230,render:(_,b)=><div style={{display:'flex',flexWrap:'wrap',gap:4}}><StatusPill tone={b.integrityVerified?'ok':'neutral'}>哈希{b.integrityVerified?'已验证':'未验证'}</StatusPill><StatusPill tone={b.signatureVerified?'ok':'warning'}>签名{b.signatureVerified?'已验证':'未验证'}</StatusPill><StatusPill tone={b.engineValidated?'ok':'neutral'}>兼容性{b.engineValidated?'已验证':'未验证'}</StatusPill></div>},
        {title:'Manifest SHA-256',key:'sha',render:(_,b)=><Mono style={{overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap',display:'block',...small}} title={b.manifestSha256}>{b.manifestSha256}</Mono>},
        {title:'导入时间',key:'published',width:170,render:(_,b)=><span style={small}>{new Date(b.publishedAt).toLocaleString()}</span>},
        {title:'操作',key:'actions',width:150,render:(_,b)=><Space size={0}><Button type="link" size="small" disabled={!canWrite||b.isCurrent||!b.signatureVerified} loading={busy} onClick={()=>void run(()=>activateRules(b.version,false))}>激活</Button><Button type="link" size="small" danger disabled={!canWrite||b.isCurrent||!b.signatureVerified} onClick={()=>Modal.confirm({title:'显式回滚到 '+b.version+'？',content:'将切换本地规则指针并记录审计。当前不会启动扫描。',onOk:()=>run(()=>activateRules(b.version,true))})}>显式回滚</Button></Space>},
      ]}/>
    </Panel>
    <Panel flush title="规则操作记录" extra={<Space wrap><Input aria-label="规则操作记录搜索" placeholder="搜索记录 ID、类型、版本或说明" allowClear value={jobSearch} onChange={event=>setJobSearch(event.target.value)} style={{width:230}}/><Select aria-label="规则操作状态筛选" value={jobStatus} onChange={setJobStatus} style={{width:130}} options={[{value:'ALL',label:'全部状态'},...Object.entries(jobStates).map(([value,state])=>({value,label:state.label}))]}/><Select aria-label="规则操作类型筛选" value={jobKind} onChange={setJobKind} style={{width:130}} options={[{value:'ALL',label:'全部操作'},...Object.entries(jobLabels).map(([value,label])=>({value,label}))]}/></Space>}>
      <DataTable<RuleJob> dataSource={jobs} rowKey="id" loading={systemLoading} tableLayout="fixed" pagination={{current:jobPage,pageSize:jobPageSize,total:jobTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 项`,onChange:(page,size)=>{if(size!==jobPageSize){setJobPageSize(size);setJobPage(1);}else setJobPage(page);}}} scroll={{x:900}} locale={{emptyText:'暂无规则操作记录'}} columns={[
        {title:'操作',dataIndex:'kind',width:110,render:(v:string)=>jobLabels[v]??v},
        {title:'版本',dataIndex:'version',width:180,render:(v:string)=><Mono>{v||'—'}</Mono>},
        {title:'状态',dataIndex:'status',width:110,render:(v:string)=>{const state=jobStates[v]??{tone:'neutral' as Tone,label:v};return <StatusPill tone={state.tone}>{state.label}</StatusPill>;}},
        {title:'说明',dataIndex:'message',render:(v:string)=><span style={{overflowWrap:'anywhere'}}>{v}</span>},
        {title:'提交时间',dataIndex:'createdAt',width:170,render:(v:string)=><span style={small}>{new Date(v).toLocaleString()}</span>},
      ]}/>
    </Panel>
  </div>;

  const customTab=<Panel flush title={<TitleWithHelp title="自定义漏洞规则" helpTitle="安全规则格式受限" help="规则只对已授权的 HTTP(S) 地址发送一次同源只读 GET（可指定路径，默认根路径 /），并匹配响应状态、响应头或响应正文；不支持请求载荷、登录凭据、代码执行或其他协议。启用的规则会自动加入后续 Nuclei / 自动扫描任务。"/>} extra={<Space wrap><Input aria-label="自定义规则搜索" placeholder="搜索规则 ID、名称或说明" allowClear value={customSearch} onChange={event=>setCustomSearch(event.target.value)} style={{width:230}}/><Select aria-label="自定义规则等级筛选" value={customSeverity} onChange={setCustomSeverity} style={{width:120}} options={[{value:'ALL',label:'全部等级'},...['critical','high','medium','low','info'].map(value=>({value,label:severityMeta[value.toUpperCase() as keyof typeof severityMeta].label}))]}/><Select aria-label="自定义规则状态筛选" value={customEnabled} onChange={setCustomEnabled} style={{width:120}} options={[{value:'ALL',label:'全部状态'},{value:'true',label:'启用'},{value:'false',label:'停用'}]}/><Button type="primary" disabled={!canWrite} onClick={()=>{setEditingRule(null);ruleForm.resetFields();ruleForm.setFieldsValue({severity:'medium',matchType:'word',part:'body',enabled:true});setRuleOpen(true);}}>新增规则</Button></Space>}>
    <DataTable<CustomRule> dataSource={customRules} rowKey="id" loading={systemLoading} tableLayout="fixed" scroll={{x:960}} pagination={{current:customPage,pageSize:customPageSize,total:customTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 项`,onChange:(page,size)=>{if(size!==customPageSize){setCustomPageSize(size);setCustomPage(1);}else setCustomPage(page);}}} locale={{emptyText:'还没有自定义规则。可先添加一个只读响应特征规则。'}} columns={[
      {title:'规则',key:'rule',render:(_,r)=><div style={{display:'flex',flexDirection:'column',gap:2,minWidth:0}}><span style={{fontWeight:600}}>{r.name}</span><Mono style={small}>{r.id}</Mono>{r.description&&<span style={{...small,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}} title={r.description}>{r.description}</span>}</div>},
      {title:'等级',key:'severity',width:96,render:(_,r)=><SeverityTag value={r.severity.toUpperCase()}/>},
      {title:'检查路径',key:'path',width:150,render:(_,r)=><Mono>{r.path||'/'}</Mono>},
      {title:'匹配方式',key:'match',width:220,render:(_,r)=>r.matchType==='status'?`HTTP 状态 ${r.statusCodes?.join(', ')}`:`${r.part==='header'?'响应头':'响应正文'} · ${r.matchType==='regex'?'正则':'文本'} · ${r.values?.length??0} 条`},
      {title:'状态',key:'enabled',width:90,render:(_,r)=><StatusPill tone={r.enabled?'ok':'neutral'}>{r.enabled?'启用':'停用'}</StatusPill>},
      {title:'操作',key:'actions',width:120,render:(_,r)=><Space size={0}><Button type="link" size="small" disabled={!canWrite} onClick={()=>editRule(r)}>修改</Button><Button type="link" size="small" danger disabled={!canWrite} onClick={()=>removeRule(r)}>删除</Button></Space>},
    ]}/>
  </Panel>;

  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <PageHeader title="节点与规则库" description="扫描节点心跳、引擎状态、规则包版本和自定义规则"
      extra={<Button type="primary" disabled={!canAdmin} onClick={()=>{nodeForm.resetFields();nodeForm.setFieldsValue({kind:'worker'});setNodeRegisterOpen(true);}}>登记节点</Button>}/>
    <CollectionNotice loading={systemLoading&&nodes.length===0&&bundles.length===0} error={systemError}/>
    <AutoGrid min={200} gap={12}>
      <StatCard title="在线节点" value={onlineNodes} suffix={`/ ${nodeTotal}`} valueColor={onlineNodes?palette.success:palette.textTertiary}/>
      <StatCard title="引擎就绪" value={readyEngines} suffix={`/ ${engines.length}`} valueColor={engines.length&&readyEngines===engines.length?palette.success:readyEngines?palette.warning:palette.textTertiary}/>
      <StatCard title="当前规则版本" value={<Mono style={{fontSize:20}}>{currentBundle?.version??'—'}</Mono>} footer={currentBundle?(currentBundle.signatureVerified?'签名已验证':'签名未验证'):ruleTotal?'请在规则包中查看当前版本':'尚未导入规则包'}/>
      <StatCard title="自定义规则" value={customTotal} footer="当前筛选下的规则数"/>
    </AutoGrid>
    <Tabs items={[
      {key:'nodes',label:`节点与引擎（${nodeTotal}）`,children:nodesTab},
      {key:'rules',label:`规则包（${ruleTotal}）`,children:rulesTab},
      {key:'custom',label:`自定义规则（${customTotal}）`,children:customTab},
      {key:'policy',label:'扫描策略',children:<ScanPolicySettings/>},
    ]}/>
    <Modal title="登记节点" open={nodeRegisterOpen} onCancel={()=>{setNodeRegisterOpen(false);nodeForm.resetFields();}} onOk={()=>nodeForm.submit()} confirmLoading={nodeBusy} destroyOnClose>
      <Alert type="info" showIcon message="登记只记录明确提交的节点" description="不会自动发现主机或扩大扫描范围。登记后可由管理员在清册中显式签发或轮换一次性令牌；证书和远程部署仍由部署流程单独配置。" style={{marginBottom:16}}/>
      <Form form={nodeForm} layout="vertical" onFinish={submitNodeRegistration} initialValues={{kind:'worker'}}>
        <Form.Item name="id" label="节点 ID" rules={[{required:true,pattern:/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/,message:'请输入 1–64 位英文、数字、点、下划线或短横线'}]}><Input maxLength={64} placeholder="例如 worker-a"/></Form.Item>
        <Form.Item name="kind" label="节点类型" rules={[{required:true}]}><Select options={[{value:'worker',label:'Worker'},{value:'updater',label:'Updater'}]}/></Form.Item>
        <Form.Item name="hostId" label="主机 ID" rules={[{required:true,pattern:/^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$/,message:'请输入 1–64 位英文、数字、点、下划线或短横线'}]}><Input maxLength={64} placeholder="例如 scan-host-a"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={nodeDetail?`节点生命周期 · ${nodeDetail.id}`:'节点生命周期'} open={nodeDetailsOpen} onCancel={()=>setNodeDetailsOpen(false)} footer={null} width={720} destroyOnClose>
      {nodeDetailLoading?<Typography.Paragraph>正在读取节点状态…</Typography.Paragraph>:nodeDetail?<><Descriptions bordered size="small" column={2}>
        <Descriptions.Item label="节点 ID">{nodeDetail.id}</Descriptions.Item><Descriptions.Item label="类型">{nodeDetail.kind}</Descriptions.Item>
        <Descriptions.Item label="主机 ID">{nodeDetail.hostId}</Descriptions.Item><Descriptions.Item label="状态"><Tag color={nodeDetail.status==='ONLINE'?'green':nodeDetail.status==='REVOKED'?'red':'default'}>{lifecycleStatusLabel(nodeDetail.status)}</Tag></Descriptions.Item>
        <Descriptions.Item label="登记时间">{formatNodeTime(nodeDetail.registeredAt)}</Descriptions.Item><Descriptions.Item label="最近心跳">{formatNodeTime(nodeDetail.lastHeartbeat)}</Descriptions.Item>
        <Descriptions.Item label="离线周期">{nodeDetail.offlineGeneration}</Descriptions.Item><Descriptions.Item label="吊销时间">{formatNodeTime(nodeDetail.revokedAt)}</Descriptions.Item>
      </Descriptions><Typography.Title level={5} style={{marginTop:20}}>生命周期事件</Typography.Title><List size="small" dataSource={nodeEvents} locale={{emptyText:'暂无生命周期事件'}} renderItem={event=><List.Item><Space><Tag>{lifecycleEventLabel(event.kind)}</Tag><Typography.Text>{formatNodeTime(event.createdAt)}</Typography.Text><Typography.Text type="secondary">周期 {event.generation}</Typography.Text></Space></List.Item>}/></>:<Alert type="warning" showIcon message="节点尚未登记或生命周期记录不可用"/>}
    </Modal>
    <Modal title="节点令牌已生成" open={nodeCredentialOpen} onCancel={()=>{setNodeCredentialOpen(false);setNodeCredential(null);}} footer={null} destroyOnClose>
      {nodeCredential&&<><Alert type="warning" showIcon message="令牌只显示这一次" description="请立即写入节点机器上的 owner-only 普通文件（建议权限 0600），不要粘贴到日志、环境变量或工单正文。服务端已经原子更新令牌注册表。"/><Descriptions bordered size="small" column={1} style={{marginTop:16}}><Descriptions.Item label="节点">{nodeCredential.id}（{nodeCredential.kind}）</Descriptions.Item><Descriptions.Item label="主机 ID">{nodeCredential.hostId}</Descriptions.Item><Descriptions.Item label="节点 API">{nodeCredential.serverUrl||'由部署配置提供'}</Descriptions.Item><Descriptions.Item label="令牌"><Input.Password readOnly value={nodeCredential.token}/></Descriptions.Item></Descriptions></>}
    </Modal>
    <Modal title="从指定规则源下载 ZIP" open={fetchOpen} onCancel={()=>setFetchOpen(false)} onOk={()=>form.submit()} confirmLoading={busy}>
      <Form form={form} layout="vertical" onFinish={async(v:{url:string;expectedSha256:string})=>{if(await run(()=>fetchRules(v.url,v.expectedSha256))) setFetchOpen(false);}}>
        <Form.Item name="url" label="HTTPS ZIP 地址" rules={[{required:true,type:'url'}]} extra="不允许 URL 内携带账号、密码、查询参数；不自动发现规则源。"><Input placeholder="https://rules.example.com/bundle.zip"/></Form.Item>
        <Form.Item name="expectedSha256" label="ZIP 的 SHA-256" rules={[{required:true,pattern:/^[a-fA-F0-9]{64}$/,message:'请输入 64 位十六进制 SHA-256'}]}><Input maxLength={64}/></Form.Item>
      </Form>
    </Modal>
    <Modal title={editingRule?'修改自定义规则':'新增自定义规则'} open={ruleOpen} onCancel={()=>{setRuleOpen(false);setEditingRule(null);ruleForm.resetFields();}} onOk={()=>ruleForm.submit()} confirmLoading={busy} destroyOnClose>
      <Form form={ruleForm} layout="vertical" onFinish={saveRule} initialValues={{severity:'medium',matchType:'word',part:'body',enabled:true}}>
        <Form.Item name="id" label="规则 ID（仅小写英文、数字、短横线）" rules={[{required:true,pattern:/^[a-z0-9][a-z0-9_-]{0,99}$/}]}><Input disabled={!!editingRule} maxLength={100} placeholder="例如 legacy-console-banner"/></Form.Item>
        <Form.Item name="name" label="规则名称" rules={[{required:true,max:120}]}><Input maxLength={120}/></Form.Item>
        <Form.Item name="severity" label="严重程度" rules={[{required:true}]}><Select options={['info','low','medium','high','critical'].map(value=>({value,label:value.toUpperCase()}))}/></Form.Item>
        <Form.Item name="description" label="说明"><Input.TextArea rows={2} maxLength={2000}/></Form.Item>
        <Form.Item name="path" label="请求路径（同源只读 GET）" extra="以 / 开头，例如 /actuator/env；留空则检查根路径 /。只发只读 GET，不发送 payload。"><Input placeholder="/ 或 /actuator/env"/></Form.Item>
        <Form.Item name="matchType" label="匹配方式" rules={[{required:true}]}><Select options={[{value:'word',label:'响应文本包含'}, {value:'regex',label:'响应内容正则'}, {value:'status',label:'HTTP 状态码'}]}/></Form.Item>
        {ruleMatchType==='status'?<Form.Item name="statusCodesText" label="状态码（英文逗号分隔）" rules={[{required:true}]} extra="例如 200, 401；允许 100–599。"><Input placeholder="200, 401"/></Form.Item>:<><Form.Item name="part" label="检查位置" rules={[{required:true}]}><Select options={[{value:'body',label:'响应正文'},{value:'header',label:'响应头'}]}/></Form.Item><Form.Item name="valuesText" label={ruleMatchType==='regex'?'正则表达式（每行一条）':'匹配文本（每行一条）'} rules={[{required:true}]} extra="最多 8 条，每条最多 256 字符。"><Input.TextArea rows={4} maxLength={2200}/></Form.Item></>}
        <Form.Item name="enabled" label="状态" rules={[{required:true}]}><Select options={[{value:true,label:'启用（自动用于后续任务）'},{value:false,label:'停用'}]}/></Form.Item>
      </Form>
    </Modal>
  </div>;
};
