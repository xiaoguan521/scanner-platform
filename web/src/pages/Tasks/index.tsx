import React, { useEffect, useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { TaskStatusTag, taskStatusMeta } from '../../components/Semantic';
import { Alert, Button, Card, Checkbox, Collapse, Descriptions, Form, Input, InputNumber, message, Modal, Segmented, Select, Space, Steps, Tag, Typography, theme } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useCollection, useServerCapability } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { pollIntervals } from '../../api/polling';
import { usePageState, useQuery } from '../../api/query';
import { apiClient, errorMessage } from '../../api/client';
import { archiveTask, cancelTask, createTask, deleteScanPlan, deleteSchedule, deleteTask, pauseTask, restoreTask, resumeTask, saveSchedule, toggleSchedule, updateSchedule } from '../../api/runtime';
import { useAuth } from '../../auth/AuthProvider';
import type { PortProbeRange, ScanPlan, ScanTask, Schedule, TaskInput, ScanPolicy } from '../../types';

import { parsePortRanges, showRanges, coversAllPorts, presetLabels, summarizePorts, compressPorts, previewProbePorts } from './policy';
import { taskTargetSummary } from './targets';
import { applicationStatuses } from './coverage';
import { TaskDetailDrawer } from './TaskDetailDrawer';
import { ScheduleHistoryModal } from './ScheduleHistoryModal';
import { ScanPlanEditor, type PlanEditorTarget } from './ScanPlanEditor';
import { renderTaskProgress } from './TaskProgress';
import { assertTaskSubmission, isAutoTaskWizard, wizardStepFields } from './wizard';
const dayOptions=['周日','周一','周二','周三','周四','周五','周六'].map((label,value)=>({label,value}));
const ApplicationCoverage:React.FC<{task:ScanTask}>=({task})=><>
  <Typography.Text>Java / Go 应用：{task.applicationScanStatus?applicationStatuses[task.applicationScanStatus]??'状态未知':'等待 Worker 回报（旧任务未记录应用覆盖）'}</Typography.Text>
  {task.applicationResults?.map(app=><Typography.Text key={app.alias} type={['collection_failed','analysis_failed'].includes(app.status)?'danger':undefined}>应用 {app.alias}：{applicationStatuses[app.status]??'状态未知'}；已分析 {app.analyzedCount} / 选中 {app.selectedCount} 个文件</Typography.Text>)}
</>;
type Values={engine:'auto'|'synthetic'|'nuclei'|'trivy'|'zap'|'port-probe';scheme:'http'|'https';inputPath:string;inputKind:'filesystem'|'image-archive'|'rootfs'|'artifact';targets:string[];assetId:string;scanPlan:string;portPreset:'common'|'custom'|'common-and-custom'|'registered'|'full';intensity:'gentle'|'standard'|'aggressive';portRanges:string;portExclusions:string;opsApproved:boolean;customRuleIds:string[];mode:'now'|'schedule';name:string;nextRun:string;intervalMinutes:number;window:boolean;weekdays:number[];start:string;end:string;timeZone:string};
function validateProbeRanges(text?:string):void{
  const ranges=parsePortRanges(text);
  if(ranges.length===0) throw new Error('此模式至少填写一个端口或端口范围');
}
export const TasksPage:React.FC=()=>{
  const {token}=theme.useToken();
  const {canWrite,isAdmin:canDelete}=useAuth();
  const [showArchived,setShowArchived]=useState(false);
  // Simulated tasks are a local-development capability; hide them unless the Server enables it.
  const syntheticEnabled=useServerCapability('synthetic-worker');
  const {data:assets}=useCollection('assets');
  const {data:scanPlans,setData:setScanPlans,loading:scanPlansLoading,error:scanPlansError}=useCollection('scan-plans');
  const {data:customRules}=useCollection('custom-rules');
  const {data:schedules,setData:setSchedules,loading:scheduleLoading,error:scheduleError}=useCollection('schedules','',true,pollIntervals.schedules);
  const [policy,setPolicy]=useState<ScanPolicy|null>(null);const [policyError,setPolicyError]=useState('');
  useEffect(()=>{const controller=new AbortController();apiClient.scanPolicy().then(setPolicy).catch(e=>setPolicyError(errorMessage(e)));return()=>controller.abort();},[]);
  const [open,setOpen]=useState(false);const [busy,setBusy]=useState(false);const [form]=Form.useForm<Values>();
  const [planTarget,setPlanTarget]=useState<PlanEditorTarget|null>(null);
  const [wizardStep,setWizardStep]=useState(0);
  const [editingSchedule,setEditingSchedule]=useState<Schedule|null>(null);
  const [historySchedule,setHistorySchedule]=useState<Schedule|null>(null);
  const [detailTask,setDetailTask]=useState<ScanTask|null>(null);
  const [taskQuery,setTaskQuery]=useState('');const [taskFilter,setTaskFilter]=useState('');const [statusFilter,setStatusFilter]=useState('all');const [engineFilter,setEngineFilter]=useState('all');const [taskSort,setTaskSort]=useState<'-created_at'|'created_at'>('-created_at');
  const engine=Form.useWatch('engine',form)??'auto';const mode=Form.useWatch('mode',form);const useWindow=Form.useWatch('window',form);const portPreset=Form.useWatch('portPreset',form)??'common';const selectedPlan=Form.useWatch('scanPlan',form)??'quick';
  const wizard=isAutoTaskWizard({engine,mode},Boolean(editingSchedule));
  const watchedValues=Form.useWatch([],form) as Partial<Values>|undefined;
  const selectedAsset=assets.find(asset=>asset.id===watchedValues?.assetId&&asset.kind==='host');
  const portPreview=useMemo(()=>{
    if(!wizard||!selectedAsset||!policy)return null;
    try{return previewProbePorts(selectedAsset,{preset:portPreset,ranges:['custom','common-and-custom'].includes(portPreset)?parsePortRanges(watchedValues?.portRanges):[],exclusions:parsePortRanges(watchedValues?.portExclusions)},policy);}catch{return null;}
  },[wizard,selectedAsset,policy,portPreset,watchedValues?.portRanges,watchedValues?.portExclusions]);
  const taskListFilters={search:taskFilter,status:statusFilter,engine:engineFilter,archived:(showArchived?'true':'false') as 'true'|'false',sort:taskSort};
  const {page:taskPage,pageSize:taskPageSize,onChange:onTaskPageChange}=usePageState(taskListFilters,10);
  const taskList=useQuery(signal=>apiClient.tasksPage(taskPage,taskPageSize,taskListFilters,signal),[taskPage,taskPageSize,taskListFilters],{pollMs:pollIntervals.activeTask,errorFallback:'扫描任务加载失败',emptyValue:{items:[],total:0,page:1,pageSize:taskPageSize,statusCounts:{}}});
  const tasks=taskList.data?.items??[];const taskTotal=taskList.data?.total??0;const taskStatusCounts=taskList.data?.statusCounts??{};const taskLoading=taskList.loading;const taskError=taskList.error;const reloadTasks=taskList.reload;
  useEffect(()=>{const timer=window.setTimeout(()=>setTaskFilter(taskQuery.trim()),300);return()=>window.clearTimeout(timer);},[taskQuery]);
  // Status counts double as quick filters; QUEUED groups every waiting status.
  const queuedCount=(['PENDING','WAITING_WINDOW','PAUSED_WINDOW'] as const).reduce((sum,status)=>sum+(taskStatusCounts[status]??0),0);
  const statusQuick=[{value:'all',label:showArchived?'全部归档':'全部',count:Object.values(taskStatusCounts).reduce((sum,count)=>sum+count,0)},{value:'RUNNING',label:'执行中',count:taskStatusCounts.RUNNING??0},{value:'QUEUED',label:'待执行',count:queuedCount},{value:'PAUSED',label:'已暂停',count:taskStatusCounts.PAUSED??0},{value:'COMPLETED',label:'已完成',count:taskStatusCounts.COMPLETED??0},{value:'FAILED',label:'失败',count:taskStatusCounts.FAILED??0}];
  useEffect(()=>{setWizardStep(0);},[engine,mode]);
  const nextWizardStep=async()=>{
    try{
      await form.validateFields(wizardStepFields(wizardStep,form.getFieldsValue(true)));
      if(wizardStep===0&&!assets.some(asset=>asset.id===form.getFieldValue('assetId')&&asset.kind==='host'))throw new Error('请选择一台当前已登记的主机');
      if(wizardStep===1){
        if(!policy)throw new Error(policyError?'扫描策略读取失败，请刷新页面后重试':'扫描策略正在加载，请稍后重试');
        if(!portPreview?.effective.length)throw new Error('所选范围没有可扫描端口，请检查端口范围和排除项');
      }
      setWizardStep(Math.min(3,wizardStep+1));
    }catch(cause){if(cause instanceof Error)message.error(cause.message);}
  };
  const options=assets.filter(a=>a.kind==='host').flatMap(a=>(a.ports??[]).filter(item=>item.kind==='WEB'||item.kind==='NON_WEB').map(item=>{
    const target=(a.address.includes(':')?'['+a.address+']':a.address)+':'+item.port;
    return {value:target,label:target+'（已审批）'};
  }));
  useEffect(()=>{if(engine==='port-probe'&&mode==='schedule')form.setFieldValue('mode','now');},[engine,mode,form]);
  const confirmFull=()=>new Promise<boolean>(resolve=>Modal.confirm({title:'确认全端口探测',content:'将对这台主机的 TCP 1–65535 端口发起连接（排除项会跳过）。按每次连接超时 1 秒、并发 16 粗略估算约 69 分钟；实际时间取决于速率、超时和响应，服务识别与漏洞检测会额外耗时。可能增加目标连接数及日志量，请确认维护窗口和授权范围。',okText:'确认全端口范围',cancelText:'返回修改',onOk:()=>resolve(true),onCancel:()=>resolve(false)}));
  const choosePlan=(plan:ScanPlan)=>{form.setFieldsValue({scanPlan:plan.id,...plan.defaults});};
  const openPlanEditor=(plan:ScanPlan,copy:boolean)=>{
    if(!canWrite){message.info('当前账号没有管理自定义扫描方案的权限');return;}
    setPlanTarget({plan,copy});
  };
  const removePlan=(plan:ScanPlan)=>Modal.confirm({title:'删除自定义扫描方案',content:`删除“${plan.title}”后不会影响已经创建的任务；之后不能再从方案卡片选择它。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteScanPlan(plan.id);setScanPlans(prev=>prev.filter(item=>item.id!==plan.id));if(selectedPlan===plan.id){const quick=scanPlans.find(item=>item.id==='quick');if(quick)choosePlan(quick);}message.success('自定义扫描方案已删除');}catch(cause){message.error(errorMessage(cause,'删除扫描方案失败'));throw cause;}}});
  const create=async(values:Values)=>{
    if(busy)return;
    setBusy(true);
    try{
      assertTaskSubmission(values,canWrite,wizard,wizardStep);
      const requestedRanges=['custom','common-and-custom'].includes(values.portPreset)?parsePortRanges(values.portRanges):[];
      const fullRange=(values.engine==='auto'||values.engine==='port-probe')&&(values.portPreset==='full'||coversAllPorts(requestedRanges)||(wizard&&portPreview?.requested.length===65535));
      if(fullRange&&!(await confirmFull()))return;
      const timeWindows=values.window?[{weekdays:values.weekdays,start:values.start,end:values.end,timeZone:values.timeZone}]:[];
      const input:TaskInput=values.engine==='auto'||values.engine==='port-probe'
        ?{synthetic:false,engine:values.engine,assetId:values.assetId,portProbe:{preset:values.portPreset??'common',ranges:requestedRanges,intensity:values.intensity??'gentle',fullConfirmed:fullRange,exclusions:parsePortRanges(values.portExclusions),opsApproved:Boolean(values.opsApproved)},...(values.engine==='auto'&&values.customRuleIds?.length?{customRuleIds:values.customRuleIds}:{}),targets:[],timeWindows}
        :{synthetic:values.engine==='synthetic',...(values.engine!=='synthetic'?{engine:values.engine}:{}),...(values.engine==='trivy'?{inputPath:values.inputPath,inputKind:values.inputKind}:values.engine!=='synthetic'?{scheme:values.scheme}:{}),targets:values.engine==='trivy'?[]:values.targets,timeWindows};
      if(values.mode==='schedule'){
        const date=new Date(values.nextRun);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()) throw new Error('首次运行时间必须晚于现在');
        const scheduleInput={...input,name:values.name,nextRun:date.toISOString(),intervalMinutes:values.intervalMinutes??0};
        if(editingSchedule){
          const updated=await updateSchedule(editingSchedule.id,scheduleInput);
          setSchedules(prev=>prev.map(item=>item.id===updated.id?updated:item));
          message.success('定时任务已修改');
        }else{
          const saved=await saveSchedule(scheduleInput);setSchedules(prev=>[saved,...prev]);
          message.success('定时任务已保存，到点由平台创建任务');
        }
      }else{const task=await createTask(input);reloadTasks();message.success(task.status==='WAITING_WINDOW'?'已创建，等待允许的时间窗':'任务已入队');}
      setOpen(false);setEditingSchedule(null);form.resetFields();
    }catch(e){message.error(errorMessage(e,'创建失败'));}finally{setBusy(false);}
  };
  const stop=async(id:string)=>{try{await cancelTask(id);reloadTasks();message.success('任务已取消，不会写入成功结果');}catch(e){message.error(errorMessage(e));}};
  const pause=async(task:ScanTask)=>Modal.confirm({title:'暂停扫描任务',content:`暂停 ${task.id} 后，Worker 会在下一次心跳停止执行，任务不会因时间窗自动恢复。之后可在详情中手动恢复。`,okText:'暂停',cancelText:'继续执行',onOk:async()=>{try{await pauseTask(task.id);reloadTasks();setDetailTask(prev=>prev?.id===task.id?{...prev,status:'PAUSED'}:prev);message.success('任务已暂停');}catch(e){message.error(errorMessage(e));throw e;}}});
  const resume=async(task:ScanTask)=>{try{const updated=await resumeTask(task.id);reloadTasks();setDetailTask(prev=>prev?.id===task.id?{...prev,status:updated.status}:prev);message.success('任务已恢复到队列，平台会重新校验时间窗和规则状态');}catch(e){message.error(errorMessage(e));}};
  const openTaskDetail=(task:ScanTask)=>setDetailTask(task);
  const setArchived=async(id:string,archived:boolean)=>{try{if(archived)await archiveTask(id);else await restoreTask(id);reloadTasks();message.success(archived?'任务已归档':'任务已恢复到清册');}catch(e){message.error(errorMessage(e));}};
  const removeTask=(task:ScanTask)=>Modal.confirm({title:'彻底删除扫描任务',content:`将永久删除任务 ${task.id}。仅允许删除已结束且没有关联发现项的任务；此操作不可撤销，已生成报告快照和审计记录会保留。`,okText:'彻底删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteTask(task.id);reloadTasks();message.success('扫描任务已彻底删除');}catch(e){message.error(errorMessage(e));throw e;}}});
  const openCreate=(selectedMode:'now'|'schedule')=>{
    setEditingSchedule(null);setWizardStep(0);
    form.resetFields();
    form.setFieldValue('mode',selectedMode);
    setOpen(true);
  };
  const openScheduleEdit=(schedule:Schedule)=>{
    const window=schedule.timeWindows?.[0];const nextRun=new Date(schedule.nextRun);
    form.setFieldsValue({engine:schedule.synthetic?'synthetic':schedule.engine??'synthetic',scheme:schedule.scheme??'http',inputPath:schedule.inputPath??'',inputKind:schedule.inputKind??'filesystem',targets:schedule.targets??[],assetId:schedule.assetId??'',scanPlan:'standard',portPreset:schedule.portProbe?.preset??'common',intensity:schedule.portProbe?.intensity??'gentle',portRanges:schedule.portProbe?.ranges?.map(r=>r.start===r.end?String(r.start):`${r.start}-${r.end}`).join(', ')??'',portExclusions:schedule.portProbe?.exclusions?.map(r=>r.start===r.end?String(r.start):`${r.start}-${r.end}`).join(', ')??'',customRuleIds:schedule.customRuleIds??[],mode:'schedule',name:schedule.name,nextRun:Number.isFinite(nextRun.getTime())?new Date(nextRun.getTime()-nextRun.getTimezoneOffset()*60000).toISOString().slice(0,16):'',intervalMinutes:schedule.intervalMinutes,window:Boolean(schedule.timeWindows?.length),weekdays:window?.weekdays??[1,2,3,4,5],start:window?.start??'09:00',end:window?.end??'18:00',timeZone:window?.timeZone??'Asia/Shanghai'});
    setWizardStep(0);setEditingSchedule(schedule);setOpen(true);
  };
  const copyTask=(task:ScanTask)=>{
    form.resetFields();
    const taskEngine:Values['engine']=task.synthetic?'synthetic':task.engines[0]==='port-probe'?'auto':task.engines[0];const window=task.timeWindows?.[0];
    const portConfig=task.portProbeConfig;
    const rangeText=(ranges?:PortProbeRange[])=>ranges?.map(range=>range.start===range.end?String(range.start):`${range.start}-${range.end}`).join(', ')??'';
    form.setFieldsValue({engine:taskEngine,scheme:task.scheme==='https'?'https':'http',inputPath:task.inputPath??'',inputKind:(task.inputKind as Values['inputKind'])??'filesystem',targets:task.chunks?.flatMap(chunk=>chunk.targets)??[],assetId:task.assetId??'',scanPlan:'standard',portPreset:portConfig?.preset??'common',intensity:portConfig?.intensity??'gentle',portRanges:rangeText(portConfig?.ranges),portExclusions:rangeText(portConfig?.exclusions),opsApproved:false,mode:'now',window:Boolean(task.timeWindows?.length),weekdays:window?.weekdays??[0,1,2,3,4,5,6],start:window?.start??'09:00',end:window?.end??'18:00',timeZone:window?.timeZone??'Asia/Shanghai'});
    setWizardStep(0);setEditingSchedule(null);setOpen(true);
  };
  const removeSchedule=(schedule:Schedule)=>Modal.confirm({title:'删除定时任务',content:`删除“${schedule.name}”后将停止后续调度，已创建的扫描任务和结果会保留。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteSchedule(schedule.id);setSchedules(prev=>prev.filter(item=>item.id!==schedule.id));message.success('定时任务已删除');}catch(cause){message.error(errorMessage(cause,'删除失败'));throw cause;}}});
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={taskLoading||scheduleLoading||scanPlansLoading} error={taskError||scheduleError||scanPlansError}/>
    <Card title="扫描任务" extra={<Space wrap>
      <Button type="primary" icon={<PlusOutlined/>} disabled={!canWrite} onClick={()=>openCreate('now')}>创建扫描任务</Button>
      <Button disabled={!canWrite} onClick={()=>openCreate('schedule')}>创建定时任务</Button>
    </Space>}>
      <Space wrap style={{marginBottom:16}}>
        <Input.Search aria-label="任务搜索" allowClear placeholder="搜索任务 ID、目标或输入路径" value={taskQuery} onChange={event=>setTaskQuery(event.target.value)} style={{width:260}}/>
        <Select aria-label="任务状态筛选" value={statusFilter} onChange={setStatusFilter} style={{width:170}} options={[{value:'all',label:'所有状态'},{value:'QUEUED',label:'待执行（含等待时间窗）'},...Object.entries(taskStatusMeta).map(([value,meta])=>({value,label:meta.label}))]}/>
        <Select aria-label="扫描方案筛选" value={engineFilter} onChange={setEngineFilter} style={{width:180}} options={[{value:'all',label:'所有扫描方案'},...(showArchived?['auto','trivy','port-probe','nuclei','zap','synthetic']:['auto','trivy',...(syntheticEnabled?['synthetic']:[])]).map(value=>({value,label:value==='auto'?'自动综合扫描':value==='port-probe'?'历史 TCP 端口探测':value==='synthetic'?'模拟任务':value==='trivy'?'离线输入扫描':`历史 ${value.toUpperCase()} 任务`}))]}/>
        <Button onClick={()=>{setShowArchived(value=>!value);setEngineFilter('all');}}>{showArchived?'返回任务清册':'查看归档'}</Button>
        <Segmented aria-label="按状态快速筛选" value={statusQuick.some(item=>item.value===statusFilter)?statusFilter:''} onChange={value=>setStatusFilter(String(value))} options={statusQuick.map(item=>({value:item.value,label:`${item.label} ${item.count}`}))}/>
      </Space>
      <DataTable<ScanTask> dataSource={tasks} rowKey="id" loading={taskLoading} tableLayout="fixed" scroll={{x:1600}} onChange={(_pagination,_filters,sorter,extra)=>{if(extra.action!=='sort')return;const current=Array.isArray(sorter)?sorter[0]:sorter;setTaskSort(current?.order==='ascend'?'created_at':'-created_at');}} locale={{emptyText:taskFilter||statusFilter!=='all'||engineFilter!=='all'?'没有符合筛选条件的任务':showArchived?'暂无归档任务':'暂无任务，请从右上角创建扫描任务或定时任务'}} pagination={{current:taskPage,pageSize:taskPageSize,total:taskTotal,showSizeChanger:true,pageSizeOptions:[10,20,50],showTotal:total=>`共 ${total} 个任务`,onChange:onTaskPageChange}}
        expandable={{expandedRowRender:t=><Space direction="vertical"><Typography.Text>下发目标：{(()=>{const all=t.chunks?.flatMap(c=>c.targets)??[];return all.length>20?`${all.slice(0,20).join('、')} ……（共 ${all.length} 个）`:all.join('、')||'无';})()}</Typography.Text>{(t.engines?.[0]==='port-probe'||t.engines?.[0]==='auto')&&<><Typography.Text>探测配置：{presetLabels[t.portProbeConfig?.preset??'common']}；范围 {showRanges(t.portProbeConfig?.ranges)}；任务排除 {showRanges(t.portProbeConfig?.exclusions)}；合并排除 {showRanges(t.effectiveExclusions??t.portProbeConfig?.exclusions)}；隔离端口 {summarizePorts(t.quarantinedPorts)}；强度 {({gentle:'温和',standard:'标准',aggressive:'积极'})[t.portProbeConfig?.intensity??'gentle']}</Typography.Text><Typography.Text>实际探测：{t.portProbePorts?.length??0} 个 TCP 端口；发现开放候选：{t.portProbeResults?.length??0} 个{t.portProbeResults?.length?`（${t.portProbeResults.slice(0,20).map(p=>p.port).join(', ')}${t.portProbeResults.length>20?' …':''}）`:''}</Typography.Text>{t.engines[0]==='auto'&&<><Typography.Text>HTTP(S) 服务：{t.serviceResults?.filter(item=>item.kind==='HTTP').length??0} 个；自定义规则：{t.customRuleCount??0} 条</Typography.Text><Typography.Text>Linux 系统包：{t.systemScanStatus??'等待 Worker 回报'}</Typography.Text><ApplicationCoverage task={t}/><Typography.Text type="secondary">开放端口候选仅用于这次明确授权的范围，不会自动登记成长期授权端口。</Typography.Text></>}</>}{t.inputKind&&<Typography.Text>离线输入：{t.inputKind==='rootfs'?'Linux 系统包':t.inputKind==='image-archive'?'Docker / OCI 镜像':t.inputKind==='artifact'?'已部署 JAR / Go 文件':'应用依赖清单'} · {t.inputPath}</Typography.Text>}<Typography.Text>跳过目标：{t.skippedTargets?.join('、')||'无'}</Typography.Text><Typography.Text>规则版本：{t.ruleVersion||'无需外部规则包'}</Typography.Text>{t.error&&<Alert type="error" message={t.error}/>}</Space>}}
        columns={[
          {title:'任务 ID',dataIndex:'id',width:200,ellipsis:true},
          {title:'执行方式',width:140,render:(_,t)=><Tag color={t.synthetic?'default':'blue'}>{t.synthetic?'模拟 Worker':t.engines[0]==='auto'?'自动综合扫描':t.engines[0]==='port-probe'?'历史 TCP 探测':t.engines.join('、').toUpperCase()}</Tag>},
          {title:'目标',width:220,render:(_,t)=>{const summary=taskTargetSummary(t);return <Space direction="vertical" size={0} style={{minWidth:0,maxWidth:'100%'}}><Typography.Text code ellipsis={{tooltip:summary.primary}}>{summary.primary}</Typography.Text><Typography.Text type="secondary" style={{fontSize:12}}>{summary.detail}</Typography.Text></Space>;}},
          {title:'进度',width:220,render:(_,t)=>renderTaskProgress(t)},
          {title:'状态',dataIndex:'status',width:150,render:(s:string,t)=><Space wrap><TaskStatusTag value={s}/>{t.archived&&<Tag>已归档</Tag>}</Space>},
          {title:'创建时间',dataIndex:'createdAt',width:180,sorter:true,sortDirections:['descend','ascend'],sortOrder:taskSort==='created_at'?'ascend':'descend',render:(v:string)=>v?new Date(v).toLocaleString():'—'},
          {title:'本地截止时间',dataIndex:'hardDeadline',width:190,render:(v:string)=>v?new Date(v).toLocaleString():'—'},
          {title:'操作',width:470,render:(_,t)=>{const terminal=['COMPLETED','CANCELED','FAILED'].includes(t.status);return <Space wrap><Button size="small" onClick={()=>openTaskDetail(t)}>详情</Button>{!terminal&&t.status!=='PAUSED'&&<Button size="small" disabled={!canWrite} onClick={()=>void pause(t)}>暂停</Button>}{t.status==='PAUSED'&&<Button size="small" type="primary" disabled={!canWrite} onClick={()=>void resume(t)}>恢复</Button>}{!terminal&&<Button size="small" danger disabled={!canWrite} onClick={()=>void stop(t.id)}>取消</Button>}{terminal&&<Button size="small" disabled={!canWrite} onClick={()=>void setArchived(t.id,!t.archived)}>{t.archived?'恢复':'归档'}</Button>}{terminal&&<Button size="small" disabled={!canWrite} onClick={()=>copyTask(t)}>按此配置新建</Button>}{terminal&&canDelete&&t.findingCount===0&&<Button size="small" danger onClick={()=>removeTask(t)}>彻底删除</Button>}{terminal&&canDelete&&t.findingCount>0&&<Tag>有关联发现，仅可归档</Tag>}</Space>}},
        ]}/>
    </Card>
    <TaskDetailDrawer task={detailTask} onTaskChange={setDetailTask} onClose={()=>setDetailTask(null)} canWrite={canWrite} onPause={task=>void pause(task)} onResume={task=>void resume(task)} onStop={id=>void stop(id)}/>
    <Card title="定时任务" extra={<Typography.Text type="secondary">间隔 0 表示仅运行一次；错过的重复任务不会集中补跑</Typography.Text>}>
      <DataTable<Schedule> dataSource={schedules} rowKey="id" loading={scheduleLoading} tableLayout="fixed" scroll={{x:1050}} locale={{emptyText:'暂无定时任务。创建时填写首次运行时间；间隔 0 表示只运行一次。'}} columns={[
        {title:'名称',dataIndex:'name'},
        {title:'下一次运行',dataIndex:'nextRun',render:(v:string)=>new Date(v).toLocaleString()},
        {title:'重复间隔',dataIndex:'intervalMinutes',render:(v:number)=>v?`${v} 分钟`:'仅一次'},
        {title:'状态',render:(_,s)=><Tag color={s.enabled?'green':'default'}>{s.enabled?'启用':'停用 / 单次已触发'}</Tag>},
        {title:'最近任务 / 错误',render:(_,s)=>s.lastError||s.lastTaskId||'尚未触发'},
        {title:'操作',width:360,render:(_,s)=><Space wrap>
          <Button size="small" disabled={!canWrite} onClick={async()=>{try{await toggleSchedule(s.id,!s.enabled);setSchedules(prev=>prev.map(item=>item.id===s.id?{...item,enabled:!s.enabled}:item));message.success('定时任务状态已保存');}catch(e){message.error(errorMessage(e));}}}>{s.enabled?'停用':'启用'}</Button>
          <Button size="small" disabled={!canWrite} onClick={async()=>{if(s.portProbe&&(s.portProbe.preset==='full'||coversAllPorts(s.portProbe.ranges??[]))&&!(await confirmFull()))return;try{await createTask({synthetic:s.synthetic,engine:s.engine,scheme:s.scheme,inputPath:s.inputPath,inputKind:s.inputKind,assetId:s.assetId,portProbe:s.portProbe,customRuleIds:s.customRuleIds,targets:s.targets,timeWindows:s.timeWindows});message.success('已另建一条任务，仍遵守时间窗');}catch(e){message.error(errorMessage(e));}}}>手动运行</Button>
          <Button size="small" onClick={()=>setHistorySchedule(s)}>历史运行</Button>
          <Button size="small" disabled={!canWrite} onClick={()=>openScheduleEdit(s)}>修改</Button>
          <Button size="small" danger disabled={!canWrite} onClick={()=>removeSchedule(s)}>删除</Button>
        </Space>},
      ]}/>
    </Card>
    <Modal title={editingSchedule?'修改定时任务':wizard?'创建自动综合扫描':'创建任务 / 定时任务'} open={open} width={720} onCancel={()=>{if(busy)return;setOpen(false);setEditingSchedule(null);setWizardStep(0);form.resetFields();}} onOk={()=>form.submit()} confirmLoading={busy} destroyOnClose maskClosable={!busy} closable={!busy} footer={wizard?<Space wrap>
      <Button disabled={busy} onClick={()=>{setOpen(false);setWizardStep(0);form.resetFields();}}>取消</Button>
      {wizardStep>0&&<Button disabled={busy} onClick={()=>setWizardStep(step=>step-1)}>上一步</Button>}
      {wizardStep<3?<Button type="primary" onClick={()=>void nextWizardStep()}>下一步</Button>:<Button type="primary" loading={busy} disabled={!canWrite||!watchedValues?.opsApproved} onClick={()=>form.submit()}>确认并创建</Button>}
    </Space>:undefined}>
      {wizard&&<Steps current={wizardStep} size="small" style={{marginBottom:24}} items={[{title:'目标'},{title:'方案'},{title:'执行方式'},{title:'确认'}]}/>}
      <Form<Values> form={form} disabled={busy} layout="vertical" onValuesChange={changed=>{if(wizard&&!Object.prototype.hasOwnProperty.call(changed,'opsApproved'))form.setFieldValue('opsApproved',false);}} onFinish={create} onKeyDown={event=>{if(wizard&&wizardStep<3&&event.key==='Enter'&&!(event.target as HTMLElement).closest('.ant-select, textarea')){event.preventDefault();void nextWizardStep();}}} initialValues={{engine:'auto',scheme:'http',inputKind:'filesystem',mode:'now',scanPlan:'quick',portPreset:'common',intensity:'gentle',portRanges:'',portExclusions:'',opsApproved:false,customRuleIds:[],window:false,weekdays:[0,1,2,3,4,5,6],start:'09:00',end:'18:00',timeZone:'Asia/Shanghai',intervalMinutes:0}}>
        <div hidden={wizard&&wizardStep!==0}><Form.Item name="engine" label="执行任务"><Select options={[{value:'auto',label:'自动综合扫描（推荐）'},{value:'trivy',label:'离线输入扫描（系统包 / 应用 / 镜像）'},...(syntheticEnabled?[{value:'synthetic',label:'模拟任务（不连接目标）'}]:[])]}/></Form.Item>{engine==='auto'&&<Collapse size="small" ghost style={{marginBottom:16}} items={[{key:'flow',label:'了解自动综合扫描流程',children:<Typography.Paragraph style={{marginBottom:0}}>选择一台已登记主机并填写端口范围或排除端口，平台会并发探测范围内的 TCP 端口，再对开放的 HTTP(S) 服务自动执行只读基线和选中的自定义规则。Worker 配置了该主机的 SSH 只读档案、known_hosts 和密钥文件或 SSH Agent，且 SSH 端口包含在本次范围时，还会临时采集 Linux 软件包快照并用本地 Trivy 漏洞库分析。如还配置了 Java/Go 应用的具体部署目录，将逐个采集支持的产物并分析其依赖。SSH 凭据和部署目录只留在 Worker。</Typography.Paragraph>}]}/>}</div>
        {(engine==='nuclei'||engine==='zap')&&<Form.Item name="scheme" label="Web 协议" rules={[{required:true}]}><Select options={[{value:'http',label:'HTTP'},{value:'https',label:'HTTPS（允许自签名证书）'}]}/></Form.Item>}
        {engine==='trivy'?<><Form.Item name="inputKind" label="输入类型"><Select options={[{value:'rootfs',label:'Linux 系统包快照（rootfs）'},{value:'filesystem',label:'应用依赖清单（lock 文件）'},{value:'artifact',label:'已部署应用 / 中间件（JAR / Go 文件）'},{value:'image-archive',label:'Docker 镜像归档（docker save / OCI tar）'}]}/></Form.Item><Form.Item name="inputPath" label="Worker 本机输入路径（只填相对路径）" rules={[{required:true,message:'请填写已复制到 Worker 的输入目录'}]} extra="系统包示例：将已授权采集的输入目录（含隐藏校验文件）复制到 Worker 的 runtime/inputs/，此处填相对路径。"><Input placeholder="例如 lab-a/os" maxLength={240}/></Form.Item><Alert style={{marginBottom:16}} type="info" showIcon message="Trivy 读取 Worker 上的离线快照，不会自行联网或连接目标。"/></>:engine==='port-probe'||engine==='auto'?<>
          <div hidden={wizard&&wizardStep!==0}><Form.Item name="assetId" label="已登记主机" rules={[{required:true,message:'请选择一台已登记的主机'}]}><Select showSearch optionFilterProp="label" options={assets.filter(a=>a.kind==='host').map(a=>({value:a.id,label:`${a.address} · ${a.businessGroup}`}))} placeholder="只选择一台主机"/></Form.Item></div>
          <div hidden={wizard&&wizardStep!==1}><Form.Item name="scanPlan" hidden><Input /></Form.Item><Form.Item label="扫描方案"><Space wrap align="start">{scanPlans.map(plan=><Card key={plan.id} size="small" hoverable onClick={()=>choosePlan(plan)} style={{width:270,cursor:'pointer',borderColor:selectedPlan===plan.id?token.colorPrimary:undefined,boxShadow:selectedPlan===plan.id?`0 0 0 1px ${token.colorPrimary}`:undefined}}><Space size={6}><Typography.Text strong>{plan.title}</Typography.Text><Tag color={plan.kind==='CUSTOM'?'blue':'default'}>{plan.kind==='CUSTOM'?'自定义':'预置'}</Tag></Space><Typography.Paragraph style={{margin:'6px 0 2px'}}>{plan.summary}</Typography.Paragraph><Typography.Text type="secondary">{plan.detail}</Typography.Text><Space size={4} style={{marginTop:8}}><Button size="small" type="link" disabled={!canWrite} onClick={event=>{event.stopPropagation();openPlanEditor(plan,true);}}>复制为自定义</Button>{plan.kind==='CUSTOM'&&<><Button size="small" type="link" disabled={!canWrite} onClick={event=>{event.stopPropagation();openPlanEditor(plan,false);}}>编辑</Button><Button size="small" type="link" danger disabled={!canWrite} onClick={event=>{event.stopPropagation();removePlan(plan);}}>删除</Button></>}</Space></Card>)}</Space></Form.Item><Form.Item name="portPreset" label="探测范围"><Select onChange={v=>{if(v==='full')form.setFieldValue('intensity','gentle');}} options={Object.entries(presetLabels).map(([value,label])=>({value,label}))}/></Form.Item>
          {(portPreset==='common'||portPreset==='common-and-custom')&&<Alert style={{marginBottom:16}} showIcon type={policyError?'error':'info'} message={policyError?'常见端口策略读取失败':`常见端口来自系统策略：${policy?.commonPorts?.length??'—'} 个`} description={(policy?summarizePorts(policy.commonPorts):null)||policyError||'由平台统一确定，创建任务时冻结策略。'}/>}
          {portPreset==='full'&&<Alert style={{marginBottom:16}} showIcon type="warning" message="全端口探测耗时较长，请预留维护窗口" description="最多 65535 个 TCP 端口，默认使用温和强度；提交时需要再次确认。排除和隔离端口始终跳过。"/>}
          <Form.Item name="intensity" label="扫描强度"><Select options={[{value:'gentle',label:'温和 · 较低并发和请求速率'},{value:'standard',label:'标准'},{value:'aggressive',label:'积极 · 连接数和目标负载较高'}]}/></Form.Item>
          {['custom','common-and-custom'].includes(portPreset)&&<Form.Item name="portRanges" label="自定义 TCP 端口范围" validateTrigger="onBlur" rules={[{validator:(_,value)=>{try{validateProbeRanges(value);return Promise.resolve();}catch(error){return Promise.reject(error);}}}]} extra="英文逗号分隔；可填写单端口、区间或完整范围，例如 8000-8100, 9000 或 1-65535。若通过 SSH 采集系统包，请把配置的 SSH 端口（常见为 22）包含在范围内。最多 65535 个端口，Worker 并发探测。"><Input placeholder="例如 1-65535"/></Form.Item>}
          <Form.Item name="portExclusions" label="任务排除端口或范围" validateTrigger="onBlur" rules={[{validator:(_,value)=>{try{parsePortRanges(value);return Promise.resolve();}catch(e){return Promise.reject(e);}}}]} extra="英文逗号分隔，最多 128 段，如 443, 8000-8010。系统默认、资产级和任务级排除取并集，隔离端口也会跳过。"><Input placeholder="443, 8000-8010"/></Form.Item>
          {engine==='auto'&&<Form.Item name="customRuleIds" label="自定义漏洞规则" extra="留空时自动使用全部启用规则。规则只对识别出的 HTTP(S) 服务执行只读检查。"><Select mode="multiple" allowClear showSearch optionFilterProp="label" options={customRules.filter(rule=>rule.enabled).map(rule=>({value:rule.id,label:`${rule.name} · ${rule.severity}`}))} placeholder="默认使用全部启用规则"/></Form.Item>}
          <Alert style={{marginBottom:16}} type="warning" showIcon message={engine==='auto'?'自动综合扫描只限选定主机和端口范围':'只对所选主机执行 TCP 连接探测'} description={engine==='auto'?'本次明确填写且经运维授权的范围内，开放 HTTP(S) 端口会执行只读漏洞检查；Worker SSH 档案匹配且端口开放时会采集系统包。端口不会扩展到范围之外，也不会登记为长期授权端口。':'不会发送应用数据、识别服务或自动进行漏洞扫描。'} />
          </div>
        </>:<>
        <Form.Item name="targets" label="目标 IP:端口" rules={[{required:true,type:'array',min:1}]} extra="先在资产页面登记目标和端口；被标记跳过的端口会被排除。"><Select mode="multiple" showSearch optionFilterProp="label" options={options} placeholder="选择明确登记的目标"/></Form.Item></>}
        <div hidden={wizard&&wizardStep!==2}><Form.Item name="mode" label="发起方式"><Select disabled={!!editingSchedule} options={[{value:'now',label:'立即入队'},{value:'schedule',label:'定时发起',disabled:engine==='port-probe'}]}/></Form.Item>
        {mode==='schedule'&&<><Form.Item name="name" label="定时任务名称" rules={[{required:true}]}><Input maxLength={100}/></Form.Item><Form.Item name="nextRun" label="首次运行时间" rules={[{required:true}]}><Input type="datetime-local" step={1}/></Form.Item><Form.Item name="intervalMinutes" label="重复间隔（分钟，0 为仅一次）"><InputNumber min={0} max={525600}/></Form.Item></>}
        <Form.Item name="window" label="限制执行时间窗"><Select options={[{value:false,label:'不限时间'},{value:true,label:'使用指定时间窗'}]}/></Form.Item>
        {useWindow&&<><Form.Item name="weekdays" label="允许开始的星期" rules={[{required:true,type:'array',min:1}]}><Select mode="multiple" options={dayOptions}/></Form.Item><Space><Form.Item name="start" label="开始时间" rules={[{required:true}]}><Input placeholder="09:00" maxLength={5}/></Form.Item><Form.Item name="end" label="结束时间（较早表示次日）" rules={[{required:true}]}><Input placeholder="18:00" maxLength={5}/></Form.Item></Space><Form.Item name="timeZone" label="时区" rules={[{required:true}]}><Select options={['Asia/Shanghai','UTC','America/New_York'].map(value=>({value,label:value}))}/></Form.Item></>}
        </div>
        {wizard&&wizardStep===3&&<>
          <Descriptions bordered size="small" column={1} title="确认扫描配置" items={[
            {key:'target',label:'实际目标',children:selectedAsset?`${selectedAsset.address} · ${selectedAsset.businessGroup}`:'主机已不可用，请返回重新选择'},
            {key:'plan',label:'扫描方案',children:`${scanPlans.find(plan=>plan.id===selectedPlan)?.title??'自定义方案'}：TCP 探测 → 受限服务识别 → 只读 HTTP(S) 检查；SSH 采集依 Worker 档案和范围执行`},
            {key:'preset',label:'端口策略',children:presetLabels[portPreset]},
            {key:'ports',label:`有效 TCP 端口预览（${portPreview?.effective.length??0} 个）`,children:<Typography.Paragraph style={{marginBottom:0,overflowWrap:'anywhere'}} ellipsis={{rows:3,expandable:true,symbol:'展开全部端口'}}>{portPreview?compressPorts(portPreview.effective)||'无':'当前策略不可用'}</Typography.Paragraph>},
            {key:'intensity',label:'扫描强度',children:({gentle:'温和 · 较低并发和请求速率',standard:'标准',aggressive:'积极 · 连接数和目标负载较高'})[watchedValues?.intensity??'gentle']},
            {key:'system-exclusions',label:'系统排除',children:policy?showRanges(policy.exclusions):'策略不可用'},
            {key:'asset-exclusions',label:'资产排除 / 隔离',children:`四层转发：${compressPorts(selectedAsset?.ports?.filter(port=>port.kind==='EXCLUDED_PROXY').map(port=>port.port))||'无'}；隔离：${compressPorts(selectedAsset?.quarantinedPorts)||'无'}`},
            {key:'task-exclusions',label:'任务排除',children:watchedValues?.portExclusions?.trim()||'无'},
            {key:'rules',label:'自定义漏洞规则',children:watchedValues?.customRuleIds?.length?watchedValues.customRuleIds.map(id=>customRules.find(rule=>rule.id===id)?.name??id).join('、'):'全部启用规则'},
            {key:'execution',label:'执行方式',children:'立即入队，遵守执行时间窗'},
            {key:'window',label:'时间窗',children:watchedValues?.window?`${watchedValues.weekdays?.map(day=>dayOptions[day]?.label).join('、')} ${watchedValues.start}–${watchedValues.end}${(watchedValues.end??'')<(watchedValues.start??'')?'（次日结束）':''} · ${watchedValues.timeZone}`:'不限时间'},
          ]}/>
          <Alert style={{marginTop:16}} type="info" showIcon message="端口预览根据当前系统策略、登记端口、排除项和隔离项计算；平台创建时重新校验并冻结实际范围。全端口提交仍需再次确认。"/>
        </>}
        {(engine==='auto'||engine==='port-probe')&&<div hidden={wizard&&wizardStep!==3} style={{marginTop:16}}><Form.Item name="opsApproved" valuePropName="checked" rules={[{validator:(_,value)=>value?Promise.resolve():Promise.reject(new Error('请确认运维授权和四层转发排除情况'))}]}><Checkbox>我已获得运维对这台主机和所选 TCP 端口范围的探测授权，并已排除已知的 Nginx 四层转发端口</Checkbox></Form.Item></div>}
      </Form>
    </Modal>
    <ScanPlanEditor target={planTarget} customRules={customRules} onClose={()=>setPlanTarget(null)} onSaved={(saved,replaced)=>setScanPlans(prev=>replaced?prev.map(item=>item.id===saved.id?saved:item):[...prev,saved])}/>
    <ScheduleHistoryModal schedule={historySchedule} onClose={()=>setHistorySchedule(null)}/>
  </div>;
};
