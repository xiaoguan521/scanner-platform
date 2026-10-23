import React, { useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Checkbox, Collapse, Descriptions, Form, Input, InputNumber, message, Modal, Select, Space, Steps, Tag, Typography, theme } from 'antd';
import { apiClient, errorMessage } from '../../api/client';
import { createTask, deleteScanPlan, saveSchedule, updateSchedule } from '../../api/runtime';
import type { Asset, CustomRule, PortProbeRange, ScanPlan, ScanTask, Schedule, TaskInput, ScanPolicy } from '../../types';

import { parsePortRanges, showRanges, coversAllPorts, presetLabels, summarizePorts, compressPorts, previewProbePorts } from './policy';
import { assertTaskSubmission, isAutoTaskWizard, wizardStepFields } from './wizard';

const dayOptions=['周日','周一','周二','周三','周四','周五','周六'].map((label,value)=>({label,value}));
type Values={engine:'auto'|'synthetic'|'nuclei'|'trivy'|'zap'|'port-probe';scheme:'http'|'https';inputPath:string;inputKind:'filesystem'|'image-archive'|'rootfs'|'artifact';targets:string[];assetIds:string[];scanPlan:string;portPreset:'common'|'custom'|'common-and-custom'|'registered'|'full';intensity:'gentle'|'standard'|'aggressive';portRanges:string;portExclusions:string;opsApproved:boolean;customRuleIds:string[];mode:'now'|'schedule';name:string;nextRun:string;intervalMinutes:number;window:boolean;weekdays:number[];start:string;end:string;timeZone:string};
function validateProbeRanges(text?:string):void{
  const ranges=parsePortRanges(text);
  if(ranges.length===0) throw new Error('此模式至少填写一个端口或端口范围');
}

/** Asks before probing all 65535 ports; used by the wizard and by manual schedule runs. */
export const confirmFull=()=>new Promise<boolean>(resolve=>Modal.confirm({title:'确认全端口探测',content:'将对这台主机的 TCP 1–65535 端口发起连接（排除项会跳过）。按每次连接超时 1 秒、并发 16 粗略估算约 69 分钟；实际时间取决于速率、超时和响应，服务识别与漏洞检测会额外耗时。可能增加目标连接数及日志量，请确认维护窗口和授权范围。',okText:'确认全端口范围',cancelText:'返回修改',onOk:()=>resolve(true),onCancel:()=>resolve(false)}));

/** What the page asks the dialog to open with. */
export type TaskCreateRequest = { kind: 'new'; mode: 'now' | 'schedule' } | { kind: 'schedule'; schedule: Schedule } | { kind: 'copy'; task: ScanTask };

// Create a task or schedule, edit a schedule, or start from an existing task.
// Simple engines use one form; automatic scans walk through the wizard steps.
export const TaskCreateModal:React.FC<{
  request:TaskCreateRequest|null;
  onClose:()=>void;
  canWrite:boolean;
  syntheticEnabled:boolean;
  assets:Asset[];
  scanPlans:ScanPlan[];
  setScanPlans:React.Dispatch<React.SetStateAction<ScanPlan[]>>;
  customRules:CustomRule[];
  setSchedules:React.Dispatch<React.SetStateAction<Schedule[]>>;
  onTaskCreated:()=>void;
  onEditPlan:(plan:ScanPlan,copy:boolean)=>void;
}>=({request,onClose,canWrite,syntheticEnabled,assets,scanPlans,setScanPlans,customRules,setSchedules,onTaskCreated:reloadTasks,onEditPlan:openPlanEditor})=>{
  const {token}=theme.useToken();
  const [open,setOpenState]=useState(false);
  // Closing also clears the page's request so the same action can open the dialog again.
  const setOpen=(value:boolean)=>{setOpenState(value);if(!value)onClose();};const [busy,setBusy]=useState(false);const [form]=Form.useForm<Values>();
  const [policy,setPolicy]=useState<ScanPolicy|null>(null);const [policyError,setPolicyError]=useState('');
  useEffect(()=>{const controller=new AbortController();apiClient.scanPolicy().then(setPolicy).catch(e=>setPolicyError(errorMessage(e)));return()=>controller.abort();},[]);
  const [wizardStep,setWizardStep]=useState(0);
  const [editingSchedule,setEditingSchedule]=useState<Schedule|null>(null);
  const engine=Form.useWatch('engine',form)??'auto';const mode=Form.useWatch('mode',form);const useWindow=Form.useWatch('window',form);const portPreset=Form.useWatch('portPreset',form)??'common';const selectedPlan=Form.useWatch('scanPlan',form)??'quick';
  const wizard=isAutoTaskWizard({engine,mode},Boolean(editingSchedule));
  const watchedValues=Form.useWatch([],form) as Partial<Values>|undefined;
  const selectedAssets=(watchedValues?.assetIds??[]).map(id=>assets.find(asset=>asset.id===id&&asset.kind==='host')).filter((asset):asset is typeof assets[number]=>Boolean(asset));
  const portPreviews=useMemo(()=>{
    if(!wizard||!selectedAssets.length||!policy)return [];
    try{return selectedAssets.map(asset=>({asset,preview:previewProbePorts(asset,{preset:portPreset,ranges:['custom','common-and-custom'].includes(portPreset)?parsePortRanges(watchedValues?.portRanges):[],exclusions:parsePortRanges(watchedValues?.portExclusions)},policy)}));}catch{return [];}
  // eslint-disable-next-line react-hooks/exhaustive-deps
  },[wizard,watchedValues?.assetIds,assets,policy,portPreset,watchedValues?.portRanges,watchedValues?.portExclusions]);
  const selectedAsset=selectedAssets[0];
  const portPreview=portPreviews[0]?.preview??null;
  useEffect(()=>{setWizardStep(0);},[engine,mode]);
  const nextWizardStep=async()=>{
    try{
      await form.validateFields(wizardStepFields(wizardStep,form.getFieldsValue(true)));
      const chosenIds:string[]=form.getFieldValue('assetIds')??[];
      if(wizardStep===0&&(!chosenIds.length||!chosenIds.every(id=>assets.some(asset=>asset.id===id&&asset.kind==='host'))))throw new Error('请选择当前已登记的主机');
      if(wizardStep===1){
        if(!policy)throw new Error(policyError?'扫描策略读取失败，请刷新页面后重试':'扫描策略正在加载，请稍后重试');
        if(!portPreviews.length||portPreviews.some(item=>!item.preview.effective.length))throw new Error('有主机在所选范围内没有可扫描端口，请检查端口范围和排除项');
      }
      setWizardStep(Math.min(3,wizardStep+1));
    }catch(cause){if(cause instanceof Error)message.error(cause.message);}
  };
  const options=assets.filter(a=>a.kind==='host').flatMap(a=>(a.ports??[]).filter(item=>item.kind==='WEB'||item.kind==='NON_WEB').map(item=>{
    const target=(a.address.includes(':')?'['+a.address+']':a.address)+':'+item.port;
    return {value:target,label:target+'（已审批）'};
  }));
  useEffect(()=>{if(engine==='port-probe'&&mode==='schedule')form.setFieldValue('mode','now');},[engine,mode,form]);
  const choosePlan=(plan:ScanPlan)=>{form.setFieldsValue({scanPlan:plan.id,...plan.defaults});};
  const removePlan=(plan:ScanPlan)=>Modal.confirm({title:'删除自定义扫描方案',content:`删除“${plan.title}”后不会影响已经创建的任务；之后不能再从方案卡片选择它。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteScanPlan(plan.id);setScanPlans(prev=>prev.filter(item=>item.id!==plan.id));if(selectedPlan===plan.id){const quick=scanPlans.find(item=>item.id==='quick');if(quick)choosePlan(quick);}message.success('自定义扫描方案已删除');}catch(cause){message.error(errorMessage(cause,'删除扫描方案失败'));throw cause;}}});
  const create=async(values:Values)=>{
    if(busy)return;
    setBusy(true);
    try{
      assertTaskSubmission(values,canWrite,wizard,wizardStep);
      const requestedRanges=['custom','common-and-custom'].includes(values.portPreset)?parsePortRanges(values.portRanges):[];
      const fullRange=(values.engine==='auto'||values.engine==='port-probe')&&(values.portPreset==='full'||coversAllPorts(requestedRanges)||(wizard&&portPreviews.some(item=>item.preview.requested.length===65535)));
      if(fullRange&&!(await confirmFull()))return;
      const timeWindows=values.window?[{weekdays:values.weekdays,start:values.start,end:values.end,timeZone:values.timeZone}]:[];
      const buildInput=(assetId:string):TaskInput=>values.engine==='auto'||values.engine==='port-probe'
        ?{synthetic:false,engine:values.engine,assetId,portProbe:{preset:values.portPreset??'common',ranges:requestedRanges,intensity:values.intensity??'gentle',fullConfirmed:fullRange,exclusions:parsePortRanges(values.portExclusions),opsApproved:Boolean(values.opsApproved)},...(values.engine==='auto'&&values.customRuleIds?.length?{customRuleIds:values.customRuleIds}:{}),targets:[],timeWindows}
        :{synthetic:values.engine==='synthetic',...(values.engine!=='synthetic'?{engine:values.engine}:{}),...(values.engine==='trivy'?{inputPath:values.inputPath,inputKind:values.inputKind}:values.engine!=='synthetic'?{scheme:values.scheme}:{}),targets:values.engine==='trivy'?[]:values.targets,timeWindows};
      const hostIds=values.engine==='auto'||values.engine==='port-probe'?values.assetIds:[''];
      if(values.mode==='schedule'){
        const date=new Date(values.nextRun);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()) throw new Error('首次运行时间必须晚于现在');
        const scheduleInput={...buildInput(hostIds[0]),name:values.name,nextRun:date.toISOString(),intervalMinutes:values.intervalMinutes??0};
        if(editingSchedule){
          if(hostIds.length!==1)throw new Error('修改定时任务时只能选择一台主机');
          const updated=await updateSchedule(editingSchedule.id,scheduleInput);
          setSchedules(prev=>prev.map(item=>item.id===updated.id?updated:item));
          message.success('定时任务已修改');
        }else{
          const created:Schedule[]=[];
          for(const id of hostIds){
            const host=assets.find(asset=>asset.id===id);
            const name=hostIds.length>1&&host?`${values.name} · ${host.address}`:values.name;
            created.unshift(await saveSchedule({...scheduleInput,...buildInput(id),name}));
          }
          setSchedules(prev=>[...created,...prev]);
          message.success(hostIds.length>1?`已保存 ${hostIds.length} 个定时任务，到点由平台创建任务`:'定时任务已保存，到点由平台创建任务');
        }
      }else{
        const tasks=[];
        try{for(const id of hostIds)tasks.push(await createTask(buildInput(id)));}
        finally{if(tasks.length)reloadTasks();}
        message.success(tasks.length>1?`已为 ${tasks.length} 台主机各创建一个任务`:tasks[0].status==='WAITING_WINDOW'?'已创建，等待允许的时间窗':'任务已入队');
      }
      setOpen(false);setEditingSchedule(null);form.resetFields();
    }catch(e){message.error(errorMessage(e,'创建失败'));}finally{setBusy(false);}
  };
  const openCreate=(selectedMode:'now'|'schedule')=>{
    setEditingSchedule(null);setWizardStep(0);
    form.resetFields();
    form.setFieldValue('mode',selectedMode);
    setOpen(true);
  };
  const openScheduleEdit=(schedule:Schedule)=>{
    const window=schedule.timeWindows?.[0];const nextRun=new Date(schedule.nextRun);
    form.setFieldsValue({engine:schedule.synthetic?'synthetic':schedule.engine??'synthetic',scheme:schedule.scheme??'http',inputPath:schedule.inputPath??'',inputKind:schedule.inputKind??'filesystem',targets:schedule.targets??[],assetIds:schedule.assetId?[schedule.assetId]:[],scanPlan:'standard',portPreset:schedule.portProbe?.preset??'common',intensity:schedule.portProbe?.intensity??'gentle',portRanges:schedule.portProbe?.ranges?.map(r=>r.start===r.end?String(r.start):`${r.start}-${r.end}`).join(', ')??'',portExclusions:schedule.portProbe?.exclusions?.map(r=>r.start===r.end?String(r.start):`${r.start}-${r.end}`).join(', ')??'',customRuleIds:schedule.customRuleIds??[],mode:'schedule',name:schedule.name,nextRun:Number.isFinite(nextRun.getTime())?new Date(nextRun.getTime()-nextRun.getTimezoneOffset()*60000).toISOString().slice(0,16):'',intervalMinutes:schedule.intervalMinutes,window:Boolean(schedule.timeWindows?.length),weekdays:window?.weekdays??[1,2,3,4,5],start:window?.start??'09:00',end:window?.end??'18:00',timeZone:window?.timeZone??'Asia/Shanghai'});
    setWizardStep(0);setEditingSchedule(schedule);setOpen(true);
  };
  const copyTask=(task:ScanTask)=>{
    form.resetFields();
    const taskEngine:Values['engine']=task.synthetic?'synthetic':task.engines[0]==='port-probe'?'auto':task.engines[0];const window=task.timeWindows?.[0];
    const portConfig=task.portProbeConfig;
    const rangeText=(ranges?:PortProbeRange[])=>ranges?.map(range=>range.start===range.end?String(range.start):`${range.start}-${range.end}`).join(', ')??'';
    form.setFieldsValue({engine:taskEngine,scheme:task.scheme==='https'?'https':'http',inputPath:task.inputPath??'',inputKind:(task.inputKind as Values['inputKind'])??'filesystem',targets:task.chunks?.flatMap(chunk=>chunk.targets)??[],assetIds:task.assetId?[task.assetId]:[],scanPlan:'standard',portPreset:portConfig?.preset??'common',intensity:portConfig?.intensity??'gentle',portRanges:rangeText(portConfig?.ranges),portExclusions:rangeText(portConfig?.exclusions),opsApproved:false,mode:'now',window:Boolean(task.timeWindows?.length),weekdays:window?.weekdays??[0,1,2,3,4,5,6],start:window?.start??'09:00',end:window?.end??'18:00',timeZone:window?.timeZone??'Asia/Shanghai'});
    setWizardStep(0);setEditingSchedule(null);setOpen(true);
  };
  useEffect(()=>{
    if(!request)return;
    if(request.kind==='new')openCreate(request.mode);
    else if(request.kind==='schedule')openScheduleEdit(request.schedule);
    else copyTask(request.task);
  // Each request object opens the dialog once.
  },[request]);
  return <>
    <Modal title={editingSchedule?'修改定时任务':wizard?'创建自动综合扫描':'创建任务 / 定时任务'} open={open} width={720} onCancel={()=>{if(busy)return;setOpen(false);setEditingSchedule(null);setWizardStep(0);form.resetFields();}} onOk={()=>form.submit()} confirmLoading={busy} destroyOnClose maskClosable={!busy} closable={!busy} footer={wizard?<Space wrap>
      <Button disabled={busy} onClick={()=>{setOpen(false);setWizardStep(0);form.resetFields();}}>取消</Button>
      {wizardStep>0&&<Button disabled={busy} onClick={()=>setWizardStep(step=>step-1)}>上一步</Button>}
      {wizardStep<3?<Button type="primary" onClick={()=>void nextWizardStep()}>下一步</Button>:<Button type="primary" loading={busy} disabled={!canWrite||!watchedValues?.opsApproved} onClick={()=>form.submit()}>确认并创建</Button>}
    </Space>:undefined}>
      {wizard&&<Steps current={wizardStep} size="small" style={{marginBottom:24}} items={[{title:'目标'},{title:'方案'},{title:'执行方式'},{title:'确认'}]}/>}
      <Form<Values> form={form} disabled={busy} layout="vertical" onValuesChange={changed=>{if(wizard&&!Object.prototype.hasOwnProperty.call(changed,'opsApproved'))form.setFieldValue('opsApproved',false);}} onFinish={create} onKeyDown={event=>{if(wizard&&wizardStep<3&&event.key==='Enter'&&!(event.target as HTMLElement).closest('.ant-select, textarea')){event.preventDefault();void nextWizardStep();}}} initialValues={{engine:'auto',scheme:'http',inputKind:'filesystem',mode:'now',scanPlan:'quick',portPreset:'common',intensity:'gentle',portRanges:'',portExclusions:'',opsApproved:false,customRuleIds:[],window:false,weekdays:[0,1,2,3,4,5,6],start:'09:00',end:'18:00',timeZone:'Asia/Shanghai',intervalMinutes:0}}>
        <div hidden={wizard&&wizardStep!==0}><Form.Item name="engine" label="执行任务"><Select options={[{value:'auto',label:'自动综合扫描（推荐）'},{value:'trivy',label:'离线输入扫描（系统包 / 应用 / 镜像）'},...(syntheticEnabled?[{value:'synthetic',label:'模拟任务（不连接目标）'}]:[])]}/></Form.Item>{engine==='auto'&&<Collapse size="small" ghost style={{marginBottom:16}} items={[{key:'flow',label:'了解自动综合扫描流程',children:<Typography.Paragraph style={{marginBottom:0}}>选择一台或多台已登记主机并填写端口范围或排除端口，平台会并发探测范围内的 TCP 端口，再对开放的 HTTP(S) 服务自动执行只读基线和选中的自定义规则。Worker 配置了该主机的 SSH 只读档案、known_hosts 和密钥文件或 SSH Agent，且 SSH 端口包含在本次范围时，还会临时采集 Linux 软件包快照并用本地 Trivy 漏洞库分析。如还配置了 Java/Go 应用的具体部署目录，将逐个采集支持的产物并分析其依赖。SSH 凭据和部署目录只留在 Worker。</Typography.Paragraph>}]}/>}</div>
        {(engine==='nuclei'||engine==='zap')&&<Form.Item name="scheme" label="Web 协议" rules={[{required:true}]}><Select options={[{value:'http',label:'HTTP'},{value:'https',label:'HTTPS（允许自签名证书）'}]}/></Form.Item>}
        {engine==='trivy'?<><Form.Item name="inputKind" label="输入类型"><Select options={[{value:'rootfs',label:'Linux 系统包快照（rootfs）'},{value:'filesystem',label:'应用依赖清单（lock 文件）'},{value:'artifact',label:'已部署应用 / 中间件（JAR / Go 文件）'},{value:'image-archive',label:'Docker 镜像归档（docker save / OCI tar）'}]}/></Form.Item><Form.Item name="inputPath" label="Worker 本机输入路径（只填相对路径）" rules={[{required:true,message:'请填写已复制到 Worker 的输入目录'}]} extra="系统包示例：将已授权采集的输入目录（含隐藏校验文件）复制到 Worker 的 runtime/inputs/，此处填相对路径。"><Input placeholder="例如 lab-a/os" maxLength={240}/></Form.Item><Alert style={{marginBottom:16}} type="info" showIcon message="Trivy 读取 Worker 上的离线快照，不会自行联网或连接目标。"/></>:engine==='port-probe'||engine==='auto'?<>
          <div hidden={wizard&&wizardStep!==0}><Form.Item name="assetIds" label="已登记主机" extra={editingSchedule?'修改定时任务时只能保留一台主机':'可多选；每台主机会各创建一个独立任务，只扫描所选主机'} rules={[{required:true,type:'array',min:1,message:'请至少选择一台已登记的主机'}]}><Select mode="multiple" maxTagCount="responsive" showSearch optionFilterProp="label" options={assets.filter(a=>a.kind==='host').map(a=>({value:a.id,label:`${a.address} · ${a.businessGroup}`}))} placeholder="选择一台或多台主机"/></Form.Item></div>
          <div hidden={wizard&&wizardStep!==1}><Form.Item name="scanPlan" hidden><Input /></Form.Item><Form.Item label="扫描方案"><Space wrap align="start" role="radiogroup" aria-label="扫描方案">{scanPlans.map(plan=><Card key={plan.id} size="small" hoverable role="radio" aria-checked={selectedPlan===plan.id} aria-label={plan.title} tabIndex={0} onClick={()=>choosePlan(plan)} onKeyDown={event=>{if(event.target===event.currentTarget&&(event.key==='Enter'||event.key===' ')){event.preventDefault();choosePlan(plan);}}} style={{width:270,cursor:'pointer',borderColor:selectedPlan===plan.id?token.colorPrimary:undefined,boxShadow:selectedPlan===plan.id?`0 0 0 1px ${token.colorPrimary}`:undefined}}><Space size={6}><Typography.Text strong>{plan.title}</Typography.Text><Tag color={plan.kind==='CUSTOM'?'blue':'default'}>{plan.kind==='CUSTOM'?'自定义':'预置'}</Tag></Space><Typography.Paragraph style={{margin:'6px 0 2px'}}>{plan.summary}</Typography.Paragraph><Typography.Text type="secondary">{plan.detail}</Typography.Text><Space size={4} style={{marginTop:8}}><Button size="small" type="link" disabled={!canWrite} onClick={event=>{event.stopPropagation();openPlanEditor(plan,true);}}>复制为自定义</Button>{plan.kind==='CUSTOM'&&<><Button size="small" type="link" disabled={!canWrite} onClick={event=>{event.stopPropagation();openPlanEditor(plan,false);}}>编辑</Button><Button size="small" type="link" danger disabled={!canWrite} onClick={event=>{event.stopPropagation();removePlan(plan);}}>删除</Button></>}</Space></Card>)}</Space></Form.Item><Form.Item name="portPreset" label="探测范围"><Select onChange={v=>{if(v==='full')form.setFieldValue('intensity','gentle');}} options={Object.entries(presetLabels).map(([value,label])=>({value,label}))}/></Form.Item>
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
            {key:'target',label:`实际目标（${selectedAssets.length} 台，各建一个任务）`,children:selectedAssets.length?selectedAssets.map(a=>`${a.address} · ${a.businessGroup}`).join('；'):'主机已不可用，请返回重新选择'},
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
  </>;
};
