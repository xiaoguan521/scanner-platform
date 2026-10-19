import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Checkbox, Form, Input, InputNumber, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { isDemoMode } from '../../api/client';
import { cancelTask, createTask, saveSchedule, toggleSchedule } from '../../api/runtime';
import { useAuth } from '../../auth/AuthProvider';
import { mockAssets, mockTasks } from '../../mock/data';
import type { PortProbeRange, ScanTask, Schedule, TaskInput } from '../../types';

const dayOptions=['周日','周一','周二','周三','周四','周五','周六'].map((label,value)=>({label,value}));
const names:Record<string,string>={PENDING:'待领取',RUNNING:'执行中',WAITING_WINDOW:'等待时间窗',PAUSED_WINDOW:'窗口结束，等待恢复',COMPLETED:'已完成',CANCELED:'已取消',FAILED:'失败'};
type Values={engine:'synthetic'|'nuclei'|'trivy'|'zap'|'port-probe';scheme:'http'|'https';inputPath:string;inputKind:'filesystem'|'image-archive'|'rootfs'|'artifact';targets:string[];assetId:string;portPreset:'common'|'custom'|'common-and-custom';portRanges:string;portExclusions:string;opsApproved:boolean;mode:'now'|'schedule';name:string;nextRun:string;intervalMinutes:number;window:boolean;weekdays:number[];start:string;end:string;timeZone:string};
function parsePortRanges(text?:string):PortProbeRange[]{
  if(!text?.trim()) return [];
  const parts=text.split(',').map(value=>value.trim());
  if(parts.length>128) throw new Error('端口范围最多填写 128 段');
  return parts.map(part=>{
    const match=/^([0-9]{1,5})(?:-([0-9]{1,5}))?$/.exec(part);
    if(!match) throw new Error('端口请填写数字或起止范围，如 8080, 9000-9010');
    const start=Number(match[1]),end=Number(match[2]??match[1]);
    if(start<1||end>65535||start>end) throw new Error('端口范围必须为 1–65535，且起始端口不大于结束端口');
    return {start,end};
  });
}
function showRanges(ranges?:PortProbeRange[]):string{return ranges?.map(range=>range.start===range.end?String(range.start):`${range.start}-${range.end}`).join(', ')||'无';}
export const TasksPage:React.FC=()=>{
  const {user}=useAuth();const canWrite=!isDemoMode&&(user?.role==='admin'||user?.role==='security_engineer');
  const {data:tasks,setData:setTasks,loading,error}=useCollection('tasks',mockTasks);
  const {data:assets}=useCollection('assets',mockAssets);
  const {data:schedules,loading:scheduleLoading,error:scheduleError}=useCollection('schedules',[]);
  const [open,setOpen]=useState(false);const [busy,setBusy]=useState(false);const [form]=Form.useForm<Values>();
  const engine=Form.useWatch('engine',form)??'synthetic';const mode=Form.useWatch('mode',form);const useWindow=Form.useWatch('window',form);const portPreset=Form.useWatch('portPreset',form)??'common';
  const options=assets.filter(a=>a.kind==='host').flatMap(a=>(a.ports??[]).filter(item=>item.kind==='WEB'||item.kind==='NON_WEB').map(item=>{
    const target=(a.address.includes(':')?'['+a.address+']':a.address)+':'+item.port;
    return {value:target,label:target+'（已审批）'};
  }));
  useEffect(()=>{if(engine==='port-probe'&&mode==='schedule')form.setFieldValue('mode','now');},[engine,mode,form]);
  const create=async(values:Values)=>{
    setBusy(true);
    try{
      const timeWindows=values.window?[{weekdays:values.weekdays,start:values.start,end:values.end,timeZone:values.timeZone}]:[];
      const input:TaskInput=values.engine==='port-probe'
        ?{synthetic:false,engine:'port-probe',assetId:values.assetId,portProbe:{preset:values.portPreset??'common',ranges:values.portPreset==='common'?[]:parsePortRanges(values.portRanges),exclusions:parsePortRanges(values.portExclusions),opsApproved:Boolean(values.opsApproved)},targets:[],timeWindows}
        :{synthetic:values.engine==='synthetic',...(values.engine!=='synthetic'?{engine:values.engine}:{}),...(values.engine==='trivy'?{inputPath:values.inputPath,inputKind:values.inputKind}:values.engine!=='synthetic'?{scheme:values.scheme}:{}),targets:values.engine==='trivy'?[]:values.targets,timeWindows};
      if(values.mode==='schedule'){
        const date=new Date(values.nextRun);if(!Number.isFinite(date.getTime())||date.getTime()<=Date.now()) throw new Error('首次运行时间必须晚于现在');
        await saveSchedule({...input,name:values.name,nextRun:date.toISOString(),intervalMinutes:values.intervalMinutes??0});
        message.success('定时任务已保存，到点由 Server 创建任务');
      }else{const task=await createTask(input);setTasks(prev=>[task,...prev]);message.success(task.status==='WAITING_WINDOW'?'已创建，等待允许的时间窗':'任务已入队');}
      setOpen(false);form.resetFields();
    }catch(e){message.error(e instanceof Error?e.message:'创建失败');}finally{setBusy(false);}
  };
  const stop=async(id:string)=>{try{await cancelTask(id);setTasks(prev=>prev.map(t=>t.id===id?{...t,status:'CANCELED'}:t));message.success('任务已取消，不会写入成功结果');}catch(e){message.error(String(e));}};
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={loading||scheduleLoading} error={error||scheduleError}/>
    <Alert type="info" showIcon message="本地任务与定时调度" description="Nuclei 执行只读 HTTP 基线检查；ZAP 被动分析指定地址的响应；Trivy 离线检查 Linux 系统包、应用依赖或镜像归档。漏洞扫描只使用已登记且已审批的 IP:端口。TCP 端口探测只连接单台已登记主机，不发送应用数据；模拟模式不连接目标。"/>
    <Card title="任务队列" extra={<Button type="primary" icon={<PlusOutlined/>} disabled={!canWrite} onClick={()=>setOpen(true)}>创建任务 / 定时任务</Button>}>
      <Table<ScanTask> dataSource={tasks} rowKey="id" loading={loading} scroll={{x:1000}}
        expandable={{expandedRowRender:t=><Space direction="vertical"><Typography.Text>下发目标：{t.chunks?.flatMap(c=>c.targets).join('、')||'无'}</Typography.Text>{t.engines?.[0]==='port-probe'&&<><Typography.Text>探测配置：{t.portProbeConfig?.preset==='common'?'常用端口':t.portProbeConfig?.preset==='custom'?'自定义范围':'常用端口 + 自定义范围'}；范围 {showRanges(t.portProbeConfig?.ranges)}；排除 {showRanges(t.portProbeConfig?.exclusions)}</Typography.Text><Typography.Text>实际探测：{t.portProbePorts?.length??0} 个 TCP 端口；发现开放候选：{t.portProbeResults?.length?t.portProbeResults.map(p=>p.port).join(', '):t.status==='COMPLETED'?'无':'等待结果'}</Typography.Text><Typography.Text type="secondary">只返回 TCP 连接成功的端口；没有服务识别或漏洞扫描。去资产页可将候选端口提交审批。</Typography.Text></>}{t.inputKind&&<Typography.Text>离线输入：{t.inputKind==='rootfs'?'Linux 系统包':t.inputKind==='image-archive'?'Docker / OCI 镜像':t.inputKind==='artifact'?'已部署 JAR / Go 文件':'应用依赖清单'} · {t.inputPath}</Typography.Text>}<Typography.Text>跳过目标：{t.skippedTargets?.join('、')||'无'}</Typography.Text><Typography.Text>规则版本：{t.ruleVersion||'无需外部规则包'}</Typography.Text>{t.error&&<Alert type="error" message={t.error}/>}</Space>}}
        columns={[
          {title:'任务 ID',dataIndex:'id',width:230,ellipsis:true},
          {title:'执行方式',render:(_,t)=><Tag color={t.synthetic?'default':'blue'}>{t.synthetic?'模拟 Worker':t.engines[0]==='port-probe'?'TCP 端口探测':t.engines.join('、').toUpperCase()}</Tag>},
          {title:'目标 / 探测端口',render:(_,t)=>t.engines[0]==='port-probe'?`${t.targetCount} 台主机 / ${t.portProbePorts?.length??0} 端口`:`${t.targetCount} / ${t.skippedTargets?.length??0}`},
          {title:'进度',render:(_,t)=>`${t.completedChunks} / ${t.totalChunks}`},
          {title:'状态',dataIndex:'status',render:(s:string)=><Tag color={s==='COMPLETED'?'success':s==='RUNNING'?'processing':'default'}>{names[s]??s}</Tag>},
          {title:'本地截止时间',dataIndex:'hardDeadline',render:(v:string)=>v?new Date(v).toLocaleString():'—'},
          {title:'操作',render:(_,t)=><Button size="small" danger disabled={!canWrite||['COMPLETED','CANCELED','FAILED'].includes(t.status)} onClick={()=>void stop(t.id)}>取消任务</Button>},
        ]}/>
    </Card>
    <Card title="定时任务" extra={<Typography.Text type="secondary">间隔 0 表示仅运行一次；错过的重复任务不会集中补跑</Typography.Text>}>
      <Table<Schedule> dataSource={schedules} rowKey="id" scroll={{x:950}} columns={[
        {title:'名称',dataIndex:'name'},
        {title:'下一次运行',dataIndex:'nextRun',render:(v:string)=>new Date(v).toLocaleString()},
        {title:'重复间隔',dataIndex:'intervalMinutes',render:(v:number)=>v?`${v} 分钟`:'仅一次'},
        {title:'状态',render:(_,s)=><Tag color={s.enabled?'green':'default'}>{s.enabled?'启用':'停用 / 单次已触发'}</Tag>},
        {title:'最近任务 / 错误',render:(_,s)=>s.lastError||s.lastTaskId||'尚未触发'},
        {title:'操作',render:(_,s)=><Space><Button size="small" disabled={!canWrite} onClick={async()=>{try{await toggleSchedule(s.id,!s.enabled);message.success('定时任务状态已保存');}catch(e){message.error(String(e));}}}>{s.enabled?'停用':'启用'}</Button><Button size="small" disabled={!canWrite} onClick={async()=>{try{await createTask({synthetic:s.synthetic,engine:s.engine,scheme:s.scheme,inputPath:s.inputPath,inputKind:s.inputKind,targets:s.targets,timeWindows:s.timeWindows});message.success('已另建一条任务，仍遵守时间窗');}catch(e){message.error(String(e));}}}>手动运行</Button></Space>},
      ]}/>
    </Card>
    <Modal title="创建任务" open={open} onCancel={()=>setOpen(false)} onOk={()=>form.submit()} confirmLoading={busy} destroyOnClose>
      <Form<Values> form={form} layout="vertical" onFinish={create} initialValues={{engine:'synthetic',scheme:'http',inputKind:'filesystem',mode:'now',portPreset:'common',portRanges:'',portExclusions:'',opsApproved:false,window:false,weekdays:[0,1,2,3,4,5,6],start:'09:00',end:'18:00',timeZone:'Asia/Shanghai',intervalMinutes:0}}>
        <Form.Item name="engine" label="执行任务"><Select options={[{value:'synthetic',label:'模拟任务（不连接目标）'},{value:'port-probe',label:'TCP 端口探测（单台主机）'},{value:'nuclei',label:'Nuclei · 只读 HTTP 基线'},{value:'zap',label:'ZAP · 被动响应检查'},{value:'trivy',label:'Trivy · Linux 系统 / 应用 / 镜像'}]}/></Form.Item>
        {(engine==='nuclei'||engine==='zap')&&<Form.Item name="scheme" label="Web 协议" rules={[{required:true}]}><Select options={[{value:'http',label:'HTTP'},{value:'https',label:'HTTPS（允许自签名证书）'}]}/></Form.Item>}
        {engine==='trivy'?<><Form.Item name="inputKind" label="输入类型"><Select options={[{value:'rootfs',label:'Linux 系统包快照（rootfs）'},{value:'filesystem',label:'应用依赖清单（lock 文件）'},{value:'artifact',label:'已部署应用 / 中间件（JAR / Go 文件）'},{value:'image-archive',label:'Docker 镜像归档（docker save / OCI tar）'}]}/></Form.Item><Form.Item name="inputPath" label="Worker 本机输入路径" rules={[{required:true}]} extra="相对于 runtime/inputs，例如 lab-a/os、lab-a/apps/web 或 lab-a/images/web.tar。先在 Linux 运行 scripts/collect_linux_inputs.py，再将目录完整复制到 Worker；不通过 SSH 自动采集。"><Input maxLength={240}/></Form.Item><Alert style={{marginBottom:16}} type="info" showIcon message="离线快照仅覆盖采集时的软件包和依赖。重新运行任务不会自动获取服务器的新状态；更新后请先重新采集。容器挂载目录需单独选为应用输入，系统包扫描不等于运行内核验证。"/></>:engine==='port-probe'?<>
          <Form.Item name="assetId" label="已登记主机" rules={[{required:true,message:'请选择一台已登记的主机'}]}><Select showSearch optionFilterProp="label" options={assets.filter(a=>a.kind==='host').map(a=>({value:a.id,label:`${a.address} · ${a.businessGroup}`}))} placeholder="只选择一台主机"/></Form.Item>
          <Form.Item name="portPreset" label="探测范围"><Select options={[{value:'common',label:'常用端口（推荐）'},{value:'custom',label:'仅自定义端口范围'},{value:'common-and-custom',label:'常用端口 + 自定义范围'}]}/></Form.Item>
          {portPreset!=='common'&&<Form.Item name="portRanges" label="自定义 TCP 端口范围" rules={[{validator:(_,value)=>value?.trim()?Promise.resolve():Promise.reject(new Error('此模式至少填写一个端口或端口范围'))}]} extra="英文逗号分隔；可写单端口或起止端口，如 8000-8100, 9000。每次最多选择 1024 个端口。"><Input placeholder="8000-8100, 9000"/></Form.Item>}
          <Form.Item name="portExclusions" label="排除端口或范围" extra="英文逗号分隔，最多 128 段，如 443, 8000-8010。资产中已登记为跳过或隔离的端口也会自动排除。"><Input placeholder="443, 8000-8010"/></Form.Item>
          <Alert style={{marginBottom:16}} type="warning" showIcon message="只对所选主机执行 TCP 连接探测" description="不会发送应用数据、识别服务或自动进行漏洞扫描。若目标配置了 Nginx stream 等四层转发，请把已知转发端口加入排除；不确定时先向运维确认。开放端口只作候选，需提交端口申请并经运维审批后才能用于漏洞扫描。"/>
          <Form.Item name="opsApproved" valuePropName="checked" rules={[{validator:(_,value)=>value?Promise.resolve():Promise.reject(new Error('请确认运维授权和四层转发排除情况'))}]}><Checkbox>我已获得运维对这台主机和所选 TCP 端口范围的探测授权，并已排除已知的 Nginx 四层转发端口</Checkbox></Form.Item>
        </>:<>
        <Form.Item name="targets" label="目标 IP:端口" rules={[{required:true,type:'array',min:1}]} extra="先在资产页面登记目标和端口；被标记跳过的端口会被排除。"><Select mode="multiple" showSearch optionFilterProp="label" options={options} placeholder="选择明确登记的目标"/></Form.Item></>}
        <Form.Item name="mode" label="发起方式"><Select options={[{value:'now',label:'立即入队'},{value:'schedule',label:'定时发起',disabled:engine==='port-probe'}]}/></Form.Item>
        {mode==='schedule'&&<><Form.Item name="name" label="定时任务名称" rules={[{required:true}]}><Input maxLength={100}/></Form.Item><Form.Item name="nextRun" label="首次运行时间" rules={[{required:true}]}><Input type="datetime-local" step={1}/></Form.Item><Form.Item name="intervalMinutes" label="重复间隔（分钟，0 为仅一次）"><InputNumber min={0} max={525600}/></Form.Item></>}
        <Form.Item name="window" label="限制执行时间窗"><Select options={[{value:false,label:'不限时间'},{value:true,label:'使用指定时间窗'}]}/></Form.Item>
        {useWindow&&<><Form.Item name="weekdays" label="允许开始的星期" rules={[{required:true,type:'array',min:1}]}><Select mode="multiple" options={dayOptions}/></Form.Item><Space><Form.Item name="start" label="开始时间" rules={[{required:true}]}><Input placeholder="09:00" maxLength={5}/></Form.Item><Form.Item name="end" label="结束时间（较早表示次日）" rules={[{required:true}]}><Input placeholder="18:00" maxLength={5}/></Form.Item></Space><Form.Item name="timeZone" label="时区" rules={[{required:true}]}><Select options={['Asia/Shanghai','UTC','America/New_York'].map(value=>({value,label:value}))}/></Form.Item></>}
      </Form>
    </Modal>
  </div>;
};
