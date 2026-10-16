import React, { useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { isDemoMode } from '../../api/client';
import { cancelTask, createTask, saveSchedule, toggleSchedule } from '../../api/runtime';
import { useAuth } from '../../auth/AuthProvider';
import { mockAssets, mockTasks } from '../../mock/data';
import type { ScanTask, Schedule, TaskInput } from '../../types';

const dayOptions=['周日','周一','周二','周三','周四','周五','周六'].map((label,value)=>({label,value}));
const names:Record<string,string>={PENDING:'待领取',RUNNING:'执行中',WAITING_WINDOW:'等待时间窗',PAUSED_WINDOW:'窗口结束，等待恢复',COMPLETED:'已完成',CANCELED:'已取消',FAILED:'失败'};
type Values={engine:'synthetic'|'nuclei'|'trivy'|'zap';scheme:'http'|'https';inputPath:string;inputKind:'filesystem'|'image-archive';targets:string[];mode:'now'|'schedule';name:string;nextRun:string;intervalMinutes:number;window:boolean;weekdays:number[];start:string;end:string;timeZone:string};
export const TasksPage:React.FC=()=>{
  const {user}=useAuth();const canWrite=!isDemoMode&&(user?.role==='admin'||user?.role==='security_engineer');
  const {data:tasks,setData:setTasks,loading,error}=useCollection('tasks',mockTasks);
  const {data:assets}=useCollection('assets',mockAssets);
  const {data:schedules,loading:scheduleLoading,error:scheduleError}=useCollection('schedules',[]);
  const [open,setOpen]=useState(false);const [busy,setBusy]=useState(false);const [form]=Form.useForm<Values>();
  const engine=Form.useWatch('engine',form)??'synthetic';const mode=Form.useWatch('mode',form);const useWindow=Form.useWatch('window',form);
  const options=assets.filter(a=>a.kind==='host').flatMap(a=>(a.requestedPorts??[]).map(port=>{
    const target=(a.address.includes(':')?'['+a.address+']':a.address)+':'+port;
    return {value:target,label:target+((a.skippedPorts??[]).includes(port)?'（已标记跳过）':'')};
  }));
  const create=async(values:Values)=>{
    setBusy(true);
    try{
      const input:TaskInput={synthetic:values.engine==='synthetic',...(values.engine!=='synthetic'?{engine:values.engine}:{}),...(values.engine==='trivy'?{inputPath:values.inputPath,inputKind:values.inputKind}:values.engine!=='synthetic'?{scheme:values.scheme}:{}),targets:values.engine==='trivy'?[]:values.targets,timeWindows:values.window?[{weekdays:values.weekdays,start:values.start,end:values.end,timeZone:values.timeZone}]:[]};
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
    <Alert type="info" showIcon message="本地任务与定时调度" description="Nuclei 执行只读 HTTP 基线检查；ZAP 被动分析指定地址的响应；Trivy 离线检查 Worker 本机目录或镜像归档。网络检查只下发已登记的 IP:端口，排除跳过和隔离端口；模拟模式不连接目标。"/>
    <Card title="任务队列" extra={<Button type="primary" icon={<PlusOutlined/>} disabled={!canWrite} onClick={()=>setOpen(true)}>创建任务 / 定时任务</Button>}>
      <Table<ScanTask> dataSource={tasks} rowKey="id" loading={loading} scroll={{x:1000}}
        expandable={{expandedRowRender:t=><Space direction="vertical"><Typography.Text>下发目标：{t.chunks?.flatMap(c=>c.targets).join('、')||'无'}</Typography.Text><Typography.Text>跳过目标：{t.skippedTargets?.join('、')||'无'}</Typography.Text><Typography.Text>规则版本：{t.ruleVersion||'无需外部规则包'}</Typography.Text>{t.error&&<Alert type="error" message={t.error}/>}</Space>}}
        columns={[
          {title:'任务 ID',dataIndex:'id',width:230,ellipsis:true},
          {title:'执行方式',render:(_,t)=><Tag color={t.synthetic?'default':'blue'}>{t.synthetic?'模拟 Worker':t.engines.join('、').toUpperCase()}</Tag>},
          {title:'目标 / 跳过',render:(_,t)=>`${t.targetCount} / ${t.skippedTargets?.length??0}`},
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
      <Form<Values> form={form} layout="vertical" onFinish={create} initialValues={{engine:'synthetic',scheme:'http',inputKind:'filesystem',mode:'now',window:false,weekdays:[0,1,2,3,4,5,6],start:'09:00',end:'18:00',timeZone:'Asia/Shanghai',intervalMinutes:0}}>
        <Form.Item name="engine" label="执行引擎"><Select options={[{value:'synthetic',label:'模拟任务（不连接目标）'},{value:'nuclei',label:'Nuclei · 只读 HTTP 基线'},{value:'zap',label:'ZAP · 被动响应检查'},{value:'trivy',label:'Trivy · 本机依赖 / 镜像归档'}]}/></Form.Item>
        {(engine==='nuclei'||engine==='zap')&&<Form.Item name="scheme" label="Web 协议" rules={[{required:true}]}><Select options={[{value:'http',label:'HTTP'},{value:'https',label:'HTTPS（允许自签名证书）'}]}/></Form.Item>}
        {engine==='trivy'?<><Form.Item name="inputKind" label="输入类型"><Select options={[{value:'filesystem',label:'依赖目录'},{value:'image-archive',label:'镜像归档（docker save / OCI tar）'}]}/></Form.Item><Form.Item name="inputPath" label="Worker 本机输入路径" rules={[{required:true}]} extra="相对于 runtime/inputs，例如 deps/my-project 或 images/app.tar。先把文件放到 Worker；不拉取远程镜像，不通过 SSH 扫描服务器。"><Input maxLength={240}/></Form.Item></>:<>
        <Form.Item name="targets" label="目标 IP:端口" rules={[{required:true,type:'array',min:1}]} extra="先在资产页面登记目标和端口；被标记跳过的端口会被排除。"><Select mode="multiple" showSearch optionFilterProp="label" options={options} placeholder="选择明确登记的目标"/></Form.Item></>}
        <Form.Item name="mode" label="发起方式"><Select options={[{value:'now',label:'立即入队'},{value:'schedule',label:'定时发起'}]}/></Form.Item>
        {mode==='schedule'&&<><Form.Item name="name" label="定时任务名称" rules={[{required:true}]}><Input maxLength={100}/></Form.Item><Form.Item name="nextRun" label="首次运行时间" rules={[{required:true}]}><Input type="datetime-local" step={1}/></Form.Item><Form.Item name="intervalMinutes" label="重复间隔（分钟，0 为仅一次）"><InputNumber min={0} max={525600}/></Form.Item></>}
        <Form.Item name="window" label="限制执行时间窗"><Select options={[{value:false,label:'不限时间'},{value:true,label:'使用指定时间窗'}]}/></Form.Item>
        {useWindow&&<><Form.Item name="weekdays" label="允许开始的星期" rules={[{required:true,type:'array',min:1}]}><Select mode="multiple" options={dayOptions}/></Form.Item><Space><Form.Item name="start" label="开始时间" rules={[{required:true}]}><Input placeholder="09:00" maxLength={5}/></Form.Item><Form.Item name="end" label="结束时间（较早表示次日）" rules={[{required:true}]}><Input placeholder="18:00" maxLength={5}/></Form.Item></Space><Form.Item name="timeZone" label="时区" rules={[{required:true}]}><Select options={['Asia/Shanghai','UTC','America/New_York'].map(value=>({value,label:value}))}/></Form.Item></>}
      </Form>
    </Modal>
  </div>;
};
