import React, { useEffect, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { TaskStatusTag, taskStatusMeta } from '../../components/Semantic';
import { Alert, Button, Card, Input, message, Modal, Segmented, Select, Space, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { useCollection, useServerCapability } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { pollIntervals } from '../../api/polling';
import { usePageState, useQuery } from '../../api/query';
import { apiClient, errorMessage } from '../../api/client';
import { archiveTask, cancelTask, createTask, deleteSchedule, deleteTask, pauseTask, restoreTask, resumeTask, toggleSchedule } from '../../api/runtime';
import { useAuth } from '../../auth/AuthProvider';
import type { ScanPlan, ScanTask, Schedule } from '../../types';

import { showRanges, coversAllPorts, presetLabels, summarizePorts } from './policy';
import { taskTargetSummary } from './targets';
import { applicationStatuses } from './coverage';
import { TaskDetailDrawer } from './TaskDetailDrawer';
import { ScheduleHistoryModal } from './ScheduleHistoryModal';
import { ScheduleTable } from './ScheduleTable';
import { ScanPlanEditor, type PlanEditorTarget } from './ScanPlanEditor';
import { TaskCreateModal, confirmFull, type TaskCreateRequest } from './TaskCreateModal';
import { renderTaskProgress } from './TaskProgress';
import { formatTime } from '../../utils/time';
const ApplicationCoverage:React.FC<{task:ScanTask}>=({task})=><>
  <Typography.Text>Java / Go 应用：{task.applicationScanStatus?applicationStatuses[task.applicationScanStatus]??'状态未知':'等待 Worker 回报（旧任务未记录应用覆盖）'}</Typography.Text>
  {task.applicationResults?.map(app=><Typography.Text key={app.alias} type={['collection_failed','analysis_failed'].includes(app.status)?'danger':undefined}>应用 {app.alias}：{applicationStatuses[app.status]??'状态未知'}；已分析 {app.analyzedCount} / 选中 {app.selectedCount} 个文件</Typography.Text>)}
</>;
export const TasksPage:React.FC=()=>{
  const {canWrite,isAdmin:canDelete}=useAuth();
  const [showArchived,setShowArchived]=useState(false);
  // Simulated tasks are a local-development capability; hide them unless the Server enables it.
  const syntheticEnabled=useServerCapability('synthetic-worker');
  const {data:assets}=useCollection('assets');
  const {data:scanPlans,setData:setScanPlans,loading:scanPlansLoading,error:scanPlansError}=useCollection('scan-plans');
  const {data:customRules}=useCollection('custom-rules');
  const {data:schedules,setData:setSchedules,loading:scheduleLoading,error:scheduleError}=useCollection('schedules','',true,pollIntervals.schedules);
  const [createRequest,setCreateRequest]=useState<TaskCreateRequest|null>(null);
  const [planTarget,setPlanTarget]=useState<PlanEditorTarget|null>(null);
  const [historySchedule,setHistorySchedule]=useState<Schedule|null>(null);
  const [detailTask,setDetailTask]=useState<ScanTask|null>(null);
  const [taskQuery,setTaskQuery]=useState('');const [taskFilter,setTaskFilter]=useState('');const [statusFilter,setStatusFilter]=useState('all');const [engineFilter,setEngineFilter]=useState('all');const [taskSort,setTaskSort]=useState<'-created_at'|'created_at'>('-created_at');
  const taskListFilters={search:taskFilter,status:statusFilter,engine:engineFilter,archived:(showArchived?'true':'false') as 'true'|'false',sort:taskSort};
  const {page:taskPage,pageSize:taskPageSize,onChange:onTaskPageChange}=usePageState(taskListFilters,10);
  const taskList=useQuery(signal=>apiClient.tasksPage(taskPage,taskPageSize,taskListFilters,signal),[taskPage,taskPageSize,taskListFilters],{pollMs:pollIntervals.activeTask,errorFallback:'扫描任务加载失败',emptyValue:{items:[],total:0,page:1,pageSize:taskPageSize,statusCounts:{}}});
  const tasks=taskList.data?.items??[];const taskTotal=taskList.data?.total??0;const taskStatusCounts=taskList.data?.statusCounts??{};const taskLoading=taskList.loading;const taskError=taskList.error;const reloadTasks=taskList.reload;
  useEffect(()=>{const timer=window.setTimeout(()=>setTaskFilter(taskQuery.trim()),300);return()=>window.clearTimeout(timer);},[taskQuery]);
  // Status counts double as quick filters; QUEUED groups every waiting status.
  const queuedCount=(['PENDING','WAITING_WINDOW','PAUSED_WINDOW'] as const).reduce((sum,status)=>sum+(taskStatusCounts[status]??0),0);
  const statusQuick=[{value:'all',label:showArchived?'全部归档':'全部',count:Object.values(taskStatusCounts).reduce((sum,count)=>sum+count,0)},{value:'RUNNING',label:'执行中',count:taskStatusCounts.RUNNING??0},{value:'QUEUED',label:'待执行',count:queuedCount},{value:'PAUSED',label:'已暂停',count:taskStatusCounts.PAUSED??0},{value:'COMPLETED',label:'已完成',count:taskStatusCounts.COMPLETED??0},{value:'FAILED',label:'失败',count:taskStatusCounts.FAILED??0}];
  const openPlanEditor=(plan:ScanPlan,copy:boolean)=>{
    if(!canWrite){message.info('当前账号没有管理自定义扫描方案的权限');return;}
    setPlanTarget({plan,copy});
  };
  const stop=async(id:string)=>{try{await cancelTask(id);reloadTasks();message.success('任务已取消，不会写入成功结果');}catch(e){message.error(errorMessage(e));}};
  const pause=async(task:ScanTask)=>Modal.confirm({title:'暂停扫描任务',content:`暂停 ${task.id} 后，Worker 会在下一次心跳停止执行，任务不会因时间窗自动恢复。之后可在详情中手动恢复。`,okText:'暂停',cancelText:'继续执行',onOk:async()=>{try{await pauseTask(task.id);reloadTasks();setDetailTask(prev=>prev?.id===task.id?{...prev,status:'PAUSED'}:prev);message.success('任务已暂停');}catch(e){message.error(errorMessage(e));throw e;}}});
  const resume=async(task:ScanTask)=>{try{const updated=await resumeTask(task.id);reloadTasks();setDetailTask(prev=>prev?.id===task.id?{...prev,status:updated.status}:prev);message.success('任务已恢复到队列，平台会重新校验时间窗和规则状态');}catch(e){message.error(errorMessage(e));}};
  const openTaskDetail=(task:ScanTask)=>setDetailTask(task);
  const setArchived=async(id:string,archived:boolean)=>{try{if(archived)await archiveTask(id);else await restoreTask(id);reloadTasks();message.success(archived?'任务已归档':'任务已恢复到清册');}catch(e){message.error(errorMessage(e));}};
  const removeTask=(task:ScanTask)=>Modal.confirm({title:'彻底删除扫描任务',content:`将永久删除任务 ${task.id}。仅允许删除已结束且没有关联发现项的任务；此操作不可撤销，已生成报告快照和审计记录会保留。`,okText:'彻底删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteTask(task.id);reloadTasks();message.success('扫描任务已彻底删除');}catch(e){message.error(errorMessage(e));throw e;}}});
  const removeSchedule=(schedule:Schedule)=>Modal.confirm({title:'删除定时任务',content:`删除“${schedule.name}”后将停止后续调度，已创建的扫描任务和结果会保留。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteSchedule(schedule.id);setSchedules(prev=>prev.filter(item=>item.id!==schedule.id));message.success('定时任务已删除');}catch(cause){message.error(errorMessage(cause,'删除失败'));throw cause;}}});
  const toggleScheduleEnabled=async(s:Schedule)=>{try{await toggleSchedule(s.id,!s.enabled);setSchedules(prev=>prev.map(item=>item.id===s.id?{...item,enabled:!s.enabled}:item));message.success('定时任务状态已保存');}catch(e){message.error(errorMessage(e));}};
  const runScheduleNow=async(s:Schedule)=>{if(s.portProbe&&(s.portProbe.preset==='full'||coversAllPorts(s.portProbe.ranges??[]))&&!(await confirmFull()))return;try{await createTask({synthetic:s.synthetic,engine:s.engine,scheme:s.scheme,inputPath:s.inputPath,inputKind:s.inputKind,assetId:s.assetId,portProbe:s.portProbe,customRuleIds:s.customRuleIds,targets:s.targets,timeWindows:s.timeWindows});message.success('已另建一条任务，仍遵守时间窗');}catch(e){message.error(errorMessage(e));}};
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={taskLoading||scheduleLoading||scanPlansLoading} error={taskError||scheduleError||scanPlansError} hasData={tasks.length>0||schedules.length>0}/>
    <Card title="扫描任务" extra={<Space wrap>
      <Button type="primary" icon={<PlusOutlined/>} disabled={!canWrite} onClick={()=>setCreateRequest({kind:'new',mode:'now'})}>创建扫描任务</Button>
      <Button disabled={!canWrite} onClick={()=>setCreateRequest({kind:'new',mode:'schedule'})}>创建定时任务</Button>
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
          {title:'创建时间',dataIndex:'createdAt',width:180,sorter:true,sortDirections:['descend','ascend'],sortOrder:taskSort==='created_at'?'ascend':'descend',render:(v:string)=>formatTime(v,'—')},
          {title:'本地截止时间',dataIndex:'hardDeadline',width:190,render:(v:string)=>formatTime(v,'—')},
          {title:'操作',width:470,render:(_,t)=>{const terminal=['COMPLETED','CANCELED','FAILED'].includes(t.status);return <Space wrap><Button size="small" onClick={()=>openTaskDetail(t)}>详情</Button>{!terminal&&t.status!=='PAUSED'&&<Button size="small" disabled={!canWrite} onClick={()=>void pause(t)}>暂停</Button>}{t.status==='PAUSED'&&<Button size="small" type="primary" disabled={!canWrite} onClick={()=>void resume(t)}>恢复</Button>}{!terminal&&<Button size="small" danger disabled={!canWrite} onClick={()=>void stop(t.id)}>取消</Button>}{terminal&&<Button size="small" disabled={!canWrite} onClick={()=>void setArchived(t.id,!t.archived)}>{t.archived?'恢复':'归档'}</Button>}{terminal&&<Button size="small" disabled={!canWrite} onClick={()=>setCreateRequest({kind:'copy',task:t})}>按此配置新建</Button>}{terminal&&canDelete&&t.findingCount===0&&<Button size="small" danger onClick={()=>removeTask(t)}>彻底删除</Button>}{terminal&&canDelete&&t.findingCount>0&&<Tag>有关联发现，仅可归档</Tag>}</Space>}},
        ]}/>
    </Card>
    <TaskDetailDrawer task={detailTask} onTaskChange={setDetailTask} onClose={()=>setDetailTask(null)} canWrite={canWrite} onPause={task=>void pause(task)} onResume={task=>void resume(task)} onStop={id=>void stop(id)}/>
    <ScheduleTable schedules={schedules} loading={scheduleLoading} canWrite={canWrite} onToggle={s=>void toggleScheduleEnabled(s)} onRunNow={s=>void runScheduleNow(s)} onHistory={setHistorySchedule} onEdit={schedule=>setCreateRequest({kind:'schedule',schedule})} onRemove={removeSchedule}/>
    <TaskCreateModal request={createRequest} onClose={()=>setCreateRequest(null)} canWrite={canWrite} syntheticEnabled={syntheticEnabled} assets={assets} scanPlans={scanPlans} setScanPlans={setScanPlans} customRules={customRules} setSchedules={setSchedules} onTaskCreated={reloadTasks} onEditPlan={openPlanEditor}/>
    <ScanPlanEditor target={planTarget} customRules={customRules} onClose={()=>setPlanTarget(null)} onSaved={(saved,replaced)=>setScanPlans(prev=>replaced?prev.map(item=>item.id===saved.id?saved:item):[...prev,saved])}/>
    <ScheduleHistoryModal schedule={historySchedule} onClose={()=>setHistorySchedule(null)}/>
  </div>;
};
