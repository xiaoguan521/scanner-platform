import React, { useEffect, useState } from 'react';
import { Button, Input, message, Modal, Select, Space, Typography } from 'antd';
import { errorMessage } from '../../api/client';
import { batchAssignFindings, batchFindingDisposition, fetchFindingAssignees } from '../../api/runtime';
import { useAppTheme } from '../../context/ThemeContext';
import { FindingSelection, batchAssignmentSelectionChanged, batchSelectionChanged, batchTransitionAllowed } from './batch';
import { acceptanceInput } from './disposition';
import type { Finding, FindingAssignee, FindingStatus } from '../../types';
const { Text } = Typography;

// Batch disposition and assignment for the rows selected in the flat list.
// The selection stays with the page because it spans pages and filters.
export const BatchBar: React.FC<{
  selection: FindingSelection[];
  onSelectionChange: (selection: FindingSelection[]) => void;
  /** Rows of the current page, used to detect records changed since selection. */
  findings: Finding[];
  canWrite: boolean;
  onBusyChange: (busy: boolean) => void;
  onUpdated: (items: Finding[], kind: 'status' | 'assign') => void;
}> = ({ selection, onSelectionChange, findings, canWrite, onBusyChange, onUpdated }) => {
  const { palette } = useAppTheme();
  const [batchAssignees,setBatchAssignees]=useState<FindingAssignee[]>([]);
  const [batchAssigneeError,setBatchAssigneeError]=useState('');
  useEffect(()=>{
    if(!canWrite){setBatchAssignees([]);setBatchAssigneeError('');return}
    const controller=new AbortController();
    void fetchFindingAssignees(controller.signal).then(result=>{if(!controller.signal.aborted){setBatchAssignees(result.items);setBatchAssigneeError('')}}).catch(()=>{if(!controller.signal.aborted)setBatchAssigneeError('批量指派候选加载失败')});
    return()=>controller.abort();
  },[canWrite]);
  const [batchStatus,setBatchStatus]=useState<FindingStatus>('IN_PROGRESS');
  const [batchOpen,setBatchOpen]=useState(false);
  const [batchReason,setBatchReason]=useState('');
  const [batchUntil,setBatchUntil]=useState('');
  const [batchSaving,setBatchSavingState]=useState(false);
  const setBatchSaving=(value:boolean)=>{setBatchSavingState(value);onBusyChange(value);};
  const [batchAssignOpen,setBatchAssignOpen]=useState(false);
  const [batchAssigneeId,setBatchAssigneeId]=useState('');
  const [batchAssignSaving,setBatchAssignSaving]=useState(false);
  const selectionChanged=batchSelectionChanged(selection,findings,true);
  const batchAllowed=selection.length>0&&selection.length<=100&&!selectionChanged&&selection.every(item=>batchTransitionAllowed(item.expectedStatus,batchStatus));
  const assignmentSelectionChanged=batchAssignmentSelectionChanged(selection,findings,true);
  const batchAssignmentAllowed=canWrite&&selection.length>0&&selection.length<=100&&!assignmentSelectionChanged&&!batchAssigneeError&&batchAssigneeId!=='';
  const saveBatch=async()=>{
    if(!canWrite||!batchAllowed)return;
    try{
      const acceptance=batchStatus==='ACCEPTED_RISK'?acceptanceInput(batchReason,batchUntil):undefined;
      setBatchSaving(true);
      const result=await batchFindingDisposition(selection,batchStatus,acceptance);
      onUpdated(result.items,'status');
      onSelectionChange([]);setBatchOpen(false);setBatchReason('');setBatchUntil('');
      message.success(`已更新 ${result.updated} 项并记录审计`);
    }catch(e){message.error(`${errorMessage(e)}；整批未保存，请核对当前状态后重新选择`)}finally{setBatchSaving(false)}
  };
  const saveBatchAssignment=async()=>{
    if(!batchAssignmentAllowed)return;
    setBatchAssignSaving(true);
    try{
      const result=await batchAssignFindings(selection.map(item=>({id:item.id,expectedAssigneeId:item.expectedAssigneeId??''})),batchAssigneeId);
      onUpdated(result.items,'assign');
      onSelectionChange([]);setBatchAssignOpen(false);setBatchAssigneeId('');
      message.success(`已批量指派 ${result.updated} 项并记录审计`);
    }catch(e){message.error(`${errorMessage(e)}；整批未保存，请核对当前指派状态后重试`)}finally{setBatchAssignSaving(false)}
  };
  return <>
    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center', padding: '12px 20px', borderTop: `1px solid ${palette.borderSubtle}`, borderBottom: `1px solid ${palette.borderSubtle}`, background: selection.length ? palette.bgElevated : undefined }}>
      <Text>已选择 {selection.length} 项（最多 100 项，包含其他分页和筛选中的已选项）</Text>
      <Select aria-label="批量处置状态" value={batchStatus} disabled={batchSaving} onChange={setBatchStatus} style={{width:150}} options={[
        {value:'IN_PROGRESS',label:'标记修复中'}, {value:'FALSE_POSITIVE',label:'标记误报'}, {value:'ACCEPTED_RISK',label:'接受风险'}, {value:'OPEN',label:'恢复待处理'},
      ]}/>
      <Button type="primary" disabled={!canWrite||!batchAllowed||batchSaving} onClick={()=>{setBatchReason('');setBatchUntil('');setBatchOpen(true)}}>批量处置</Button>
      <Select aria-label="批量指派对象" allowClear placeholder="批量指派给" value={batchAssigneeId||undefined} onChange={value=>setBatchAssigneeId(value??'')} disabled={!canWrite||batchAssignSaving||Boolean(batchAssigneeError)} style={{width:150}} options={batchAssignees.map(item=>({value:item.id,label:item.name}))}/>
      <Button disabled={!batchAssignmentAllowed||batchAssignSaving} onClick={()=>setBatchAssignOpen(true)}>批量指派</Button>
      <Button disabled={!selection.length||batchSaving} onClick={()=>onSelectionChange([])}>清空选择</Button>
      {selection.length>0&&!batchAllowed&&<Text type="warning">{selectionChanged?'已选记录状态已变化，请清空后重新选择':'选中记录包含不允许的状态流转，请调整选择或目标状态'}</Text>}
      {selection.length>0&&assignmentSelectionChanged&&<Text type="warning">已选记录的指派状态已变化，请清空后重新选择</Text>}
      {batchAssigneeError&&<Text type="warning">{batchAssigneeError}</Text>}
    </div>
    <Modal title="确认批量处置" open={batchOpen} onCancel={()=>{if(!batchSaving)setBatchOpen(false)}} onOk={()=>void saveBatch()} confirmLoading={batchSaving} okText="确认保存" cancelText="取消" okButtonProps={{disabled:!batchAllowed}} cancelButtonProps={{disabled:batchSaving}} closable={!batchSaving} maskClosable={!batchSaving}>
      <Space direction="vertical" style={{width:'100%'}}>
        <Text>将以下 {selection.length} 项统一更新为 {batchStatus}。任一记录状态发生变化或不允许流转时，整批不保存。</Text>
        <div style={{maxHeight:180,overflowY:'auto',overflowWrap:'anywhere'}}>{selection.map(item=><div key={item.id}><Text code>{item.id}</Text> · {item.expectedStatus}</div>)}</div>
        {batchStatus==='ACCEPTED_RISK'&&<>
          <Input.TextArea aria-label="批量接受风险原因" placeholder="统一接受原因（1–500 UTF-8 字节）" value={batchReason} onChange={e=>setBatchReason(e.target.value)} disabled={batchSaving}/>
          <Input aria-label="批量接受风险到期时间" type="datetime-local" value={batchUntil} onChange={e=>setBatchUntil(e.target.value)} disabled={batchSaving}/>
        </>}
      </Space>
    </Modal>
    <Modal title="确认批量指派" open={batchAssignOpen} onCancel={()=>{if(!batchAssignSaving)setBatchAssignOpen(false)}} onOk={()=>void saveBatchAssignment()} confirmLoading={batchAssignSaving} okText="确认指派" cancelText="取消" okButtonProps={{disabled:!batchAssignmentAllowed}} cancelButtonProps={{disabled:batchAssignSaving}} closable={!batchAssignSaving} maskClosable={!batchAssignSaving}>
      <Space direction="vertical" style={{width:'100%'}}>
        <Text>将以下 {selection.length} 项统一指派给 {batchAssignees.find(item=>item.id===batchAssigneeId)?.name??batchAssigneeId}。任一记录指派状态发生变化时，整批不保存。</Text>
        <div style={{maxHeight:180,overflowY:'auto',overflowWrap:'anywhere'}}>{selection.map(item=><div key={item.id}><Text code>{item.id}</Text> · 当前 {item.expectedAssigneeId||'未指派'}</div>)}</div>
      </Space>
    </Modal>
  </>;
};
