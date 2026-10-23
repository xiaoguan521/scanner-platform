import React, { useEffect, useState } from 'react';
import { Alert, Button, Descriptions, Drawer, Input, message, Modal, Select, Space, Tag, Timeline, Typography, theme } from 'antd';
import type { Finding, FindingAssignee, FindingAssignmentEvent, FindingEvent, FindingNote, FindingRetest, FindingStatus } from '../../types';
import { FindingStatusTag, SeverityTag } from '../../components/Semantic';
import { addFindingNote, assignFinding, createFindingRetest, fetchFindingAssignees, fetchFindingAssignments, fetchFindingEvents, fetchFindingNotes, fetchFindingRetests } from '../../api/runtime';
import { errorMessage } from '../../api/client';
import { pollWhileVisible } from '../../api/polling';
import { confidenceLabels, methodLabels, riskLabels } from './presentation';
import { detailIdentifiers, detailList, detailText } from './drawer';
import { acceptanceInput, canAcceptRisk } from './disposition';
import { findingNoteInput } from './work';
import { retestIsActive, retestStatusLabel } from './retest';
const { Text } = Typography;

// Detail drawer: loads the finding's history, notes, assignees and retests
// itself. Status changes go through the page so the list updates in place.
export const FindingDrawer: React.FC<{
  selectedFinding: Finding | null;
  canWrite: boolean;
  saving: boolean;
  /** Bumped by the page after status changes so the history reloads. */
  eventRevision: number;
  onClose: () => void;
  afterOpenChange: (open: boolean) => void;
  onUpdateStatus: (id: string, status: FindingStatus, acceptance?: { reason: string; acceptedUntil: string }) => Promise<void>;
  onFindingUpdated: (finding: Finding) => void;
}> = ({ selectedFinding, canWrite, saving, eventRevision, onClose, afterOpenChange, onUpdateStatus: handleUpdateStatus, onFindingUpdated }) => {
  const { token } = theme.useToken();
  const selectedFindingId = selectedFinding?.id ?? null;
  const [acceptReason,setAcceptReason]=useState('');
  const [acceptUntil,setAcceptUntil]=useState('');
  const [events,setEvents]=useState<FindingEvent[]>([]);
  const [eventsError,setEventsError]=useState('');
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

  // Start from the saved assignee each time another finding opens.
  useEffect(() => { setAssigneeId(selectedFinding?.assigneeId ?? ''); }, [selectedFindingId]);
  const saveAssignment=async(id:string)=>{
    setWorkSaving(true);
    try{const item=await assignFinding(id,assigneeId);onFindingUpdated(item);setWorkRevision(n=>n+1);message.success('指派已保存并记录审计')}
    catch(e){message.error(errorMessage(e))}finally{setWorkSaving(false)}
  };
  const saveNote=async(id:string)=>{
    try{const body=findingNoteInput(noteBody);setWorkSaving(true);await addFindingNote(id,body);setWorkRevision(n=>n+1);message.success('备注已追加并记录审计')}
    catch(e){message.error(errorMessage(e))}finally{setWorkSaving(false)}
  };

  const startRetest=async(id:string)=>{
    Modal.confirm({
      title:'确认重新扫描该漏洞？',
      content:'平台会复用原扫描任务的冻结目标和授权范围，并创建一条新的扫描任务。',
      okText:'创建复测任务',cancelText:'取消',
      onOk:async()=>{
        setRetestSaving(true);
        try{const result=await createFindingRetest(id);setRetests(previous=>[...previous,result.retest]);setRetestRevision(n=>n+1);message.success(`复测任务已创建：${result.task.id}`)}
        catch(e){message.error(errorMessage(e));throw e}
        finally{setRetestSaving(false)}
      },
    });
  };

  return (
    <Drawer
      title="发现项详情"
      open={Boolean(selectedFinding)}
      onClose={onClose}
      afterOpenChange={afterOpenChange}
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
              <Button loading={saving} disabled={!canWrite} onClick={()=>{try{void handleUpdateStatus(selectedFinding.id,'ACCEPTED_RISK',acceptanceInput(acceptReason,acceptUntil))}catch(e){message.error(errorMessage(e,'接受风险输入无效'))}}}>接受风险</Button>
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
  );
};
