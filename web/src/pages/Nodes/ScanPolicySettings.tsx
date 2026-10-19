import React, { useEffect, useState } from 'react';
import { Alert, Button, Card, Form, Input, InputNumber, message, Space, Tag, Typography } from 'antd';
import { apiClient, isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { useAuth } from '../../auth/AuthProvider';
import { parsePortRanges, showRanges, compressPorts, expandPortRanges } from '../Tasks/policy';
import type { ScanPolicy } from '../../types';

type PolicyValues={commonPortsText:string;exclusionsText:string;quarantineThreshold:number};
export const ScanPolicySettings:React.FC=()=>{
  const {user}=useAuth();const canEdit=!isDemoMode&&user?.role==='admin';const [form]=Form.useForm<PolicyValues>();
  const [policy,setPolicy]=useState<ScanPolicy|null>(null);const [error,setError]=useState('');const [busy,setBusy]=useState(false);
  const {data:capabilities,error:capabilityError}=useCollection('detection-capabilities',[]);
  const apply=(next:ScanPolicy)=>{setPolicy(next);form.setFieldsValue({commonPortsText:compressPorts(next.commonPorts),exclusionsText:showRanges(next.exclusions)==='无'?'':showRanges(next.exclusions),quarantineThreshold:next.quarantineThreshold});};
  useEffect(()=>{if(isDemoMode)return;let active=true;apiClient.scanPolicy().then(p=>{if(active)apply(p);}).catch(e=>{if(active)setError(e instanceof Error?e.message:'策略读取失败');});return()=>{active=false;};},[]);
  const save=async(values:PolicyValues)=>{setBusy(true);try{
    const ranges=parsePortRanges(values.commonPortsText);if(!ranges.length)throw new Error('常见端口至少包含一个端口');
    const commonPorts=expandPortRanges(values.commonPortsText);
    const saved=await apiClient.saveScanPolicy({commonPorts,exclusions:parsePortRanges(values.exclusionsText),quarantineThreshold:values.quarantineThreshold,discoveryAttempts:3});apply(saved);setError('');message.success('系统扫描策略已保存；新建任务将冻结新策略');
  }catch(e){message.error(e instanceof Error?e.message:'保存失败');}finally{setBusy(false);}};
  const validateRanges=(_:unknown,value:string)=>{try{parsePortRanges(value);return Promise.resolve();}catch(e){return Promise.reject(e);}};
  return <>
    <Card title="检测能力状态"><Space wrap>{capabilities.map(c=><Tag key={c.id} color={c.status==='enabled'?'green':'default'} title={c.message}>{c.name}：{c.status==='enabled'?'已启用':c.status==='disabled'?'未启用':'未提供'}</Tag>)}{!capabilities.some(c=>c.id==='weak_credential')&&<Tag>弱口令：本次未启用该检测项</Tag>}</Space>{capabilityError&&<Typography.Paragraph type="danger">{capabilityError}</Typography.Paragraph>}</Card>
    <Card title="系统扫描策略" extra={<Tag>{canEdit?'管理员可编辑':'只读'}</Tag>}>
      <Alert style={{marginBottom:16}} type={error?'error':'info'} showIcon message={error||'系统默认排除优先应用于所有新任务'} description="系统、资产与任务的排除端口取并集，并跳过活动隔离端口。保存策略不会改变已经创建任务的冻结配置。每端口识别最多 3 次。"/>
      {isDemoMode?<Typography.Text type="secondary">演示模式不读取或修改系统扫描策略。</Typography.Text>:<Form form={form} layout="vertical" onFinish={save} disabled={!canEdit||!policy}>
        <Form.Item name="commonPortsText" label="常见 TCP 端口清单" rules={[{required:true,message:'至少填写一个常见端口'},{validator:validateRanges}]} extra="支持端口或范围，英文逗号分隔；任务页从此策略读取清单。"><Input.TextArea rows={3} placeholder="例如 22, 80, 443, 8000-8010"/></Form.Item>
        <Form.Item name="exclusionsText" label="系统默认排除端口" rules={[{validator:validateRanges}]} extra="初始为空。被排除的端口不会进行连接、服务识别或漏洞检测。"><Input placeholder="例如 3306, 9000-9100"/></Form.Item>
        <Form.Item name="quarantineThreshold" label="疑似转发隔离阈值" rules={[{required:true}]} extra="达到阈值时保留开放信息并隔离；人工核查后由管理员解除。"><InputNumber min={1} max={3} precision={0}/></Form.Item>
        <Button type="primary" htmlType="submit" disabled={!canEdit||!policy} loading={busy}>保存系统策略</Button>
      </Form>}
    </Card>
  </>;
};
