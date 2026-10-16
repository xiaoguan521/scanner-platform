import React, { useState } from 'react';
import { Alert, Button, Card, Form, Input, message, Modal, Space, Table, Tag, Typography } from 'antd';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';
import { isDemoMode } from '../../api/client';
import { activateRules, fetchRules, importRules } from '../../api/runtime';
import { mockNodes, mockRuleBundles } from '../../mock/data';
import type { NodeInfo, RuleBundle, RuleJob } from '../../types';

export const NodesPage:React.FC=()=>{
  const {user}=useAuth();const canWrite=!isDemoMode&&(user?.role==='admin'||user?.role==='security_engineer');
  const {data:nodes,loading,error}=useCollection('nodes',mockNodes);
  const {data:bundles,error:bundleError}=useCollection('rules',mockRuleBundles);
  const {data:jobs,error:jobError}=useCollection('rule-jobs',[]);
  const [file,setFile]=useState<File|null>(null);const [busy,setBusy]=useState(false);const [fetchOpen,setFetchOpen]=useState(false);const [form]=Form.useForm();
  const run=async(action:()=>Promise<unknown>)=>{setBusy(true);try{await action();message.success('操作已排队，等待本地 Updater 处理；请查看操作记录');return true;}catch(e){message.error(e instanceof Error?e.message:String(e));return false;}finally{setBusy(false);}};
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={loading} error={error||bundleError||jobError}/>
    <Alert type="info" showIcon message="本地节点与规则包" description="Worker 和 Updater 通过本机 API 工作，只有 Updater 写入规则目录。导入检查 ZIP 路径、manifest 和文件 SHA-256；当前未验签；真实任务在执行前校验固定规则版本。引擎程序由 make engines 安装，只有明确创建的真实任务才会连接目标。"/>
    <Card title="节点心跳"><Table<NodeInfo> dataSource={nodes} rowKey="id" pagination={false} scroll={{x:850}} columns={[
      {title:'节点',dataIndex:'id'},{title:'类型',dataIndex:'kind'},
      {title:'状态',dataIndex:'status',render:(v:string)=><Tag color={v==='OFFLINE'?'default':'green'}>{v==='BUSY'?'处理中':v==='ONLINE'?'在线':'离线'}</Tag>},
      {title:'当前任务',dataIndex:'currentTask',ellipsis:true},
      {title:'最近心跳',dataIndex:'lastHeartbeat',render:(v:string)=>new Date(v).toLocaleString()},
      {title:'运行模式',render:()=> <Tag>本机开发 · 未启用网络围栏</Tag>},
    ]}/></Card>
    <Card title="扫描引擎"><Table dataSource={nodes.flatMap(n=>(n.engines??[]).map(e=>({...e,nodeId:n.id,online:n.status!=='OFFLINE'})))} rowKey={e=>e.nodeId+'-'+e.name} pagination={false} columns={[{title:'引擎',dataIndex:'name',render:(v:string)=>v.toUpperCase()},{title:'固定版本',dataIndex:'version'},{title:'节点',dataIndex:'nodeId'},{title:'状态',render:(_,e)=><Tag color={e.online&&e.ready?'green':'default'}>{!e.online?'节点离线':e.ready?'本地就绪':e.installed?'缺少数据 / 运行环境':'未安装'}</Tag>},{title:'说明',dataIndex:'message'}]}/></Card>
    <Card title="规则包版本" extra={<Space wrap><input aria-label="选择离线规则包" type="file" accept=".zip" disabled={!canWrite} onChange={e=>setFile(e.target.files?.[0]??null)}/><Button disabled={!canWrite||!file} loading={busy} onClick={()=>void run(()=>importRules(file!))}>离线导入 ZIP</Button><Button disabled={!canWrite} onClick={()=>setFetchOpen(true)}>从规则源下载</Button></Space>}>
      <Typography.Paragraph type="secondary">ZIP 须包含 manifest.json 和 nuclei/、trivy/ 下声明的规则文件。下载后或离线导入后，点击“激活”切换当前版本。</Typography.Paragraph>
      <Table<RuleBundle> dataSource={bundles} rowKey="version" scroll={{x:1000}} columns={[
        {title:'版本',dataIndex:'version',render:(v:string,b)=><Space><Typography.Text strong>{v}</Typography.Text>{b.isCurrent&&<Tag color="success">CURRENT</Tag>}</Space>},
        {title:'引擎数据',render:(_,b)=>b.engines?.join('、')||'—'},
        {title:'完整性 / 引擎验证',render:(_,b)=><Space direction="vertical"><Tag>{b.integrityVerified?'文件哈希已验证':'未验证'}</Tag><Typography.Text type="secondary">未验签 · 引擎兼容性未验证</Typography.Text></Space>},
        {title:'Manifest SHA-256',dataIndex:'manifestSha256',ellipsis:true},
        {title:'导入时间',dataIndex:'publishedAt',render:(v:string)=>new Date(v).toLocaleString()},
        {title:'操作',render:(_,b)=><Space><Button disabled={!canWrite||b.isCurrent} loading={busy} onClick={()=>void run(()=>activateRules(b.version,false))}>激活</Button><Button danger disabled={!canWrite||b.isCurrent} onClick={()=>Modal.confirm({title:'显式回滚到 '+b.version+'？',content:'将切换本地规则指针并记录审计。当前不会启动扫描。',onOk:()=>run(()=>activateRules(b.version,true))})}>显式回滚</Button></Space>},
      ]}/>
    </Card>
    <Card title="规则操作记录"><Table<RuleJob> dataSource={jobs} rowKey="id" scroll={{x:950}} columns={[
      {title:'操作',dataIndex:'kind',render:(v:string)=>({IMPORT:'离线导入',FETCH:'下载导入',ACTIVATE:'版本切换'}[v]??v)},
      {title:'版本',dataIndex:'version'},{title:'状态',dataIndex:'status',render:(v:string)=><Tag color={v==='FAILED'?'error':v==='COMPLETED'?'success':'processing'}>{v}</Tag>},
      {title:'说明',dataIndex:'message'},{title:'提交时间',dataIndex:'createdAt',render:(v:string)=>new Date(v).toLocaleString()},
    ]}/></Card>
    <Modal title="从指定规则源下载 ZIP" open={fetchOpen} onCancel={()=>setFetchOpen(false)} onOk={()=>form.submit()} confirmLoading={busy}>
      <Form form={form} layout="vertical" onFinish={async(v:{url:string;expectedSha256:string})=>{if(await run(()=>fetchRules(v.url,v.expectedSha256))) setFetchOpen(false);}}>
        <Form.Item name="url" label="HTTPS ZIP 地址" rules={[{required:true,type:'url'}]} extra="不允许 URL 内携带账号、密码、查询参数；不自动发现规则源。"><Input placeholder="https://rules.example.com/bundle.zip"/></Form.Item>
        <Form.Item name="expectedSha256" label="ZIP 的 SHA-256" rules={[{required:true,pattern:/^[a-fA-F0-9]{64}$/,message:'请输入 64 位十六进制 SHA-256'}]}><Input maxLength={64}/></Form.Item>
      </Form>
    </Modal>
  </div>;
};
