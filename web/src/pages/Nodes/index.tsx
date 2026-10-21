import React, { useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Tag, Typography } from 'antd';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';
import { activateRules, createCustomRule, deleteCustomRule, fetchRules, importRules, updateCustomRule } from '../../api/runtime';
import type { CustomRule, NodeInfo, RuleBundle, RuleJob } from '../../types';

import { ScanPolicySettings } from './ScanPolicySettings';
type CustomRuleForm={id:string;name:string;severity:CustomRule['severity'];description:string;matchType:CustomRule['matchType'];part:'header'|'body';valuesText:string;statusCodesText:string;enabled:boolean};

export const NodesPage:React.FC=()=>{
  const {user}=useAuth();const canWrite=user?.role==='admin'||user?.role==='security_engineer';
  const {data:nodes,loading,error}=useCollection('nodes');
  const {data:bundles,error:bundleError}=useCollection('rules');
  const {data:jobs,error:jobError}=useCollection('rule-jobs');
  const {data:customRules,setData:setCustomRules,loading:customRulesLoading,error:customRulesError}=useCollection('custom-rules');
  const [file,setFile]=useState<File|null>(null);const [busy,setBusy]=useState(false);const [fetchOpen,setFetchOpen]=useState(false);const [form]=Form.useForm();
  const [ruleOpen,setRuleOpen]=useState(false);const [editingRule,setEditingRule]=useState<CustomRule|null>(null);const [ruleForm]=Form.useForm<CustomRuleForm>();
  const ruleMatchType=Form.useWatch('matchType',ruleForm)??'word';
  const run=async(action:()=>Promise<unknown>)=>{setBusy(true);try{await action();message.success('操作已排队，等待本地 Updater 处理；请查看操作记录');return true;}catch(e){message.error(e instanceof Error?e.message:String(e));return false;}finally{setBusy(false);}};
  const saveRule=async(values:CustomRuleForm)=>{setBusy(true);try{const input:Omit<CustomRule,'template'>={id:values.id.trim().toLowerCase(),name:values.name.trim(),severity:values.severity,description:values.description??'',matchType:values.matchType,enabled:values.enabled??true,...(values.matchType==='status'?{statusCodes:values.statusCodesText.split(',').map(v=>Number(v.trim()))}:{part:values.part,values:values.valuesText.split('\n').map(v=>v.trim()).filter(Boolean)})};const saved=editingRule?await updateCustomRule(editingRule.id,input):await createCustomRule(input);setCustomRules(prev=>editingRule?prev.map(item=>item.id===saved.id?saved:item):[saved,...prev]);message.success(editingRule?'自定义规则已更新':'自定义规则已创建');setRuleOpen(false);setEditingRule(null);ruleForm.resetFields();}catch(e){message.error(e instanceof Error?e.message:String(e));}finally{setBusy(false);}};
  const editRule=(rule:CustomRule)=>{setEditingRule(rule);ruleForm.setFieldsValue({id:rule.id,name:rule.name,severity:rule.severity,description:rule.description,matchType:rule.matchType,part:rule.part??'body',valuesText:rule.values?.join('\n')??'',statusCodesText:rule.statusCodes?.join(', ')??'',enabled:rule.enabled});setRuleOpen(true);};
  const removeRule=(rule:CustomRule)=>Modal.confirm({title:'删除自定义规则',content:`删除“${rule.name}”后新建任务将不再使用它；已创建任务保留创建时的规则快照。`,okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{try{await deleteCustomRule(rule.id);setCustomRules(prev=>prev.filter(item=>item.id!==rule.id));message.success('自定义规则已删除');}catch(e){message.error(e instanceof Error?e.message:String(e));throw e;}}});
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={loading||customRulesLoading} error={error||bundleError||jobError||customRulesError}/>
    <Alert type="info" showIcon message="本地节点与规则包" description="Worker 和 Updater 通过本机 API 工作，只有 Updater 写入规则目录。外部规则包导入和激活需要受信任公钥验证签名，并检查文件 SHA-256；未验签的历史版本可查看，不能通过此页面激活。真实任务在执行前校验固定规则版本。"/>
    <ScanPolicySettings/>
    <Card title="节点心跳"><DataTable<NodeInfo> dataSource={nodes} rowKey="id" pagination={false} scroll={{x:850}} columns={[
      {title:'节点',dataIndex:'id'},{title:'类型',dataIndex:'kind'},
      {title:'状态',dataIndex:'status',render:(v:string)=><Tag color={v==='OFFLINE'?'default':'green'}>{v==='BUSY'?'处理中':v==='ONLINE'?'在线':'离线'}</Tag>},
      {title:'当前任务',dataIndex:'currentTask',ellipsis:true},
      {title:'最近心跳',dataIndex:'lastHeartbeat',render:(v:string)=>new Date(v).toLocaleString()},
      {title:'运行模式',render:()=> <Tag>本机开发 · 未启用网络围栏</Tag>},
    ]}/></Card>
    <Card title="扫描引擎"><DataTable dataSource={nodes.flatMap(n=>(n.engines??[]).map(e=>({...e,nodeId:n.id,online:n.status!=='OFFLINE'})))} rowKey={e=>e.nodeId+'-'+e.name} pagination={false} columns={[{title:'引擎',dataIndex:'name',render:(v:string)=>v.toUpperCase()},{title:'固定版本',dataIndex:'version'},{title:'节点',dataIndex:'nodeId'},{title:'状态',render:(_,e)=><Tag color={e.online&&e.ready?'green':'default'}>{!e.online?'节点离线':e.ready?'本地就绪':e.installed?'缺少数据 / 运行环境':'未安装'}</Tag>},{title:'说明',dataIndex:'message'}]}/></Card>
    <Card title="规则包版本" extra={<Space wrap><input aria-label="选择离线规则包" type="file" accept=".zip" disabled={!canWrite} onChange={e=>setFile(e.target.files?.[0]??null)}/><Button disabled={!canWrite||!file} loading={busy} onClick={()=>void run(()=>importRules(file!))}>离线导入 ZIP</Button><Button disabled={!canWrite} onClick={()=>setFetchOpen(true)}>从规则源下载</Button></Space>}>
      <Typography.Paragraph type="secondary">网页上传 ZIP 上限为 256 MiB，须包含 manifest.json、manifest.json.sig 和 nuclei/、trivy/ 下声明的规则文件。1.1 GiB 级 GitHub Actions 漏洞库制品请在 Updater 所在机器运行 `sec-updater --import-bundle-file /路径/vulnerability-data.zip`，再重启 Updater；大包导入并验证后，可在此处点击“激活”或“显式回滚”切换当前版本。</Typography.Paragraph>
      <DataTable<RuleBundle> dataSource={bundles} rowKey="version" scroll={{x:1000}} columns={[
        {title:'版本',dataIndex:'version',render:(v:string,b)=><Space><Typography.Text strong>{v}</Typography.Text>{b.isCurrent&&<Tag color="success">CURRENT</Tag>}</Space>},
        {title:'引擎数据',render:(_,b)=>b.engines?.join('、')||'—'},
        {title:'完整性 / 签名 / 兼容性',render:(_,b)=><Space direction="vertical"><Tag>{b.integrityVerified?'文件哈希已验证':'文件哈希未验证'}</Tag><Tag color={b.signatureVerified?'success':'default'}>{b.signatureVerified?'签名已验证':'签名未验证'}</Tag><Typography.Text type="secondary">{b.engineValidated?'引擎兼容性已验证':'引擎兼容性未验证'}</Typography.Text></Space>},
        {title:'Manifest SHA-256',dataIndex:'manifestSha256',ellipsis:true},
        {title:'导入时间',dataIndex:'publishedAt',render:(v:string)=>new Date(v).toLocaleString()},
        {title:'操作',render:(_,b)=><Space><Button disabled={!canWrite||b.isCurrent||!b.signatureVerified} loading={busy} onClick={()=>void run(()=>activateRules(b.version,false))}>激活</Button><Button danger disabled={!canWrite||b.isCurrent||!b.signatureVerified} onClick={()=>Modal.confirm({title:'显式回滚到 '+b.version+'？',content:'将切换本地规则指针并记录审计。当前不会启动扫描。',onOk:()=>run(()=>activateRules(b.version,true))})}>显式回滚</Button></Space>},
      ]}/>
    </Card>
    <Card title="自定义漏洞规则" extra={<Button type="primary" disabled={!canWrite} onClick={()=>{setEditingRule(null);ruleForm.resetFields();ruleForm.setFieldsValue({severity:'medium',matchType:'word',part:'body',enabled:true});setRuleOpen(true);}}>新增规则</Button>}>
      <Alert type="info" showIcon message="安全规则格式受限" description="规则只允许对已授权 HTTP(S) 地址发送一次根路径 GET，并匹配响应状态、响应头或响应正文；不支持自定义路径、请求载荷、登录凭据、代码执行或其他协议。启用的规则会自动加入后续 Nuclei / 自动扫描任务。" style={{marginBottom:16}}/>
      <DataTable<CustomRule> dataSource={customRules} rowKey="id" loading={customRulesLoading} locale={{emptyText:'还没有自定义规则。可先添加一个只读响应特征规则。'}} columns={[
        {title:'规则 ID',dataIndex:'id',width:180,ellipsis:true},{title:'规则名称',dataIndex:'name'},{title:'等级',dataIndex:'severity',render:(v:string)=><Tag color={v==='critical'||v==='high'?'red':v==='medium'?'orange':'blue'}>{v.toUpperCase()}</Tag>},
        {title:'匹配方式',render:(_,r)=><Typography.Text>{r.matchType==='status'?`HTTP 状态 ${r.statusCodes?.join(', ')}`:`${r.part==='header'?'响应头':'响应正文'} · ${r.matchType==='regex'?'正则':'文本'} · ${r.values?.length??0} 条`}</Typography.Text>},
        {title:'状态',dataIndex:'enabled',render:(v:boolean)=><Tag color={v?'green':'default'}>{v?'启用':'停用'}</Tag>},{title:'操作',width:140,render:(_,r)=><Space><Button size="small" disabled={!canWrite} onClick={()=>editRule(r)}>修改</Button><Button size="small" danger disabled={!canWrite} onClick={()=>removeRule(r)}>删除</Button></Space>},
      ]}/>
    </Card>
    <Card title="规则操作记录"><DataTable<RuleJob> dataSource={jobs} rowKey="id" scroll={{x:950}} columns={[
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
    <Modal title={editingRule?'修改自定义规则':'新增自定义规则'} open={ruleOpen} onCancel={()=>{setRuleOpen(false);setEditingRule(null);ruleForm.resetFields();}} onOk={()=>ruleForm.submit()} confirmLoading={busy} destroyOnClose>
      <Form form={ruleForm} layout="vertical" onFinish={saveRule} initialValues={{severity:'medium',matchType:'word',part:'body',enabled:true}}>
        <Form.Item name="id" label="规则 ID（仅小写英文、数字、短横线）" rules={[{required:true,pattern:/^[a-z0-9][a-z0-9_-]{0,99}$/}]}><Input disabled={!!editingRule} maxLength={100} placeholder="例如 legacy-console-banner"/></Form.Item>
        <Form.Item name="name" label="规则名称" rules={[{required:true,max:120}]}><Input maxLength={120}/></Form.Item>
        <Form.Item name="severity" label="严重程度" rules={[{required:true}]}><Select options={['info','low','medium','high','critical'].map(value=>({value,label:value.toUpperCase()}))}/></Form.Item>
        <Form.Item name="description" label="说明"><Input.TextArea rows={2} maxLength={2000}/></Form.Item>
        <Form.Item name="matchType" label="匹配方式" rules={[{required:true}]}><Select options={[{value:'word',label:'响应文本包含'}, {value:'regex',label:'响应内容正则'}, {value:'status',label:'HTTP 状态码'}]}/></Form.Item>
        {ruleMatchType==='status'?<Form.Item name="statusCodesText" label="状态码（英文逗号分隔）" rules={[{required:true}]} extra="例如 200, 401；允许 100–599。"><Input placeholder="200, 401"/></Form.Item>:<><Form.Item name="part" label="检查位置" rules={[{required:true}]}><Select options={[{value:'body',label:'响应正文'},{value:'header',label:'响应头'}]}/></Form.Item><Form.Item name="valuesText" label={ruleMatchType==='regex'?'正则表达式（每行一条）':'匹配文本（每行一条）'} rules={[{required:true}]} extra="最多 8 条，每条最多 256 字符。"><Input.TextArea rows={4} maxLength={2200}/></Form.Item></>}
        <Form.Item name="enabled" label="状态" rules={[{required:true}]}><Select options={[{value:true,label:'启用（自动用于后续任务）'},{value:false,label:'停用'}]}/></Form.Item>
      </Form>
    </Modal>
  </div>;
};
