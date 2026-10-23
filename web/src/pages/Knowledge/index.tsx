import React, { useCallback, useEffect, useRef, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Button, Col, Descriptions, Drawer, Form, Input, InputNumber, message, Modal, Row, Select, Space, Typography } from 'antd';
import { Mono, StatusPill } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import { TitleWithHelp } from '../../components/HelpTip';
import { PlusOutlined, UploadOutlined } from '@ant-design/icons';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { apiClient } from '../../api/client';
import { createKnowledge, updateKnowledge, deleteKnowledge, importKnowledge } from '../../api/runtime';
import { useAuth } from '../../auth/AuthProvider';
import type { KnowledgeEntry } from '../../types';

type Values=Omit<KnowledgeEntry,'identifiers'|'references'|'affectedRanges'|'updatedAt'> & {identifiersText:string;referencesText:string;rangesText:string};
export const KnowledgePage:React.FC=()=>{
  const {user}=useAuth();const canWrite=user?.role==='admin'||user?.role==='security_engineer';
  const {data:categories}=useCollection('vulnerability-categories');
  const [items,setItems]=useState<KnowledgeEntry[]>([]);const [loading,setLoading]=useState(true);const [error,setError]=useState('');const [page,setPage]=useState(1);const [pageSize,setPageSize]=useState(15);const [total,setTotal]=useState(0);const [query,setQuery]=useState('');const [open,setOpen]=useState(false);const [editing,setEditing]=useState<KnowledgeEntry|null>(null);const [detail,setDetail]=useState<KnowledgeEntry|null>(null);const [busy,setBusy]=useState(false);const [form]=Form.useForm<Values>();const fileRef=useRef<HTMLInputElement>(null);
  const reload=useCallback(async(signal?:AbortSignal)=>{setLoading(true);try{const response=await apiClient.knowledgePage(page,pageSize,query,signal);if(!signal?.aborted){setItems(response.items);setTotal(response.total);setError('');}}catch(cause){if(!signal?.aborted)setError(cause instanceof Error?cause.message:'知识库读取失败');}finally{if(!signal?.aborted)setLoading(false);}},[page,pageSize,query]);
  useEffect(()=>{const controller=new AbortController();void reload(controller.signal);return()=>controller.abort();},[reload]);
  const edit=(item?:KnowledgeEntry)=>{setEditing(item??null);form.resetFields();form.setFieldsValue(item?{...item,identifiersText:JSON.stringify(item.identifiers??{},null,2),referencesText:item.references?.join('\n')??'',rangesText:JSON.stringify(item.affectedRanges??[],null,2)}:{language:'zh-CN',identifiersText:'{}',rangesText:'[]',referencesText:'',source:'自建中文内容'});setOpen(true);};
  const save=async(values:Values)=>{
    setBusy(true);try{
      const {identifiersText,referencesText,rangesText,...fields}=values;
      const identifiers=JSON.parse(identifiersText||'{}');const affectedRanges=JSON.parse(rangesText||'[]');
      if(!identifiers||Array.isArray(identifiers)||typeof identifiers!=='object'||Object.values(identifiers).some(v=>!Array.isArray(v)||v.some(x=>typeof x!=='string')))throw new Error('编号应为 JSON 对象，每个值为字符串数组');
      if(!Array.isArray(affectedRanges)||affectedRanges.some(r=>!r||typeof r!=='object'||Object.entries(r).some(([k,v])=>!['introduced','fixed','lastAffected'].includes(k)||typeof v!=='string')))throw new Error('版本范围须为数组，仅支持 introduced、fixed、lastAffected 字符串');
      const input={...fields,identifiers,affectedRanges,references:(referencesText??'').split('\n').map(v=>v.trim()).filter(Boolean),updatedAt:new Date().toISOString()};
      const saved=editing?await updateKnowledge(editing.id,input):await createKnowledge(input);
      setItems(prev=>editing?prev.map(i=>i.id===saved.id?saved:i):[saved,...prev]);message.success('知识条目已保存');setOpen(false);if(!editing){setPage(1);}else{void reload();}
    }catch(e){message.error(e instanceof Error?e.message:'保存失败');}finally{setBusy(false);}
  };
  const remove=(item:KnowledgeEntry)=>Modal.confirm({title:`删除知识条目 ${item.id}`,content:'已生成的扫描发现项和报告快照会保留。后续版本匹配不再使用该条目。',okText:'删除',okButtonProps:{danger:true},cancelText:'取消',onOk:async()=>{await deleteKnowledge(item.id);setItems(prev=>prev.filter(i=>i.id!==item.id));message.success('条目已删除');}});
  const importFile=async(file?:File)=>{
    if(!file)return;setBusy(true);try{
      if(file.size>5*1024*1024)throw new Error('JSON 文件不能超过 5 MiB');
      const parsed=JSON.parse(await file.text());const imported=Array.isArray(parsed)?parsed:parsed.items;
      if(!Array.isArray(imported)||imported.length===0||imported.length>10000)throw new Error('JSON 需要包含条目数组或 {"items": [...]}，每次 1–10000 条');
      if(imported.some(i=>!i||typeof i!=='object'||typeof i.id!=='string'))throw new Error('每个条目必须包含字符串 id');
      const result=await importKnowledge(imported);setPage(1);await reload();message.success(`已导入 ${result.imported??imported.length} 条知识`);
    }catch(e){message.error(e instanceof Error?e.message:'导入失败');}finally{setBusy(false);if(fileRef.current)fileRef.current.value='';}
  };
  const chinese=items.filter(i=>i.language==='zh-CN').length;
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <PageHeader title={<TitleWithHelp title="漏洞知识库" helpTitle="漏洞知识库与中文修复建议" help="支持本地 JSON 导入和自建中文内容。条目用于组件版本匹配与发现项内容补全；版本匹配结果标注为版本推断。CNNVD、CNVD 等数据源尚未接入，可人工填写外部编号。导入格式为条目数组或 {&quot;items&quot;: [...]}，每条包含 id、title、component、affectedRanges、description、impact、solution、references、identifiers、category、source、language；单文件最多 5 MiB。"/>}
      description={`共 ${total} 条知识${items.length?` · 本页中文内容 ${chinese}/${items.length}`:''}`}
      extra={<Space wrap><input ref={fileRef} type="file" accept=".json,application/json" style={{display:'none'}} onChange={e=>void importFile(e.target.files?.[0])}/><Button icon={<UploadOutlined/>} disabled={!canWrite} loading={busy} onClick={()=>fileRef.current?.click()}>导入本地 JSON</Button><Button type="primary" icon={<PlusOutlined/>} disabled={!canWrite} onClick={()=>edit()}>新增条目</Button></Space>}/>
    <CollectionNotice loading={loading&&items.length===0} error={error}/>
    <Panel flush title="知识条目" extra={<Input.Search aria-label="搜索知识条目" value={query} onChange={e=>{setQuery(e.target.value);setPage(1);}} allowClear placeholder="搜索平台编号、标题、组件或外部编号" style={{width:320}}/>}>
      <DataTable<KnowledgeEntry> rowKey="id" dataSource={items} loading={loading} tableLayout="fixed" scroll={{x:1100}} locale={{emptyText:query?'没有符合条件的知识条目':'暂无知识条目，可导入本地 JSON 或新增条目'}} pagination={{current:page,pageSize,total,showSizeChanger:true,pageSizeOptions:[15,30,60],showTotal:n=>`共 ${n} 条`,onChange:(nextPage,nextSize)=>{if(nextSize!==pageSize){setPageSize(nextSize);setPage(1);}else setPage(nextPage);}}} columns={[
        {title:'平台编号',dataIndex:'id',width:190,ellipsis:true,render:(v:string)=><Mono title={v}>{v}</Mono>},
        {title:'中文标题',dataIndex:'title',render:(v:string,r)=><Button type="link" style={{padding:0,height:'auto',whiteSpace:'normal',textAlign:'left'}} onClick={()=>setDetail(r)}>{v}</Button>},
        {title:'组件',dataIndex:'component',width:160,ellipsis:true,render:(v:string)=><Mono title={v}>{v}</Mono>},
        {title:'CVSS',dataIndex:'cvssScore',width:80,render:(v:number|undefined)=>v==null?<Typography.Text type="secondary">—</Typography.Text>:<Mono style={{fontWeight:600}}>{v.toFixed(1)}</Mono>},
        {title:'分类',dataIndex:'category',width:140,ellipsis:true,render:(v:string|undefined)=>categories.find(c=>c.id===v)?.name??v??'—'},
        {title:'内容',dataIndex:'language',width:130,render:(v:string)=><StatusPill tone={v==='zh-CN'?'ok':'warning'}>{v==='zh-CN'?'中文':'原文待中文化'}</StatusPill>},
        {title:'来源',dataIndex:'source',width:150,ellipsis:true},
        {title:'操作',key:'actions',width:120,render:(_,r)=><Space size={0}><Button type="link" size="small" disabled={!canWrite} onClick={()=>edit(r)}>编辑</Button><Button type="link" size="small" danger disabled={!canWrite} onClick={()=>remove(r)}>删除</Button></Space>},
      ]}/>
    </Panel>
    <Modal title={editing?'编辑知识条目':'新增知识条目'} open={open} width={840} onCancel={()=>setOpen(false)} onOk={()=>form.submit()} confirmLoading={busy} destroyOnClose>
      <Form form={form} layout="vertical" onFinish={save}>
        <Row gutter={16}><Col span={12}><Form.Item name="id" label="平台编号" rules={[{required:true}]}><Input disabled={!!editing} maxLength={160}/></Form.Item></Col><Col span={12}><Form.Item name="title" label="中文标题" rules={[{required:true}]}><Input maxLength={500}/></Form.Item></Col></Row>
        <Row gutter={16}><Col span={12}><Form.Item name="component" label="组件名称" rules={[{required:true}]}><Input maxLength={200}/></Form.Item></Col><Col span={12}><Form.Item name="category" label="漏洞分类"><Select allowClear showSearch options={categories.map(c=>({value:c.id,label:c.name}))}/></Form.Item></Col></Row>
        <Row gutter={16}><Col span={8}><Form.Item name="cvssScore" label="CVSS 风险值（0–10）"><InputNumber min={0} max={10} step={0.1} style={{width:'100%'}}/></Form.Item></Col><Col span={8}><Form.Item name="language" label="内容语言" rules={[{required:true}]}><Select options={[{value:'zh-CN',label:'中文'},{value:'original',label:'原文待中文化'}]}/></Form.Item></Col><Col span={8}><Form.Item name="source" label="来源" rules={[{required:true}]}><Input maxLength={300}/></Form.Item></Col></Row>
        <Form.Item name="description" label="风险描述" rules={[{required:true}]}><Input.TextArea rows={3} maxLength={10000}/></Form.Item>
        <Form.Item name="impact" label="风险影响"><Input.TextArea rows={2} maxLength={10000}/></Form.Item>
        <Form.Item name="solution" label="中文修复建议" rules={[{required:true,message:'请补充可执行的修复建议'}]}><Input.TextArea rows={3} maxLength={10000} placeholder="说明修复版本、配置变更和核查步骤"/></Form.Item>
        <Form.Item name="rangesText" label="受影响版本范围（JSON）" extra={'例如 [{"introduced":"1.0.0","fixed":"1.2.0"}]；fixed 为首个已修复版本，lastAffected 为最后受影响版本。'}><Input.TextArea rows={3}/></Form.Item>
        <Form.Item name="identifiersText" label="外部编号（JSON）" extra={'例如 {"CVE":["CVE-2026-0001"],"CWE":["CWE-200"]}'}><Input.TextArea rows={2}/></Form.Item>
        <Form.Item name="referencesText" label="参考资料（每行一个 URL）"><Input.TextArea rows={2}/></Form.Item>
      </Form>
    </Modal>
    <Drawer title={detail?.title??'知识详情'} open={!!detail} onClose={()=>setDetail(null)} width={780}>{detail&&<Space direction="vertical" size={18} style={{width:'100%'}}>
      <Descriptions bordered column={2} size="small" items={[{key:'id',label:'平台编号',children:detail.id},{key:'score',label:'CVSS',children:detail.cvssScore??'未提供'},{key:'component',label:'组件',children:detail.component},{key:'source',label:'来源',children:detail.source},{key:'ids',label:'外部编号',span:2,children:Object.entries(detail.identifiers??{}).map(([k,v])=>`${k}: ${v.join(', ')}`).join('；')||'无'}]}/>
      {[['风险描述',detail.description],['风险影响',detail.impact],['修复建议',detail.solution],['参考资料',detail.references?.join('\n')],['版本范围',JSON.stringify(detail.affectedRanges,null,2)]].map(([label,value])=><div key={label}><Typography.Title level={5}>{label}</Typography.Title><Typography.Paragraph style={{whiteSpace:'pre-wrap'}}>{value||'待补充'}</Typography.Paragraph></div>)}
    </Space>}</Drawer>
  </div>;
};
