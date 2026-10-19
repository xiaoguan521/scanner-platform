import React, { useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { mockAssets, mockPortQuarantines, mockTasks } from '../../mock/data';
import type { Asset, ScanTask } from '../../types';
import { apiClient, isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';

const { Text } = Typography;
type AssetForm = {kind:'host'|'image_repo';address:string;businessGroup:string;owner:string;requestedPorts?:string;skippedPorts?:string};
type CandidateRow = {port:number;status:string;requestable:boolean};
function parsePorts(text?: string): number[] {
  if (!text?.trim()) return [];
  const tokens = text.split(',').map(v => v.trim());
  if (tokens.length > 50 || tokens.some(v => !/^[0-9]{1,5}$/.test(v))) throw new Error('端口请用英文逗号分隔，最多 50 个');
  const ports = tokens.map(Number);
  if (ports.some(v => v < 1 || v > 65535) || new Set(ports).size !== ports.length) {
    throw new Error('端口范围必须为 1–65535，不能重复');
  }
  return ports;
}
export const AssetsPage: React.FC = () => {
  const {user} = useAuth();
  const canEdit = isDemoMode || user?.role === 'admin' || user?.role === 'security_engineer';
  const {data:assets,setData:setAssets,loading,error} = useCollection('assets',mockAssets);
  const {data:quarantines,setData:setQuarantines} = useCollection('port-quarantines',mockPortQuarantines);
  const {data:tasks,loading:taskLoading,error:taskError} = useCollection('tasks',mockTasks);
  const [createOpen,setCreateOpen] = useState(false);
  const [editing,setEditing] = useState<Asset|null>(null);
  const [candidateAsset,setCandidateAsset] = useState<Asset|null>(null);
  const [selectedCandidatePorts,setSelectedCandidatePorts] = useState<React.Key[]>([]);
  const [candidateFilter,setCandidateFilter] = useState('');
  const [saving,setSaving] = useState(false);
  const [requestingCandidates,setRequestingCandidates] = useState(false);
  const [checkingAsset,setCheckingAsset] = useState('');
  const [filter,setFilter] = useState('');
  const [createForm] = Form.useForm<AssetForm>();
  const [editForm] = Form.useForm<Pick<AssetForm,'address'|'businessGroup'|'owner'|'requestedPorts'|'skippedPorts'>>();
  const rows = useMemo(()=>assets.filter(a=>(a.address+' '+a.businessGroup+' '+a.owner).toLowerCase().includes(filter.toLowerCase())),[assets,filter]);
  const checkReachability = async(asset:Asset) => {
    if(asset.kind!=='host')return;
    if(isDemoMode){message.info('演示模式不会向目标发送 Ping');return;}
    setCheckingAsset(asset.id);
    try {
      const result=await apiClient.checkAssetReachability(asset.id);
      setAssets(prev=>prev.map(item=>item.id===asset.id?{...item,reachabilityStatus:result.status,reachabilityCheckedAt:result.checkedAt}:item));
      message[result.status==='REACHABLE'?'success':'warning'](result.status==='REACHABLE'?'收到目标 Ping 响应':'未收到 Ping 响应；目标可能屏蔽 ICMP');
    } catch(cause) {
      message.error(cause instanceof Error?cause.message:'可达性检测失败');
    } finally {setCheckingAsset('');}
  };
  const deleteAsset = (asset:Asset) => Modal.confirm({
    title:'删除资产',
    content:`确定删除 ${asset.address}？仍有关联授权范围时，需要先撤销或删除授权。`,
    okText:'删除',okButtonProps:{danger:true},cancelText:'取消',
    onOk:async()=>{
      try {
        if(!isDemoMode) await apiClient.deleteAsset(asset.id);
        setAssets(prev=>prev.filter(item=>item.id!==asset.id));
        if(candidateAsset?.id===asset.id)setCandidateAsset(null);
        message.success(isDemoMode?'演示资产已移除':'资产已删除');
      } catch(cause) {message.error(cause instanceof Error?cause.message:'删除失败');throw cause;}
    },
  });
  const latestProbes = useMemo(()=>{
    const ordered=tasks.filter(task=>task.engines?.[0]==='port-probe').slice().sort((a,b)=>Date.parse(b.createdAt)-Date.parse(a.createdAt));
    const byAsset=new Map<string,ScanTask>();
    for(const task of ordered) if(task.assetId&&!byAsset.has(task.assetId)) byAsset.set(task.assetId,task);
    return byAsset;
  },[tasks]);
  const candidateRows = useMemo<CandidateRow[]>(()=>{
    if(!candidateAsset)return [];
    const probe=latestProbes.get(candidateAsset.id);
    if(!probe||probe.status!=='COMPLETED')return [];
    const classifications=new Map((candidateAsset.ports??[]).map(item=>[item.port,item.kind]));
    const skippedPorts=new Set([...(candidateAsset.skippedPorts??[]),...(candidateAsset.quarantinedPorts??[])]);
    const requestedPorts=new Set(candidateAsset.requestedPorts??[]);
    return [...new Set((probe.portProbeResults??[]).map(result=>result.port))].sort((a,b)=>a-b).map(port=>{
      const classification=classifications.get(port);
      const skipped=skippedPorts.has(port)||classification==='EXCLUDED_PROXY';
      const requested=requestedPorts.has(port);
      const requestable=!skipped&&!requested&&!classification;
      const status=skipped?'已跳过 / 隔离':classification==='WEB'?'已审批 · Web':classification==='NON_WEB'?'已审批 · 非 Web':requested?'已提交申请':'待申请';
      return {port,status,requestable};
    });
  },[candidateAsset,latestProbes]);
  const filteredCandidateRows = useMemo(()=>candidateRows.filter(row=>!candidateFilter||String(row.port).includes(candidateFilter.trim())),[candidateRows,candidateFilter]);

  const create = async (input: AssetForm) => {
    setSaving(true);
    try {
      const requestedPorts=parsePorts(input.requestedPorts);
      const skippedPorts=parsePorts(input.skippedPorts);
      if(skippedPorts.some(p=>!requestedPorts.includes(p))) throw new Error('跳过端口必须来自目标端口列表');
      let asset: Asset;
      if (isDemoMode) {
        asset={id:'demo-'+Date.now(),kind:input.kind,address:input.address,businessGroup:input.businessGroup,
          owner:input.owner,createdAt:new Date().toISOString(),ports:[],requestedPorts,quarantinedPorts:[]};
        message.info('仅演示：添加本地草稿，端口尚未获扫描授权');
      } else {
        asset=await apiClient.createAsset({...input,requestedPorts,skippedPorts});
        message.success('资产与明确输入的端口已保存；跳过端口不会下发给 Worker');
      }
      setAssets(prev=>[asset,...prev]);setCreateOpen(false);createForm.resetFields();
      if(asset.kind==='host'&&!isDemoMode) void checkReachability(asset);
    } catch(e) {message.error(e instanceof Error?e.message:'登记失败');}
    finally {setSaving(false);}
  };
  const update = async (input: Pick<AssetForm,'address'|'businessGroup'|'owner'|'requestedPorts'|'skippedPorts'>) => {
    if (!editing) return;
    setSaving(true);
    try {
      const address=input.address!.trim();
      const addressChanged=address!==editing.address;
      const patch={address,businessGroup:input.businessGroup!,owner:input.owner!,requestedPorts:parsePorts(input.requestedPorts),skippedPorts:parsePorts(input.skippedPorts)};
      const result=isDemoMode?{...editing,...patch}:await apiClient.updateAsset(editing.id,patch);
      setAssets(prev=>prev.map(a=>a.id===editing.id?result:a));
      setEditing(null);
      message[isDemoMode?'info':'success'](isDemoMode?'仅演示：更新本地数据':addressChanged?'资产 IP 已更新；旧授权已撤销，需重新申请审批':'资产信息已保存；原有端口审批已重置');
      if(addressChanged&&result.kind==='host'&&!isDemoMode) void checkReachability(result);
    }catch(e){message.error(e instanceof Error?e.message:'更新失败');}
    finally{setSaving(false);}
  };
  const releaseDemo = (assetId:string,port:number)=>{
    if (!isDemoMode)return;
    Modal.confirm({title:'仅在演示页面解除隔离？',content:'不会更改 Server 或实际安全状态',
      onOk:()=>{
        setQuarantines(prev=>prev.filter(q=>q.assetId!==assetId || q.port!==port));
        setAssets(prev=>prev.map(a=>a.id===assetId?{...a,quarantinedPorts:a.quarantinedPorts?.filter(p=>p!==port)}:a));
        message.info('仅演示：本地显示更新');
      }});
  };
  const requestSelectedCandidates = async() => {
    if(!candidateAsset)return;
    const selected=new Set(selectedCandidatePorts.map(Number));
    const ports=candidateRows.filter(row=>row.requestable&&selected.has(row.port)).map(row=>row.port);
    if(ports.length===0){message.info('请选择待申请的开放端口');return;}
    setRequestingCandidates(true);
    try {
      await apiClient.requestAssetPorts(candidateAsset.id,ports);
      const requestedPorts=[...new Set([...(candidateAsset.requestedPorts??[]),...ports])].sort((a,b)=>a-b);
      setAssets(prev=>prev.map(item=>item.id===candidateAsset.id?{...item,requestedPorts}:item));
      setCandidateAsset({...candidateAsset,requestedPorts});
      setSelectedCandidatePorts([]);
      message.success(`已提交 ${ports.length} 个端口申请，请到“授权与时间窗”由运维审批`);
    } catch(cause) {message.error(cause instanceof Error?cause.message:'端口申请失败');}
    finally {setRequestingCandidates(false);}
  };

  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={loading||taskLoading} error={error||taskError}/>
    <Alert type="warning" showIcon
      message="端口探测只针对已登记的单台主机"
      description="在任务中心可选择常用 TCP 端口或输入范围（支持 1-65535），Worker 最多并发探测 64 个端口；也可填写排除端口。资产中已标记跳过或隔离的端口会自动排除。开放端口只作候选；提交申请并经运维审批后，才会出现在漏洞扫描目标中。"/>
    <Alert type="info" showIcon message="资产可达性" description="新增主机后会自动发送一次 ICMP Ping，也可点“重测”。无响应不等于主机离线，目标防火墙可能屏蔽 ICMP。" />

    {quarantines.length > 0 && <Card title="疑似四层转发隔离区（仅演示）">
      <Table rowKey={q=>q.assetId+'-'+q.port} dataSource={quarantines} size="small" pagination={false}
        columns={[
          {title:'地址',dataIndex:'address'},{title:'端口',dataIndex:'port'},{title:'原因',dataIndex:'reason'},
          {title:'操作',render:(_:unknown,q:typeof quarantines[number])=><Button type="link" disabled={!isDemoMode}
            onClick={()=>releaseDemo(q.assetId,q.port)}>演示解除</Button>}
        ]}/>
    </Card>}
    <Card title="资产登记台账" extra={<Space>
      <Input.Search placeholder="搜索地址、组或负责人" allowClear value={filter} onChange={e=>setFilter(e.target.value)} style={{width:220}}/>
      <Button type="primary" icon={<PlusOutlined/>} disabled={!canEdit} onClick={()=>setCreateOpen(true)}>登记资产</Button>
    </Space>}>
      <Table<Asset> rowKey="id" dataSource={rows} loading={loading||taskLoading} tableLayout="fixed" scroll={{x:1600}} pagination={{pageSize:10}}
        columns={[
          {title:'资产地址',dataIndex:'address',width:150,ellipsis:true,render:(value:string)=><Text strong>{value}</Text>},
          {title:'类型',dataIndex:'kind',width:86,render:(v:string)=><Tag>{v==='host'?'主机':'镜像仓库'}</Tag>},
          {title:'业务组',dataIndex:'businessGroup',width:110,ellipsis:true},{title:'责任人',dataIndex:'owner',width:100,ellipsis:true},
          {title:'已申请端口',dataIndex:'requestedPorts',width:120,render:(ports:number[]|undefined)=>
            ports?.length?<Tag color="gold">{ports.length} 个端口</Tag>:<Text type="secondary">未申请</Text>},
          {title:'端口状态',dataIndex:'ports',width:170,render:(ports:Asset['ports'])=>{
            const counts={WEB:0,NON_WEB:0,EXCLUDED_PROXY:0};
            for(const port of ports??[]) if(port.kind in counts) counts[port.kind as keyof typeof counts]++;
            return <Space wrap size={[4,2]}>{counts.WEB>0&&<Tag color="green">Web {counts.WEB}</Tag>}{counts.NON_WEB>0&&<Tag>非 Web {counts.NON_WEB}</Tag>}{counts.EXCLUDED_PROXY>0&&<Tag color="orange">跳过 {counts.EXCLUDED_PROXY}</Tag>}{!ports?.length&&<Text type="secondary">暂无分类</Text>}</Space>;
          }},
          {title:'最近端口探测',width:200,render:(_:unknown,asset:Asset)=>{
            const probe=latestProbes.get(asset.id);
            if(!probe)return <Text type="secondary">尚未探测</Text>;
            if(probe.status!=='COMPLETED')return <Tag color={probe.status==='FAILED'?'error':'processing'}>{probe.status==='RUNNING'?'探测中':probe.status==='PENDING'?'待领取':probe.status==='FAILED'?'失败':probe.status==='PAUSED_WINDOW'?'等待下个时间窗':'等待执行'}</Tag>;
            const count=probe.portProbeResults?.length??0;
            return <Space direction="vertical" size={2}><Tag color={count?'blue':'default'}>{count} 个开放候选</Tag>{count>0&&<Button type="link" size="small" style={{padding:0,height:'auto'}} onClick={()=>{setCandidateAsset(asset);setCandidateFilter('');setSelectedCandidatePorts([]);}}>查看与批量申请</Button>}</Space>;
          }},
          {title:'IP 可达性（ICMP）',width:170,render:(_:unknown,asset:Asset)=>{
            if(asset.kind!=='host')return <Text type="secondary">主机地址适用</Text>;
            const status=checkingAsset===asset.id?'CHECKING':asset.reachabilityStatus??'UNCHECKED';
            const labels:Record<string,string>={UNCHECKED:'未检测',CHECKING:'检测中',REACHABLE:'Ping 可达',NO_RESPONSE:'未收到响应',CHECK_FAILED:'检测不可用'};
            const color=status==='REACHABLE'?'green':status==='NO_RESPONSE'?'orange':status==='CHECKING'?'processing':'default';
            return <Space direction="vertical" size={2}><Tag color={color}>{labels[status]??status}</Tag>{asset.reachabilityCheckedAt&&<Text type="secondary">{new Date(asset.reachabilityCheckedAt).toLocaleString()}</Text>}</Space>;
          }},
          {title:'登记时间',dataIndex:'createdAt',width:150,render:(value:string)=>new Date(value).toLocaleDateString()},
          {title:'操作',width:220,fixed:'right',render:(_:unknown,asset:Asset)=><Space size={4}>
            {asset.kind==='host'&&<Button type="link" size="small" disabled={!canEdit||isDemoMode||checkingAsset===asset.id} loading={checkingAsset===asset.id} onClick={()=>void checkReachability(asset)}>重测</Button>}
            <Button type="link" size="small" disabled={!canEdit} onClick={()=>{
              editForm.setFieldsValue({address:asset.address,businessGroup:asset.businessGroup,owner:asset.owner,requestedPorts:asset.requestedPorts?.join(', ')??'',skippedPorts:asset.skippedPorts?.join(', ')??''});
              setEditing(asset);
            }}>编辑</Button>
            <Button type="link" size="small" danger disabled={!canEdit} onClick={()=>deleteAsset(asset)}>删除</Button>
          </Space>}
        ]}/>
    </Card>
    <Modal title={isDemoMode?'演示：登记资产':'登记新资产'} open={createOpen}
      onCancel={()=>setCreateOpen(false)} onOk={()=>createForm.submit()} okButtonProps={{loading:saving}}>
      <Form form={createForm} layout="vertical" onFinish={create} autoComplete="off">
        <Form.Item name="kind" label="资产类型" initialValue="host" rules={[{required:true}]}>
          <Select options={[{label:'主机（纯数字 IPv4/IPv6）',value:'host'},{label:'镜像仓库',value:'image_repo'}]}/>
        </Form.Item>
        <Form.Item name="address" label="资产地址" rules={[{required:true}]} extra="主机只接受数字 IP，不展开 CIDR 或域名">
          <Input placeholder="例如 192.0.2.18"/>
        </Form.Item>
        <Form.Item name="businessGroup" label="所属业务组" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="owner" label="责任人" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="requestedPorts" label="已知端口申请（可留空）" extra="仅填写已知端口，如 80,443；未知端口请留空，在任务中心探测后可从本页批量申请。填写此处不会直接授权扫描。">
          <Input placeholder="80, 443"/>
        </Form.Item>
        <Form.Item name="skippedPorts" label="跳过端口（Nginx 四层转发等）" extra="必须属于上面的目标端口，英文逗号分隔；不会下发给 Worker"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={'编辑资产：'+(editing?.address??'')} open={!!editing}
      onCancel={()=>setEditing(null)} onOk={()=>editForm.submit()} okButtonProps={{loading:saving}}>
      <Alert type="warning" showIcon style={{marginBottom:16}} message="保存会重置已有端口审批；修改主机 IP 会撤销该资产的授权范围，并重新检查 Ping。" />
      <Form form={editForm} layout="vertical" onFinish={update}>
        <Form.Item name="address" label="资产地址" rules={[{required:true,message:'请输入资产地址'}]} extra="主机仅接受数字 IP，不支持 CIDR 或域名；修改后需重新申请授权。"><Input maxLength={255}/></Form.Item>
        <Form.Item name="businessGroup" label="业务组" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="owner" label="责任人" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="requestedPorts" label="拟申请端口" extra="只是申请记录，不是扫描授权"><Input/></Form.Item>
        <Form.Item name="skippedPorts" label="跳过端口（Nginx 四层转发等）" extra="必须属于上面的目标端口，英文逗号分隔；不会下发给 Worker"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={`开放端口候选${candidateAsset?` · ${candidateAsset.address}`:''}`} open={!!candidateAsset} width={720}
      onCancel={()=>{setCandidateAsset(null);setSelectedCandidatePorts([]);setCandidateFilter('');}}
      footer={<Space style={{width:'100%',justifyContent:'space-between'}}><Text type="secondary">已选 {selectedCandidatePorts.length} 个 · 每次最多申请 1024 个</Text><Space><Button onClick={()=>{setCandidateAsset(null);setSelectedCandidatePorts([]);setCandidateFilter('');}}>关闭</Button><Button type="primary" disabled={!canEdit||isDemoMode||selectedCandidatePorts.length===0} loading={requestingCandidates} onClick={()=>void requestSelectedCandidates()}>申请选中端口</Button></Space></Space>}>
      <Alert type="info" showIcon style={{marginBottom:12}} message={`本次探测发现 ${candidateRows.length} 个开放候选。开放结果只是候选；所选端口会逐个提交给运维审批。`} />
      <Input.Search allowClear placeholder="按端口号筛选" value={candidateFilter} onChange={event=>setCandidateFilter(event.target.value)} style={{marginBottom:12,maxWidth:280}}/>
      <Table<CandidateRow> rowKey="port" size="small" dataSource={filteredCandidateRows} pagination={{pageSize:25,showSizeChanger:true,pageSizeOptions:[25,50,100],showTotal:(total)=>`共 ${total} 个候选`}} scroll={{y:420}}
        rowSelection={{selectedRowKeys:selectedCandidatePorts,preserveSelectedRowKeys:true,getCheckboxProps:row=>({disabled:!row.requestable||!canEdit||isDemoMode}),onChange:keys=>{
          if(keys.length>1024){message.warning('一次最多选择 1024 个端口申请');setSelectedCandidatePorts(keys.slice(0,1024));return;}
          setSelectedCandidatePorts(keys);
        }}}
        columns={[{title:'TCP 端口',dataIndex:'port',width:140,sorter:(a,b)=>a.port-b.port},{title:'状态',dataIndex:'status',render:(status:string,row:CandidateRow)=><Tag color={row.requestable?'blue':status.startsWith('已跳过')?'orange':'default'}>{status}</Tag>}]} />
      {isDemoMode&&<Text type="secondary">演示模式只能查看，连接 Server 模式后才能提交端口申请。</Text>}
    </Modal>
  </div>;
};
