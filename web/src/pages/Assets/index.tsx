import React, { useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { mockAssets, mockPortQuarantines, mockTasks } from '../../mock/data';
import type { Asset } from '../../types';
import { apiClient, isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';

const { Text } = Typography;
type AssetForm = {kind:'host'|'image_repo';address:string;businessGroup:string;owner:string;requestedPorts?:string;skippedPorts?:string};
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
  const [saving,setSaving] = useState(false);
  const [requestingPort,setRequestingPort] = useState('');
  const [filter,setFilter] = useState('');
  const [createForm] = Form.useForm<AssetForm>();
  const [editForm] = Form.useForm<Pick<AssetForm,'businessGroup'|'owner'|'requestedPorts'|'skippedPorts'>>();
  const rows = useMemo(()=>assets.filter(a=>(a.address+' '+a.businessGroup+' '+a.owner).toLowerCase().includes(filter.toLowerCase())),[assets,filter]);

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
    } catch(e) {message.error(e instanceof Error?e.message:'登记失败');}
    finally {setSaving(false);}
  };
  const update = async (input: Pick<AssetForm,'businessGroup'|'owner'|'requestedPorts'|'skippedPorts'>) => {
    if (!editing) return;
    setSaving(true);
    try {
      const patch={businessGroup:input.businessGroup!,owner:input.owner!,requestedPorts:parsePorts(input.requestedPorts),skippedPorts:parsePorts(input.skippedPorts)};
      const result=isDemoMode?{...editing,...patch}:await apiClient.updateAsset(editing.id,patch);
      setAssets(prev=>prev.map(a=>a.id===editing.id?result:a));
      setEditing(null);
      message[isDemoMode?'info':'success'](isDemoMode?'仅演示：更新本地数据':'资产信息已保存；原有端口审批已重置');
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
  const requestCandidate = async(asset:Asset,port:number) => {
    const key=`${asset.id}:${port}`;
    setRequestingPort(key);
    try {
      await apiClient.requestAssetPort(asset.id,port);
      setAssets(prev=>prev.map(item=>item.id===asset.id?{...item,requestedPorts:[...new Set([...(item.requestedPorts??[]),port])].sort((a,b)=>a-b)}:item));
      message.success(`${port} 已提交端口申请；请到“授权与时间窗”由运维审批`);
    } catch(cause) {message.error(cause instanceof Error?cause.message:'端口申请失败');}
    finally {setRequestingPort('');}
  };

  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <CollectionNotice loading={loading||taskLoading} error={error||taskError}/>
    <Alert type="warning" showIcon
      message="端口探测只针对已登记的单台主机"
      description="在任务中心可选择常用 TCP 端口或自定义范围，并填写排除端口。资产中已标记跳过或隔离的端口会自动排除。开放端口只作候选；提交申请并经运维审批后，才会出现在漏洞扫描目标中。"/>

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
      <Table<Asset> rowKey="id" dataSource={rows} loading={loading||taskLoading} scroll={{x:1500}} pagination={{pageSize:10}}
        columns={[
          {title:'资产地址',dataIndex:'address',render:(value:string)=><Text strong>{value}</Text>},
          {title:'类型',dataIndex:'kind',render:(v:string)=><Tag>{v==='host'?'主机':'镜像仓库'}</Tag>},
          {title:'业务组',dataIndex:'businessGroup'},{title:'责任人',dataIndex:'owner'},
          {title:'明确登记的目标端口',dataIndex:'requestedPorts',render:(ports:number[]|undefined)=>
            ports?.length?<Space wrap>{ports.map(port=><Tag key={port} color="gold">{port} 已登记</Tag>)}</Space>:<Text type="secondary">未填写</Text>},
          {title:'端口分类 / 跳过标记',dataIndex:'ports',render:(ports:Asset['ports'])=>
            ports?.length?<Space wrap>{ports.map(p=><Tag key={p.port} color={p.kind==='WEB'?'green':'default'}>{p.port} {p.kind==='EXCLUDED_PROXY'?'跳过':p.kind}</Tag>)}</Space>:<Text type="secondary">无（不可扫）</Text>},
          {title:'最近端口探测',render:(_:unknown,asset:Asset)=>{
            const probe=tasks.find(task=>task.assetId===asset.id&&task.engines?.[0]==='port-probe');
            if(!probe)return <Text type="secondary">尚未探测</Text>;
            if(probe.status!=='COMPLETED')return <Tag color={probe.status==='FAILED'?'error':'processing'}>{probe.status==='RUNNING'?'探测中':probe.status==='PENDING'?'待领取':probe.status==='FAILED'?'失败':'等待时间窗'}</Tag>;
            const candidates=(probe.portProbeResults??[]).map(result=>result.port);
            return candidates.length?<Space wrap>{candidates.map(port=><Tag color="blue" key={port}>{port} 开放候选</Tag>)}</Space>:<Text type="secondary">所选范围内未发现开放端口</Text>;
          }},
          {title:'登记时间',dataIndex:'createdAt',render:(value:string)=>new Date(value).toLocaleString()},
          {title:'操作',render:(_:unknown,asset:Asset)=>{
            const probe=tasks.find(task=>task.assetId===asset.id&&task.engines?.[0]==='port-probe'&&task.status==='COMPLETED');
            const candidates=(probe?.portProbeResults??[]).map(result=>result.port).filter(port=>!(asset.requestedPorts??[]).includes(port)&&!(asset.skippedPorts??[]).includes(port)&&!(asset.quarantinedPorts??[]).includes(port)&&!(asset.ports??[]).some(item=>item.port===port));
            return <Space wrap><Button type="link" disabled={!canEdit} onClick={()=>{
              editForm.setFieldsValue({businessGroup:asset.businessGroup,owner:asset.owner,requestedPorts:asset.requestedPorts?.join(', ')??'',skippedPorts:asset.skippedPorts?.join(', ')??''});
              setEditing(asset);
            }}>编辑信息</Button>{candidates.map(port=><Button key={port} size="small" disabled={!canEdit||isDemoMode||requestingPort===`${asset.id}:${port}`} loading={requestingPort===`${asset.id}:${port}`} onClick={()=>void requestCandidate(asset,port)}>申请 {port}</Button>)}</Space>;
          }}
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
        <Form.Item name="requestedPorts" label="目标端口" extra="英文逗号分隔，如 80,443；空值表示未申请">
          <Input placeholder="80, 443"/>
        </Form.Item>
        <Form.Item name="skippedPorts" label="跳过端口（Nginx 四层转发等）" extra="必须属于上面的目标端口，英文逗号分隔；不会下发给 Worker"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
    <Modal title={'编辑资产：'+(editing?.address??'')} open={!!editing}
      onCancel={()=>setEditing(null)} onOk={()=>editForm.submit()} okButtonProps={{loading:saving}}>
      <Form form={editForm} layout="vertical" onFinish={update}>
        <Form.Item name="businessGroup" label="业务组" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="owner" label="责任人" rules={[{required:true}]}><Input maxLength={100}/></Form.Item>
        <Form.Item name="requestedPorts" label="拟申请端口" extra="只是申请记录，不是扫描授权"><Input/></Form.Item>
        <Form.Item name="skippedPorts" label="跳过端口（Nginx 四层转发等）" extra="必须属于上面的目标端口，英文逗号分隔；不会下发给 Worker"><Input placeholder="例如 443"/></Form.Item>
      </Form>
    </Modal>
  </div>;
};
