import React, { useMemo, useState } from 'react';
import { DataTable } from '../../components/DataState';
import { Alert, Button, Form, Input, message, Modal, Select, Space } from 'antd';
import { PlusOutlined } from '@ant-design/icons';
import { apiClient, errorMessage } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';
import { Mono, StatusPill, roleNames } from '../../components/Semantic';
import { PageHeader, Panel } from '../../components/Page';
import type { Tone } from '../../theme/palette';
import type { User, UserRole } from '../../types';

const roleOptions = Object.entries(roleNames).map(([value,label])=>({value,label}));

export const UsersPage: React.FC = () => {
  const {user:currentUser, isAdmin} = useAuth();
  const {data: users, setData: setUsers, loading, error} = useCollection('users');
  const [query,setQuery] = useState('');
  const [creating,setCreating] = useState(false);
  const [editing,setEditing] = useState<User|null>(null);
  const [resetting,setResetting] = useState<User|null>(null);
  const [busy,setBusy] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const [resetForm] = Form.useForm<{password:string;confirmPassword:string}>();
  const rows = useMemo(()=>users.filter(u=>u.username.toLowerCase().includes(query.trim().toLowerCase())),[users,query]);
  const canManage = isAdmin;

  const createUser = async (values:{username:string,password:string,role:UserRole}) => {
    setBusy(true);
    try {
      const result=await apiClient.createUser(values.username,values.password,values.role);
      setUsers(prev=>[...prev,result]);createForm.resetFields();setCreating(false);
      message.success('用户已创建');
    }catch(e){message.error(errorMessage(e,'创建失败'));}
    finally{setBusy(false);}
  };
  const editUser = async (values:{role:UserRole,isActive:boolean})=>{
    if(!editing)return;
    setBusy(true);
    try {
      const result=await apiClient.updateUser(editing.id,values.role,values.isActive);
      setUsers(prev=>prev.map(u=>u.id===result.id?result:u));setEditing(null);
      message.success('用户资料已更新');
    }catch(e){message.error(errorMessage(e,'更新失败'));}
    finally{setBusy(false);}
  };
  const resetPassword = async (values:{password:string;confirmPassword:string})=>{
    if(!resetting)return;
    if(values.password!==values.confirmPassword){message.error('两次输入的新密码不一致');return;}
    setBusy(true);
    try {
      await apiClient.resetUserPassword(resetting.id,values.password);
      setResetting(null);resetForm.resetFields();message.success(`已重置 ${resetting.username} 的密码，旧会话已失效`);
    }catch(e){message.error(errorMessage(e,'密码重置失败'));}
    finally{setBusy(false);}
  };
  const roleTones: Record<UserRole, Tone> = { admin: 'warning', security_engineer: 'running', ops_approver: 'ok', viewer: 'neutral' };
  const admins = users.filter(u => u.role === 'admin').length;
  const inactive = users.filter(u => !u.isActive).length;
  return <div style={{display:'flex',flexDirection:'column',gap:16}}>
    <PageHeader title="用户与角色" description={`共 ${users.length} 个账号 · 管理员 ${admins} 个${inactive ? ` · 已停用 ${inactive} 个` : ''}`}
      extra={<Button type="primary" icon={<PlusOutlined/>} disabled={!canManage} onClick={()=>setCreating(true)}>新建用户</Button>}/>
    <CollectionNotice loading={loading&&users.length===0} error={error}/>
    <Panel flush title="账号列表" extra={<Input.Search aria-label="用户搜索" value={query} onChange={e=>setQuery(e.target.value)} allowClear placeholder="搜索用户名" style={{width:220}}/>}>
      <DataTable<User> dataSource={rows} rowKey="id" loading={loading} tableLayout="fixed" pagination={{pageSize:10,hideOnSinglePage:true,showTotal:total=>`共 ${total} 个账号`}} locale={{emptyText:query?'没有符合条件的用户':'暂无用户'}}
        columns={[
          {title:'用户名',key:'username',render:(_:unknown,record:User)=><span style={{display:'flex',alignItems:'center',gap:8}}><Mono style={{fontWeight:600}}>{record.username}</Mono>{record.id===currentUser?.id&&<StatusPill tone="running">当前登录</StatusPill>}</span>},
          {title:'角色',key:'role',width:160,render:(_:unknown,record:User)=><StatusPill tone={roleTones[record.role]??'neutral'}>{roleNames[record.role]??record.role}</StatusPill>},
          {title:'账号状态',key:'active',width:120,render:(_:unknown,record:User)=><StatusPill tone={record.isActive?'ok':'neutral'}>{record.isActive?'启用':'停用'}</StatusPill>},
          {title:'操作',key:'actions',width:220,render:(_:unknown,record:User)=><Space size={0}><Button type="link" size="small" disabled={!canManage || record.id===currentUser?.id} onClick={()=>{
            editForm.setFieldsValue({role:record.role,isActive:record.isActive});setEditing(record);
          }}>修改角色 / 状态</Button><Button type="link" size="small" disabled={!canManage} onClick={()=>{resetForm.resetFields();setResetting(record);}}>重置密码</Button></Space>},
        ]}/>
    </Panel>
    <Modal title="新增用户" open={creating} onOk={()=>createForm.submit()} onCancel={()=>setCreating(false)} okButtonProps={{loading:busy}}>
      <Form form={createForm} layout="vertical" onFinish={createUser} autoComplete="off">
        <Form.Item name="username" label="用户名" rules={[{required:true},{pattern:/^[a-zA-Z][a-zA-Z0-9_.-]{2,39}$/,message:'3–40 位，以英文字母开头'}]}><Input/></Form.Item>
        <Form.Item name="password" label="初始密码" rules={[{required:true},{min:12,message:'至少 12 个字符'}]}><Input.Password autoComplete="new-password"/></Form.Item>
        <Form.Item name="role" label="角色" initialValue="viewer" rules={[{required:true}]}><Select options={roleOptions}/></Form.Item>
      </Form>
    </Modal>
    <Modal title={'修改 ' + (editing?.username ?? '')} open={!!editing} onOk={()=>editForm.submit()} onCancel={()=>setEditing(null)} okButtonProps={{loading:busy}}>
      <Form form={editForm} layout="vertical" onFinish={editUser}>
        <Form.Item name="role" label="角色" rules={[{required:true}]}><Select options={roleOptions}/></Form.Item>
        <Form.Item name="isActive" label="启用状态" rules={[{required:true}]}><Select options={[{value:true,label:'启用'},{value:false,label:'停用'}]}/></Form.Item>
      </Form>
    </Modal>
    <Modal title={'重置 ' + (resetting?.username ?? '') + ' 的密码'} open={!!resetting} onOk={()=>resetForm.submit()} onCancel={()=>{if(busy)return;setResetting(null);resetForm.resetFields();}} okButtonProps={{loading:busy}} destroyOnClose>
      <Alert type="warning" showIcon message="重置后旧会话立即失效" description="新密码不会写入审计日志或返回页面；请通过安全渠道交付给用户。" style={{marginBottom:16}}/>
      <Form form={resetForm} layout="vertical" onFinish={resetPassword} autoComplete="off">
        <Form.Item name="password" label="新密码" rules={[{required:true},{min:12,message:'至少 12 个字符'},{max:72,message:'最多 72 个字节'}]}><Input.Password autoComplete="new-password"/></Form.Item>
        <Form.Item name="confirmPassword" label="确认新密码" dependencies={['password']} rules={[{required:true},{validator:(_,value)=>value===resetForm.getFieldValue('password')?Promise.resolve():Promise.reject(new Error('两次输入的新密码不一致'))}]}><Input.Password autoComplete="new-password"/></Form.Item>
      </Form>
    </Modal>
  </div>;
};
