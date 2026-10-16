import React, { useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, message, Modal, Select, Space, Table, Tag, Typography } from 'antd';
import { PlusOutlined, UserOutlined } from '@ant-design/icons';
import { isDemoMode, apiClient } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { useAuth } from '../../auth/AuthProvider';
import { mockUsers } from '../../mock/users';
import type { User, UserRole } from '../../types';

const roleNames: Record<UserRole, string> = {
  admin: '系统管理员',
  security_engineer: '安全工程师',
  ops_approver: '运维审批人',
  viewer: '只读观察员',
};
const roleOptions = Object.entries(roleNames).map(([value,label])=>({value,label}));

export const UsersPage: React.FC = () => {
  const {user:currentUser} = useAuth();
  const {data: users, setData: setUsers, loading, error} = useCollection('users', mockUsers);
  const [query,setQuery] = useState('');
  const [creating,setCreating] = useState(false);
  const [editing,setEditing] = useState<User|null>(null);
  const [busy,setBusy] = useState(false);
  const [createForm] = Form.useForm();
  const [editForm] = Form.useForm();
  const rows = useMemo(()=>users.filter(u=>u.username.toLowerCase().includes(query.trim().toLowerCase())),[users,query]);
  const canManage = !isDemoMode && currentUser?.role==='admin';

  const createUser = async (values:{username:string,password:string,role:UserRole}) => {
    setBusy(true);
    try {
      const result=await apiClient.createUser(values.username,values.password,values.role);
      setUsers(prev=>[...prev,result]);createForm.resetFields();setCreating(false);
      message.success('用户已创建并写入 SQLite');
    }catch(e){message.error(e instanceof Error ? e.message:'创建失败');}
    finally{setBusy(false);}
  };
  const editUser = async (values:{role:UserRole,isActive:boolean})=>{
    if(!editing)return;
    setBusy(true);
    try {
      const result=await apiClient.updateUser(editing.id,values.role,values.isActive);
      setUsers(prev=>prev.map(u=>u.id===result.id?result:u));setEditing(null);
      message.success('用户资料已更新');
    }catch(e){message.error(e instanceof Error ? e.message:'更新失败');}
    finally{setBusy(false);}
  };
  return <div style={{display:'flex',flexDirection:'column',gap:20}}>
    <CollectionNotice loading={loading} error={error}/>
    <Alert showIcon type={isDemoMode?'info':'success'}
      message={isDemoMode?'用户管理演示：数据未连接数据库':'用户管理：已连接 SQLite'}
      description={isDemoMode?'请使用 VITE_DATA_MODE=server 启动前端，并初始化管理员后登录。':'管理员可以创建、修改角色及启停用户。其余扫描业务仍未启用。'}/>
    <Card title={<Space><UserOutlined/> 用户与角色管理</Space>}
      extra={<Space><Input.Search value={query} onChange={e=>setQuery(e.target.value)} allowClear placeholder="搜索用户名" style={{width:180}}/>
        <Button type="primary" icon={<PlusOutlined/>} disabled={!canManage} onClick={()=>setCreating(true)}>新建用户</Button>
      </Space>}>
      <Table<User> dataSource={rows} rowKey="id" loading={loading} pagination={{pageSize:10}}
        columns={[
          {title:'用户名',dataIndex:'username',render:(name:string)=><Typography.Text strong>{name}</Typography.Text>},
          {title:'角色',dataIndex:'role',render:(role:UserRole)=><Tag color={role==='admin'?'orange':'blue'}>{roleNames[role]}</Tag>},
          {title:'账号状态',dataIndex:'isActive',render:(active:boolean)=><Tag color={active?'success':'default'}>{active?'启用':'停用'}</Tag>},
          {title:'操作',render:(_:unknown,record:User)=><Button type="link" disabled={!canManage || record.id===currentUser?.id} onClick={()=>{
            editForm.setFieldsValue({role:record.role,isActive:record.isActive});setEditing(record);
          }}>修改角色 / 状态</Button>},
        ]}/>
    </Card>
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
  </div>;
};
