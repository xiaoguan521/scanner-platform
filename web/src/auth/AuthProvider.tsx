import React, { createContext, useContext, useEffect, useMemo, useState } from 'react';
import { Alert, Button, Card, Form, Input, Spin, Typography } from 'antd';
import { apiClient, ApiRequestError, isDemoMode } from '../api/client';
import type { User } from '../types';

interface AuthState {
  user: User | null;
  logout: () => Promise<void>;
}
const Context = createContext<AuthState>({user:null,logout:async()=>{}});
export const useAuth = () => useContext(Context);

export const AuthProvider: React.FC<{children:React.ReactNode}> = ({children}) => {
  const [user,setUser] = useState<User|null>(null);
  const [loading,setLoading] = useState(!isDemoMode);
  const [error,setError] = useState('');
  const [setupRequired,setSetupRequired] = useState(false);
  const [submitting,setSubmitting] = useState(false);
  useEffect(()=>{
    if(isDemoMode) return;
    apiClient.setupStatus().then(v=>setSetupRequired(v.required)).catch(()=>{});
    const expired=()=>{setUser(null);};
    window.addEventListener('scanner-session-expired',expired);
    apiClient.me().then(setUser).catch((cause:unknown)=>{
      if (!(cause instanceof ApiRequestError && cause.status===401)) setError('无法连接 Server，请先启动 Go 服务。');
    }).finally(()=>setLoading(false));
    return ()=>window.removeEventListener('scanner-session-expired',expired);
  },[]);
  const logout=async()=>{try{await apiClient.logout();}finally{setUser(null);}};
  const state=useMemo(()=>({user,logout}),[user]);
  if(isDemoMode) return <Context.Provider value={state}>{children}</Context.Provider>;
  if(loading) return <div style={{display:'grid',placeItems:'center',height:'100vh'}}><Spin size="large" /></div>;
  if(!user) return (
    <div style={{minHeight:'100vh',display:'grid',placeItems:'center',background:'#f1f5f9',padding:20}}>
      <Card title={setupRequired ? "首次使用 · 创建管理员" : "安全扫描平台 · 登录"} style={{width:'100%',maxWidth:430}}>
        <Typography.Paragraph type="secondary">本地开发版：账号来自 SQLite，扫描服务仍未启用。</Typography.Paragraph>
        {error && <Alert showIcon type="warning" message={error} style={{marginBottom:16}}/>}
        <Form layout="vertical" autoComplete="off" onFinish={async(values:{username:string,password:string})=>{
          setSubmitting(true);setError('');
          try{if(setupRequired){await apiClient.setup(values.username,values.password);setSetupRequired(false);} setUser(await apiClient.login(values.username,values.password));}
          catch(cause){setError(cause instanceof ApiRequestError&&cause.status===429?'登录尝试过多，请稍后再试':setupRequired?'初始化失败：用户名需 3–40 位，密码需 12–72 字节，或管理员已存在':'账号或密码错误，或 Server 不可用');}
          finally{setSubmitting(false);}
        }}>
          <Form.Item name="username" label="用户名" rules={[{required:true}]}><Input autoComplete="username"/></Form.Item>
          <Form.Item name="password" label="密码" rules={[{required:true}]}><Input.Password autoComplete="current-password"/></Form.Item>
          <Button block type="primary" htmlType="submit" loading={submitting}>{setupRequired ? "创建管理员并登录" : "登录"}</Button>
        </Form>
        <Typography.Paragraph style={{marginTop:16}} type="secondary">
          {setupRequired ? "设置自己的管理员账号和 12–72 字节密码；不会创建默认密码。" : "账号与会话由本机 Server 管理。"}
        </Typography.Paragraph>
      </Card>
    </div>);
  return <Context.Provider value={state}>{children}</Context.Provider>;
};
