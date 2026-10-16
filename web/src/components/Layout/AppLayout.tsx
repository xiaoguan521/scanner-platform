import React, { useState } from 'react';
import {
  Layout,
  Menu,
  theme,
  Badge,
  Space,
  Tag,
  Button,
  Tooltip,
  Alert,
} from 'antd';
import {
  DashboardOutlined,
  ApartmentOutlined,
  CalendarOutlined,
  RadarChartOutlined,
  BugOutlined,
  ClusterOutlined,
  BulbOutlined,
  BulbFilled,
  SafetyCertificateOutlined,
  TeamOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAppTheme } from '../../context/ThemeContext';
import { isDemoMode } from '../../api/client';
import { useSystemStatus } from '../../api/hooks';
import { useAuth } from '../../auth/AuthProvider';

const { Header, Sider, Content } = Layout;

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useAppTheme();
  const { token } = theme.useToken();
  const { status, error } = useSystemStatus();
  const { user, logout } = useAuth();

  const menuItems = [
    {
      key: '/',
      icon: <DashboardOutlined />,
      label: '态势大屏',
    },
    {
      key: '/assets',
      icon: <ApartmentOutlined />,
      label: '资产与端口准入',
    },
    {
      key: '/scopes',
      icon: <CalendarOutlined />,
      label: '授权与时间窗',
    },
    {
      key: '/tasks',
      icon: <RadarChartOutlined />,
      label: '扫描任务中心',
    },
    {
      key: '/findings',
      icon: <BugOutlined />,
      label: '漏洞生命周期',
    },
    {
      key: '/nodes',
      icon: <ClusterOutlined />,
      label: '节点与规则版本',
    },
    {
      key: '/users',
      icon: <TeamOutlined />,
      label: '用户与权限',
    },
  ].filter(item => item.key !== '/users' || isDemoMode || user?.role === 'admin');

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
        breakpoint="lg"
        collapsedWidth={64}
        collapsible
        collapsed={collapsed}
        onCollapse={(val) => setCollapsed(val)}
        style={{
          borderRight: `1px solid ${token.colorBorderSecondary}`,
          background: isDark ? '#0f172a' : '#ffffff',
        }}
        width={220}
      >
        <div
          style={{
            height: 64,
            display: 'flex',
            alignItems: 'center',
            padding: '0 16px',
            gap: 10,
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
          }}
        >
          <SafetyCertificateOutlined style={{ fontSize: 26, color: '#1677ff' }} />
          {!collapsed && (
            <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
              <div style={{ fontWeight: 700, fontSize: 15, letterSpacing: '0.5px' }}>
                安全扫描平台
              </div>
              <div style={{ fontSize: 11, color: '#64748b' }}>企业级漏洞管理中心</div>
            </div>
          )}
        </div>

        <Menu
          theme={isDark ? 'dark' : 'light'}
          mode="inline"
          selectedKeys={[location.pathname]}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ background: 'transparent', borderRight: 0, marginTop: 8 }}
        />
      </Sider>

      <Layout style={{minWidth:0}}>
        <Header
          style={{
            padding: '0 24px',
            background: isDark ? '#0f172a' : '#ffffff',
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            minHeight: 64,
            height: 'auto',
            flexWrap: 'wrap',
            gap: 8,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: 16, fontWeight: 600 }}>
              {menuItems.find((m) => m.key === location.pathname)?.label || '控制台'}
            </span>
            <Tag color="blue" bordered={false}>
              {status?.enabled.includes('synthetic-worker') ? '早期开发 · 本地运行' : 'Phase 0 PoC'}
            </Tag>
          </div>

          <Space size="middle" wrap>
            {!isDemoMode && user && <Space size={8}><span>{user.username} · {user.role}</span><Button size="small" onClick={() => { void logout(); }}>退出</Button></Space>}
            <Tooltip title={isDemoMode ? '演示数据，不代表真实运行状态' : error ?? '来自 Server 的控制面状态（不是扫描器状态）'}>
              <Space size={6}>
                <Badge status={status?.ready ? 'success' : 'default'} />
                <span style={{ fontSize: 13, color: '#94a3b8' }}>
                  {isDemoMode ? '演示模式 · 非实时' : error ? 'Server 连接失败' : status ? `Server: ${status.state}（${status.ready ? "就绪" : "未就绪"}）` : '读取 Server 状态…'}
                </span>
              </Space>
            </Tooltip>
            <Tooltip title="实际规则激活版本需由 Server/Updater 验证并提供">
              <Tag style={{ margin: 0 }}>规则版本见节点页</Tag>
            </Tooltip>

            <Tooltip title={isDark ? '切换至浅色模式' : '切换至暗色科技模式'}>
              <Button
                type="text"
                shape="circle"
                icon={isDark ? <BulbFilled style={{ color: '#faad14' }} /> : <BulbOutlined />}
                onClick={toggleTheme}
              />
            </Tooltip>
          </Space>
        </Header>

        <Content
          style={{
            padding: 24,
            minHeight: 280,
            overflowY: 'auto',
          }}
        >
          <Alert
            type={isDemoMode ? 'info' : 'warning'}
            showIcon
            style={{ marginBottom: 16 }}
            message={isDemoMode ? '演示模式：所有资产、任务、漏洞及节点信息均为模拟数据' : status?.enabled.includes('synthetic-worker') ? '本地框架运行中：任务和结果已接入 SQLite' : '账号管理已连接 Server；扫描业务仍未开放'}
            description={status?.enabled.includes('synthetic-worker') ? '可选择模拟任务或已接入的扫描引擎；只有明确创建的真实任务才连接指定目标，跳过标记和时间窗仍生效。' : isDemoMode ? '演示操作仅影响当前浏览器内的页面；不会发起扫描、写数据库、解除隔离或生成审计。' : error ? `Server 状态接口不可用：${error}` : '本地业务已接 SQLite；引擎就绪状态见节点页面。'}
          />
          {children}
        </Content>
      </Layout>
    </Layout>
  );
};
