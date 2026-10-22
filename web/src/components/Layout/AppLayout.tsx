import React, { useState } from 'react';
import {
  Layout,
  Menu,
  type MenuProps,
  theme,
  Badge,
  Space,
  Button,
  Tooltip,
} from 'antd';
import {
  DashboardOutlined,
  ApartmentOutlined,
  RadarChartOutlined,
  BugOutlined,
  ClusterOutlined,
  BulbOutlined,
  BulbFilled,
  SafetyCertificateOutlined,
  FileTextOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAppTheme } from '../../context/ThemeContext';
import { SystemStatusContext, useSystemStatus } from '../../api/hooks';
import { roleNames } from '../Semantic';
import { useAuth } from '../../auth/AuthProvider';
import { navigationLabel, visibleNavigation } from './navigation';

const { Header, Sider, Content } = Layout;

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useAppTheme();
  const { token } = theme.useToken();
  const systemStatus = useSystemStatus();
  const { status, error } = systemStatus;
  const { user, logout } = useAuth();
  const groups = visibleNavigation(user?.role);
  const icons: Record<string, React.ReactNode> = {
    overview: <DashboardOutlined />,
    assets: <ApartmentOutlined />,
    scans: <RadarChartOutlined />,
    findings: <BugOutlined />,
    reports: <FileTextOutlined />,
    system: <ClusterOutlined />,
  };
  const menuItems: MenuProps['items'] = groups.map(group => ({
    key: group.key,
    icon: icons[group.key],
    label: group.label,
    children: group.children.map(item => ({ key: item.key, label: item.label })),
  }));
  const selectedLabel = navigationLabel(location.pathname, groups);

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
          <SafetyCertificateOutlined style={{ fontSize: 26, color: token.colorPrimary }} />
          {!collapsed && (
            <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
              <div style={{ fontWeight: 700, fontSize: 15, letterSpacing: '0.5px' }}>
                安全扫描平台
              </div>
              <div style={{ fontSize: 11, color: token.colorTextSecondary }}>企业级漏洞管理中心</div>
            </div>
          )}
        </div>

        <Menu
          theme={isDark ? 'dark' : 'light'}
          mode="inline"
          selectedKeys={[location.pathname]}
          defaultOpenKeys={groups.map(group => group.key)}
          items={menuItems}
          onClick={({ key }) => {
            const group = groups.find(item => item.key === key);
            navigate(group?.defaultPath ?? key);
          }}
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
          <span style={{ fontSize: 16, fontWeight: 600 }}>
            {selectedLabel || '控制台'}
          </span>

          <Space size="middle" wrap>
            <Tooltip title={error ? `平台连接失败：${error}` : status ? (status.ready ? '平台服务运行正常' : '平台服务尚未就绪') : '正在读取平台服务状态'}>
              <Space size={6} aria-label="平台服务状态">
                <Badge status={error ? 'error' : status?.ready ? 'success' : 'default'} />
                <span style={{ fontSize: 13, color: token.colorTextTertiary }}>
                  {error ? '服务连接异常' : status?.ready ? '服务正常' : '服务未就绪'}
                </span>
              </Space>
            </Tooltip>
            <Tooltip title={isDark ? '切换至浅色模式' : '切换至深色模式'}>
              <Button
                type="text"
                shape="circle"
                aria-label={isDark ? '切换至浅色模式' : '切换至深色模式'}
                icon={isDark ? <BulbFilled style={{ color: token.gold }} /> : <BulbOutlined />}
                onClick={toggleTheme}
              />
            </Tooltip>
            {user && <Space size={8}><span>{user.username} · {roleNames[user.role] ?? user.role}</span><Button size="small" onClick={() => { void logout(); }}>退出</Button></Space>}
          </Space>
        </Header>

        <Content
          style={{
            padding: 24,
            minHeight: 280,
            overflowY: 'auto',
          }}
        >
          <SystemStatusContext.Provider value={systemStatus}>{children}</SystemStatusContext.Provider>
        </Content>
      </Layout>
    </Layout>
  );
};
