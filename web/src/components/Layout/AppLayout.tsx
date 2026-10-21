import React, { useState } from 'react';
import {
  Layout,
  Menu,
  type MenuProps,
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
import { useSystemStatus } from '../../api/hooks';
import { useAuth } from '../../auth/AuthProvider';
import { navigationLabel, visibleNavigation } from './navigation';

const { Header, Sider, Content } = Layout;

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useAppTheme();
  const { token } = theme.useToken();
  const { status, error } = useSystemStatus();
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
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: 16, fontWeight: 600 }}>
              {selectedLabel || '控制台'}
            </span>
            <Tag color="blue" bordered={false}>
              {status?.enabled.includes('synthetic-worker') ? '早期开发 · 本地运行' : 'Phase 0 PoC'}
            </Tag>
          </div>

          <Space size="middle" wrap>
            {user && <Space size={8}><span>{user.username} · {user.role}</span><Button size="small" onClick={() => { void logout(); }}>退出</Button></Space>}
            <Tooltip title={error ?? '来自 Server 的控制面状态（不是扫描器状态）'}>
              <Space size={6}>
                <Badge status={status?.ready ? 'success' : 'default'} />
                <span style={{ fontSize: 13, color: '#94a3b8' }}>
                  {error ? 'Server 连接失败' : status ? `Server: ${status.state}（${status.ready ? "就绪" : "未就绪"}）` : '读取 Server 状态…'}
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
            type="warning"
            showIcon
            style={{ marginBottom: 16 }}
            message={status?.enabled.includes('synthetic-worker') ? '本地框架运行中：任务和结果已接入 SQLite' : '账号管理已连接 Server；扫描业务仍未开放'}
            description={status?.enabled.includes('synthetic-worker') ? '只有明确创建的真实任务才连接指定目标，跳过标记和时间窗仍生效。' : error ? `Server 状态接口不可用：${error}` : '本地业务已接 SQLite；引擎就绪状态见节点页面。'}
          />
          {children}
        </Content>
      </Layout>
    </Layout>
  );
};
