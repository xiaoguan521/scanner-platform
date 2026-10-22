import React, { useState } from 'react';
import {
  Layout,
  Menu,
  type MenuProps,
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
  FileTextOutlined,
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAppTheme } from '../../context/ThemeContext';
import { SystemStatusContext, useSystemStatus } from '../../api/hooks';
import { roleNames, StatusPill } from '../Semantic';
import { useAuth } from '../../auth/AuthProvider';
import { navigationLabel, visibleNavigation } from './navigation';

const { Header, Sider, Content } = Layout;

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, palette, toggleTheme } = useAppTheme();
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
  // Single-page groups are plain items; groups with several pages open as submenus.
  const menuItems: MenuProps['items'] = groups.map(group => group.children.length === 1
    ? { key: group.children[0].key, icon: icons[group.key], label: group.children[0].label }
    : { key: group.key, icon: icons[group.key], label: group.label, children: group.children.map(item => ({ key: item.key, label: item.label })) });
  const selectedLabel = navigationLabel(location.pathname, groups);
  const sectionLabel = groups.find(group => group.children.some(item => item.key === location.pathname))?.label;
  const serviceTone = error ? 'error' : status?.ready ? 'ok' : 'neutral';

  return (
    <Layout style={{ minHeight: '100vh', background: palette.bgLayout }}>
      <Sider
        breakpoint="lg"
        collapsedWidth={64}
        collapsible
        collapsed={collapsed}
        onCollapse={(val) => setCollapsed(val)}
        style={{ borderRight: `1px solid ${palette.borderSubtle}`, background: palette.bgSider }}
        width={232}
      >
        <div style={{ height: 64, display: 'flex', alignItems: 'center', padding: collapsed ? '0 17px' : '0 20px', gap: 10 }}>
          <svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke={palette.primary} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" style={{ flex: '0 0 auto' }}><path d="M12 3l7 3v5c0 4.5-3 8.2-7 10-4-1.8-7-5.5-7-10V6l7-3z" /><path d="M9 12l2 2 4-4" /></svg>
          {!collapsed && (
            <div style={{ overflow: 'hidden', whiteSpace: 'nowrap', display: 'flex', flexDirection: 'column' }}>
              <span style={{ fontWeight: 700, fontSize: 15, color: palette.text }}>安全扫描平台</span>
              <span style={{ fontSize: 12, color: palette.textTertiary }}>漏洞管理中心</span>
            </div>
          )}
        </div>

        <Menu
          mode="inline"
          selectedKeys={[location.pathname]}
          defaultOpenKeys={groups.filter(group => group.children.some(item => item.key === location.pathname)).map(group => group.key)}
          items={menuItems}
          onClick={({ key }) => navigate(key)}
          style={{ background: 'transparent', borderInlineEnd: 0, padding: '0 8px' }}
        />
      </Sider>

      <Layout style={{ minWidth: 0, background: palette.bgLayout }}>
        <Header
          style={{
            padding: '0 32px',
            background: palette.bgLayout,
            borderBottom: `1px solid ${palette.borderSubtle}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            minHeight: 56,
            height: 'auto',
            lineHeight: 'normal',
            flexWrap: 'wrap',
            gap: 12,
          }}
        >
          <nav aria-label="当前位置" style={{ fontSize: 13, color: palette.textTertiary }}>
            {sectionLabel && sectionLabel !== selectedLabel && <>{sectionLabel} / </>}
            <span style={{ color: palette.text }}>{selectedLabel || '控制台'}</span>
          </nav>

          <Space size="middle" wrap>
            <Tooltip title={error ? `平台连接失败：${error}` : status ? (status.ready ? '平台服务运行正常' : '平台服务尚未就绪') : '正在读取平台服务状态'}>
              <span aria-label="平台服务状态"><StatusPill tone={serviceTone}>{error ? '服务连接异常' : status?.ready ? '服务正常' : '服务未就绪'}</StatusPill></span>
            </Tooltip>
            <Tooltip title={isDark ? '切换至浅色模式' : '切换至深色模式'}>
              <Button
                type="text"
                aria-label={isDark ? '切换至浅色模式' : '切换至深色模式'}
                icon={isDark ? <BulbFilled /> : <BulbOutlined />}
                onClick={toggleTheme}
                style={{ color: palette.textSecondary }}
              />
            </Tooltip>
            {user && <Space size={8} style={{ fontSize: 13, color: palette.textSecondary }}><span>{user.username} · {roleNames[user.role] ?? user.role}</span><Button size="small" onClick={() => { void logout(); }}>退出</Button></Space>}
          </Space>
        </Header>

        <Content style={{ padding: '24px 32px 40px', minHeight: 280, overflowY: 'auto' }}>
          <SystemStatusContext.Provider value={systemStatus}>{children}</SystemStatusContext.Provider>
        </Content>
      </Layout>
    </Layout>
  );
};
