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
} from '@ant-design/icons';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAppTheme } from '../../context/ThemeContext';

const { Header, Sider, Content } = Layout;

export const AppLayout: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [collapsed, setCollapsed] = useState(false);
  const navigate = useNavigate();
  const location = useLocation();
  const { isDark, toggleTheme } = useAppTheme();
  const { token } = theme.useToken();

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
  ];

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Sider
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

      <Layout>
        <Header
          style={{
            padding: '0 24px',
            background: isDark ? '#0f172a' : '#ffffff',
            borderBottom: `1px solid ${token.colorBorderSecondary}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            height: 64,
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
            <span style={{ fontSize: 16, fontWeight: 600 }}>
              {menuItems.find((m) => m.key === location.pathname)?.label || '控制台'}
            </span>
            <Tag color="blue" bordered={false}>
              Phase 0 PoC
            </Tag>
          </div>

          <Space size="large">
            {/* 系统状态小部件 */}
            <Tooltip title="控制面唯一连库 (PostgreSQL / SQLite)">
              <Space size={6}>
                <Badge status="processing" color="#13c2c2" />
                <span style={{ fontSize: 13, color: '#94a3b8' }}>sec-server 在线</span>
              </Space>
            </Tooltip>

            <Tooltip title="当前激活的 CURRENT 规则包版本">
              <Tag color="cyan" style={{ margin: 0 }}>
                规则库: v2026.10.15-rel
              </Tag>
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
          {children}
        </Content>
      </Layout>
    </Layout>
  );
};
