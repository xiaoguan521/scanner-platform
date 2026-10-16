import React, { useMemo, useState } from 'react';
import { Alert, Button, Card, Input, Space, Table, Tag, Tooltip, Typography } from 'antd';
import { PlusOutlined, UserOutlined } from '@ant-design/icons';
import { isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';
import { mockUsers } from '../../mock/users';
import type { User, UserRole } from '../../types';

const roleNames: Record<UserRole, string> = {
  admin: '系统管理员',
  security_engineer: '安全工程师',
  ops_approver: '运维审批人',
  viewer: '只读观察员',
};

export const UsersPage: React.FC = () => {
  const { data: users, loading, error } = useCollection('users', mockUsers);
  const [query, setQuery] = useState('');
  const rows = useMemo(
    () => users.filter((user) => user.username.toLowerCase().includes(query.trim().toLowerCase())),
    [users, query],
  );

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <CollectionNotice loading={loading} error={error} />
      <Alert
        type="warning"
        showIcon
        message={isDemoMode ? '用户管理演示：账号和角色均为示例数据' : '用户管理尚未接入身份认证与权限服务'}
        description="仅提供角色与用户列表的界面、数据契约。创建账号、授权角色、禁用用户、重置凭据均必须由 Server 完成认证、RBAC 校验和审计；当前不开放任何写操作。"
      />
      <Card
        title={<Space><UserOutlined /> 用户与角色管理</Space>}
        extra={
          <Space>
            <Input.Search
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="按用户名筛选"
              allowClear
              style={{ width: 220 }}
            />
            <Tooltip title="待 Server 登录、RBAC 与审计模块实现后开放">
              <Button type="primary" icon={<PlusOutlined />} disabled>
                新建用户
              </Button>
            </Tooltip>
          </Space>
        }
      >
        <Table<User>
          dataSource={rows}
          rowKey="id"
          loading={loading}
          pagination={{ pageSize: 10 }}
          columns={[
            { title: '用户 ID', dataIndex: 'id', width: 150 },
            { title: '用户名', dataIndex: 'username', render: (name: string) => <Typography.Text strong>{name}</Typography.Text> },
            {
              title: '角色',
              dataIndex: 'role',
              render: (role: UserRole) => <Tag color={role === 'admin' ? 'orange' : role === 'viewer' ? 'default' : 'blue'}>{roleNames[role]}</Tag>,
            },
            {
              title: '账号状态',
              dataIndex: 'isActive',
              render: (active: boolean) => <Tag color={active ? 'success' : 'default'}>{active ? '启用（仅演示）' : '停用'}</Tag>,
            },
            {
              title: '操作',
              render: () => (
                <Space>
                  <Button type="link" disabled>修改角色</Button>
                  <Button type="link" danger disabled>停用账号</Button>
                </Space>
              ),
            },
          ]}
        />
      </Card>
      <Card size="small" title="计划中的角色权限边界">
        <Typography.Text type="secondary">
          管理员、 安全工程师、 运维审批人和只读观察员是 V3.2 已定义的角色类别，但具体权限矩阵、登录会话、审计与管理审批尚未实现，不应据此前端显示判断用户具备任何后台权限。
        </Typography.Text>
      </Card>
    </div>
  );
};
