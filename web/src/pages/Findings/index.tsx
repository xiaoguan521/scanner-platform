import React, { useState } from 'react';
import {
  Card,
  Table,
  Tag,
  Button,
  Space,
  Select,
  Typography,
  Alert,
  Tooltip,
  message,
} from 'antd';
import {
  SecurityScanOutlined,
  SafetyCertificateOutlined,
} from '@ant-design/icons';
import { mockFindings } from '../../mock/data';
import { Finding, FindingSeverity, FindingStatus } from '../../types';
import { isDemoMode } from '../../api/client';
import { useCollection } from '../../api/hooks';
import { CollectionNotice } from '../../api/CollectionNotice';

const { Text } = Typography;

export const FindingsPage: React.FC = () => {
  const { data: findings, setData: setFindings, loading, error } = useCollection('findings', mockFindings);
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [statusFilter, setStatusFilter] = useState<string>('ALL');

  const filteredFindings = findings.filter((f) => {
    if (severityFilter !== 'ALL' && f.severity !== severityFilter) return false;
    if (statusFilter !== 'ALL' && f.status !== statusFilter) return false;
    return true;
  });

  const handleUpdateStatus = (id: string, newStatus: FindingStatus) => {
    // FIXED is a Server-only decision based on a complete verified scan.
    if (newStatus === 'FIXED') {
      message.warning('FIXED 必须经 Server 确认完整扫描、规则执行和未检出阈值，目前不可操作');
      return;
    }
    if (!isDemoMode) {
      message.warning('真实漏洞状态变更必须由 Server 鉴权与审计');
      return;
    }
    setFindings((prev) => prev.map((f) => f.id === id ? { ...f, status: newStatus } : f));
    message.info('仅演示：本地漏洞状态已更新，Server 数据和审计日志没有变化');
  };

  const getSeverityTag = (sev: FindingSeverity) => {
    const map: Record<FindingSeverity, { color: string; label: string }> = {
      CRITICAL: { color: 'magenta', label: '严重 (Critical)' },
      HIGH: { color: 'red', label: '高危 (High)' },
      MEDIUM: { color: 'orange', label: '中危 (Medium)' },
      LOW: { color: 'blue', label: '低危 (Low)' },
      INFO: { color: 'default', label: '信息 (Info)' },
    };
    return <Tag color={map[sev].color}>{map[sev].label}</Tag>;
  };

  const getStatusTag = (status: FindingStatus) => {
    const map: Record<FindingStatus, { color: string; label: string }> = {
      OPEN: { color: 'error', label: '待修复 (OPEN)' },
      REOPENED: { color: 'error', label: '重新出现 (REOPENED)' },
      IN_PROGRESS: { color: 'processing', label: '修复中 (IN_PROGRESS)' },
      FIXED: { color: 'success', label: '已修复 (FIXED)' },
      FALSE_POSITIVE: { color: 'default', label: '误报静默 (FALSE_POSITIVE)' },
      ACCEPTED_RISK: { color: 'warning', label: '接受风险 (ACCEPTED_RISK)' },
    };
    return <Tag color={map[status].color}>{map[status].label}</Tag>;
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <CollectionNotice loading={loading} error={error} />
      <Alert
        message="稳定指纹与严苛 FIXED 判定规则 (架构硬规则 §7.1)"
        description="漏洞指纹仅由稳定字段（资产、端口、引擎、模板 ID、规范路径）哈希生成，不随扫描时间戳变化。只有在扫描完整完成且规则模板依旧存在的前提下未再检出，才允许转为 FIXED，防止误报闭环。"
        type="warning"
        showIcon
        icon={<SafetyCertificateOutlined />}
      />

      <Card
        title="漏洞发现与生命周期闭环看板"
        bordered={false}
        extra={
          <Space>
            <Select
              value={severityFilter}
              onChange={setSeverityFilter}
              style={{ width: 140 }}
              options={[
                { value: 'ALL', label: '全部等级' },
                { value: 'CRITICAL', label: '严重 (Critical)' },
                { value: 'HIGH', label: '高危 (High)' },
                { value: 'MEDIUM', label: '中危 (Medium)' },
                { value: 'LOW', label: '低危 (Low)' },
              ]}
            />
            <Select
              value={statusFilter}
              onChange={setStatusFilter}
              style={{ width: 140 }}
              options={[
                { value: 'ALL', label: '全部状态' },
                { value: 'OPEN', label: '待修复 (OPEN)' },
                { value: 'REOPENED', label: '重新出现 (REOPENED)' },
                { value: 'IN_PROGRESS', label: '修复中' },
                { value: 'FIXED', label: '已修复 (FIXED)' },
                { value: 'FALSE_POSITIVE', label: '误报' },
                { value: 'ACCEPTED_RISK', label: '接受风险' },
              ]}
            />
          </Space>
        }
      >
        <Table
          dataSource={filteredFindings}
          rowKey="id"
          columns={[
            {
              title: '等级',
              dataIndex: 'severity',
              width: 130,
              render: (s: FindingSeverity) => getSeverityTag(s),
            },
            {
              title: '漏洞详情与稳定指纹',
              render: (_, record) => (
                <Space direction="vertical" size={2}>
                  <Text strong>{record.title}</Text>
                  <Space size={8}>
                    <Tag color={record.engine === 'nuclei' ? 'purple' : 'cyan'}>
                      {record.engine.toUpperCase()}
                    </Tag>
                    <Text code>{record.templateOrCve}</Text>
                    <Tooltip title="归一化稳定指纹 (SHA256)">
                      <Space size={2} style={{ fontSize: 11, color: '#64748b' }}>
                        <SecurityScanOutlined />
                        <span>{record.fingerprint}</span>
                      </Space>
                    </Tooltip>
                  </Space>
                </Space>
              ),
            },
            {
              title: '目标地址',
              dataIndex: 'target',
              width: 220,
              render: (t: string) => <Text code>{t}</Text>,
            },
            {
              title: '业务归属',
              render: (_, r) => (
                <Space direction="vertical" size={2}>
                  <Text>{r.businessGroup}</Text>
                  <Text type="secondary" style={{ fontSize: 12 }}>
                    负责人: {r.owner}
                  </Text>
                </Space>
              ),
            },
            {
              title: '生命周期状态',
              dataIndex: 'status',
              width: 140,
              render: (s: FindingStatus) => getStatusTag(s),
            },
            {
              title: '最近检出 / 未检出计数',
              render: (_, r) => (
                <Space direction="vertical" size={1} style={{ fontSize: 12 }}>
                  <span>最近: {r.lastSeen}</span>
                  {r.status === 'FIXED' ? (
                    <Text type="success">连续未检出: {r.consecutiveMisses} 次</Text>
                  ) : (
                    <Text type="secondary">初见: {r.firstSeen}</Text>
                  )}
                </Space>
              ),
            },
            {
              title: '状态流转',
              width: 150,
              render: (_, r) => (
                <Space size={4}>
                  {r.status === 'OPEN' && (
                    <Button
                      type="link"
                      size="small"
                      disabled={!isDemoMode}
                      onClick={() => handleUpdateStatus(r.id, 'IN_PROGRESS')}
                    >
                      标记处理中
                    </Button>
                  )}
                  {r.status === 'IN_PROGRESS' && (
                    <Button
                      type="link"
                      size="small"
                      style={{ color: '#13c2c2' }}
                      disabled
                      onClick={() => handleUpdateStatus(r.id, 'FIXED')}
                    >
                      标记修复
                    </Button>
                  )}
                  {r.status !== 'FALSE_POSITIVE' && r.status !== 'FIXED' && (
                    <Button
                      type="link"
                      size="small"
                      danger
                      disabled={!isDemoMode}
                      onClick={() => handleUpdateStatus(r.id, 'FALSE_POSITIVE')}
                    >
                      误报
                    </Button>
                  )}
                </Space>
              ),
            },
          ]}
        />
      </Card>
    </div>
  );
};
