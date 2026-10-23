import React, { useEffect, useState } from 'react';
import { Button, Table, Tooltip } from 'antd';
import { DownOutlined, RightOutlined } from '@ant-design/icons';
import { DataTable } from '../../components/DataState';
import { FindingStatusTag, Mono, SeverityTag, findingStatusMeta } from '../../components/Semantic';
import { useAppTheme } from '../../context/ThemeContext';
import { apiClient, errorMessage } from '../../api/client';
import type { FindingGroup, FindingGroupPage, FindingQueryOptions } from '../../api/client';
import { formatTime } from '../../utils/time';
import type { Finding } from '../../types';

const statusOrder = ['OPEN', 'REOPENED', 'IN_PROGRESS', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'FIXED'] as const;
const clampTwoLines: React.CSSProperties = { display: '-webkit-box', WebkitLineClamp: 2, WebkitBoxOrient: 'vertical', overflow: 'hidden', overflowWrap: 'anywhere' };

/** Findings of one group, loaded when the group row is expanded. */
const GroupFindings: React.FC<{
  by: 'cve' | 'package';
  groupKey: string;
  total: number;
  options: FindingQueryOptions;
  revision: number;
  onLoaded: (items: Finding[]) => void;
  onOpen: (finding: Finding, trigger: HTMLElement) => void;
  onBatch: () => void;
}> = ({ by, groupKey, total, options, revision, onLoaded, onOpen, onBatch }) => {
  const { palette } = useAppTheme();
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<Finding[]>([]);
  const [count, setCount] = useState(total);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const optionsKey = JSON.stringify(options);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    const exact = by === 'cve' ? { cve: groupKey } : { package: groupKey };
    apiClient.findingsPage(page, 10, { ...options, ...exact, sort: '-severity' }, controller.signal).then(result => {
      if (controller.signal.aborted) return;
      setItems(result.items); setCount(result.total); setError(''); onLoaded(result.items);
    }).catch(cause => { if (!controller.signal.aborted) setError(errorMessage(cause,'明细加载失败')); })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // options is compared through optionsKey; onLoaded only forwards results.
  }, [by, groupKey, page, optionsKey, revision]);
  const muted = { color: palette.textSecondary };
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8, padding: '4px 0 8px' }}>
      {error && <span style={{ color: palette.error }}>{error}</span>}
      <Table<Finding>
        size="small"
        rowKey="id"
        loading={loading}
        dataSource={items}
        tableLayout="fixed"
        pagination={count > 10 ? { current: page, pageSize: 10, total: count, size: 'small', showSizeChanger: false, onChange: setPage } : false}
        columns={[
          { title: '等级', key: 'severity', width: 90, render: (_, f) => <SeverityTag value={f.severity} /> },
          by === 'package'
            ? { title: '漏洞', key: 'cve', render: (_, f) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><Mono>{f.templateOrCve}</Mono><span style={{ ...muted, ...clampTwoLines, fontSize: 12 }} title={f.title}>{f.title}</span></div> }
            : { title: '软件包 / 版本', key: 'package', render: (_, f) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><Mono>{f.package || '—'}</Mono><span style={{ fontSize: 12, overflowWrap: 'anywhere' }}><Mono style={muted}>{f.installedVersion || '—'}</Mono><span style={{ color: palette.textTertiary }}> → </span>{f.fixedVersion ? <Mono style={{ color: palette.success }}>{f.fixedVersion}</Mono> : <span style={{ color: palette.textTertiary }}>暂无修复版本</span>}</span></div> },
          { title: '目标', key: 'target', width: 180, render: (_, f) => <Mono style={{ overflowWrap: 'anywhere' }}>{f.target}</Mono> },
          { title: '状态', key: 'status', width: 130, render: (_, f) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, alignItems: 'flex-start' }}><FindingStatusTag value={f.status} />{(f.assigneeName || f.assigneeId) && <span style={{ fontSize: 12, ...muted }}>{f.assigneeName || f.assigneeId}</span>}</div> },
          { title: '最近检出', key: 'lastSeen', width: 160, render: (_, f) => <span style={{ fontSize: 12, ...muted }}>{formatTime(f.lastSeen,'—')}</span> },
          { title: '', key: 'action', width: 100, render: (_, f) => <Button size="small" aria-label={`查看详情：${f.title}`} onClick={event => { event.stopPropagation(); onOpen(f, event.currentTarget); }}>查看详情</Button> },
        ]}
      />
      <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 8, fontSize: 12, ...muted }}>
        <span>本组共 {count} 项发现；单条处置请打开详情，需要批量处置时进入平铺视图。</span>
        <Button size="small" onClick={onBatch}>在平铺视图中批量处置</Button>
      </div>
    </div>
  );
};

/** Aggregated findings by CVE / template ID or by software package, paged by the Server. */
export const FindingGroups: React.FC<{
  by: 'cve' | 'package';
  options: FindingQueryOptions;
  revision: number;
  onDrill: (key: string) => void;
  onOpen: (finding: Finding, trigger: HTMLElement) => void;
  onLoaded: (items: Finding[]) => void;
  onSummary: (summary: Pick<FindingGroupPage, 'findings' | 'counts' | 'total'> | null, error: string | null) => void;
}> = ({ by, options, revision, onDrill, onOpen, onLoaded, onSummary }) => {
  const { palette } = useAppTheme();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [data, setData] = useState<FindingGroupPage | null>(null);
  const [loading, setLoading] = useState(true);
  const [expanded, setExpanded] = useState<string[]>([]);
  const optionsKey = JSON.stringify(options);
  useEffect(() => { setPage(1); setExpanded([]); }, [by, optionsKey]);
  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    apiClient.findingGroups(by, page, pageSize, options, controller.signal).then(result => {
      if (controller.signal.aborted) return;
      setData(result);
      onSummary({ findings: result.findings, counts: result.counts, total: result.total }, null);
    }).catch(cause => {
      if (controller.signal.aborted) return;
      setData(null);
      onSummary(null, errorMessage(cause,'聚合结果加载失败'));
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // options is compared through optionsKey; onSummary only forwards results.
  }, [by, page, pageSize, optionsKey, revision]);

  const toggle = (key: string) => setExpanded(current => current.includes(key) ? current.filter(item => item !== key) : [...current, key]);
  const statusBar = (group: FindingGroup) => {
    const tones = { OPEN: palette.severity.HIGH.solid, REOPENED: palette.severity.CRITICAL.solid, IN_PROGRESS: palette.primary, ACCEPTED_RISK: palette.severity.MEDIUM.solid, FALSE_POSITIVE: palette.textTertiary, FIXED: palette.success };
    const label = statusOrder.filter(status => group.statusCounts[status]).map(status => `${findingStatusMeta[status].label} ${group.statusCounts[status]}`).join('，');
    return <Tooltip title={label}><div role="img" aria-label={label} style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1, background: palette.borderSubtle }}>
      {statusOrder.map(status => group.statusCounts[status] ? <div key={status} style={{ flex: group.statusCounts[status], background: tones[status] }} /> : null)}
    </div></Tooltip>;
  };
  const fixedVersions = (fixed?: string[]) => fixed?.length
    ? <Mono style={{ color: palette.success, overflowWrap: 'anywhere' }}>{fixed.join(' / ')}</Mono>
    : <span style={{ color: palette.textTertiary }}>暂无修复版本</span>;
  const expandButton = (group: FindingGroup) => {
    const open = expanded.includes(group.key);
    return <Button size="small" type={open ? 'default' : 'text'} aria-expanded={open} aria-label={`${open ? '收起' : '展开'}明细：${group.key}`} icon={open ? <DownOutlined /> : <RightOutlined />} onClick={event => { event.stopPropagation(); toggle(group.key); }}>{open ? '收起' : '明细'}</Button>;
  };
  const shared = {
    severity: { title: '最高等级', key: 'severity', width: 92, render: (_: unknown, group: FindingGroup) => <SeverityTag value={group.maxSeverity} /> },
    count: { title: '发现项', key: 'count', width: 76, render: (_: unknown, group: FindingGroup) => <Mono>{group.count}</Mono> },
    assets: { title: '资产', key: 'assets', width: 64, render: (_: unknown, group: FindingGroup) => <Mono>{group.assetCount}</Mono> },
    status: { title: '处置进度', key: 'status', width: 100, render: (_: unknown, group: FindingGroup) => statusBar(group) },
    action: { title: '', key: 'action', width: 88, render: (_: unknown, group: FindingGroup) => expandButton(group) },
  };
  const columns = by === 'cve' ? [
    { title: '漏洞编号', key: 'key', render: (_: unknown, group: FindingGroup) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><Mono style={{ fontWeight: 600 }}>{group.key}</Mono>{group.title && <span style={{ color: palette.textSecondary, fontSize: 12, ...clampTwoLines }} title={group.title}>{group.title}</span>}</div> },
    shared.severity,
    { title: '受影响软件包', key: 'packages', width: 160, render: (_: unknown, group: FindingGroup) => group.packages?.length ? <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{group.packages.map(name => <Mono key={name} style={{ padding: '0 6px', borderRadius: 4, background: palette.bgElevated, fontSize: 12, overflowWrap: 'anywhere' }}>{name}</Mono>)}</span> : <span style={{ color: palette.textTertiary }}>—</span> },
    { title: '修复版本', key: 'fixed', width: 160, render: (_: unknown, group: FindingGroup) => fixedVersions(group.fixedVersions) },
    shared.count, shared.assets, shared.status, shared.action,
  ] : [
    { title: '软件包', key: 'key', width: 220, render: (_: unknown, group: FindingGroup) => <Mono style={{ fontWeight: 600, overflowWrap: 'anywhere' }}>{group.key}</Mono> },
    { title: '安装版本 → 修复版本', key: 'versions', render: (_: unknown, group: FindingGroup) => <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'baseline', minWidth: 0 }}><Mono style={{ color: palette.textSecondary, overflowWrap: 'anywhere' }}>{group.installedVersions?.join(' / ') || '—'}</Mono><span style={{ color: palette.textTertiary }}>→</span>{fixedVersions(group.fixedVersions)}</span> },
    { title: '漏洞数', key: 'cves', width: 76, render: (_: unknown, group: FindingGroup) => <Mono>{group.cveCount ?? 0}</Mono> },
    shared.severity, shared.count, shared.assets, shared.status, shared.action,
  ];

  return <>
    <DataTable<FindingGroup>
      rowKey="key"
      dataSource={data?.items ?? []}
      loading={loading}
      columns={columns}
      tableLayout="fixed"
      scroll={{ x: 960 }}
      onRow={group => ({ onClick: () => toggle(group.key), style: { cursor: 'pointer' } })}
      expandable={{
        expandedRowKeys: expanded,
        showExpandColumn: false,
        expandedRowRender: group => <GroupFindings by={by} groupKey={group.key} total={group.count} options={options} revision={revision} onLoaded={onLoaded} onOpen={onOpen} onBatch={() => onDrill(group.key)} />,
      }}
      locale={{ emptyText: by === 'cve' ? '没有符合条件的漏洞编号' : '没有符合条件的软件包' }}
      pagination={{ current: page, pageSize, total: data?.total ?? 0, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: total => `共 ${total} 组`, onChange: (next, size) => { setExpanded([]); if (size !== pageSize) { setPageSize(size); setPage(1); } else setPage(next); } }}
    />
    {Boolean(data?.ungrouped) && <div style={{ padding: '8px 20px', fontSize: 12, color: palette.textTertiary }}>另有 {data?.ungrouped} 项发现没有{by === 'cve' ? '漏洞编号' : '软件包'}信息，请在平铺视图中查看。</div>}
  </>;
};
