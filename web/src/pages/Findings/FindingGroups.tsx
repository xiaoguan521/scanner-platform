import React, { useEffect, useState } from 'react';
import { Button, Tooltip } from 'antd';
import { DataTable } from '../../components/DataState';
import { Mono, SeverityTag, findingStatusMeta } from '../../components/Semantic';
import { useAppTheme } from '../../context/ThemeContext';
import { apiClient } from '../../api/client';
import type { FindingGroup, FindingGroupPage, FindingQueryOptions } from '../../api/client';

const statusOrder = ['OPEN', 'REOPENED', 'IN_PROGRESS', 'ACCEPTED_RISK', 'FALSE_POSITIVE', 'FIXED'] as const;

/** Aggregated findings by CVE / template ID or by software package, paged by the Server. */
export const FindingGroups: React.FC<{
  by: 'cve' | 'package';
  options: FindingQueryOptions;
  revision: number;
  onDrill: (key: string) => void;
  onSummary: (summary: Pick<FindingGroupPage, 'findings' | 'counts' | 'total'> | null, error: string | null) => void;
}> = ({ by, options, revision, onDrill, onSummary }) => {
  const { palette } = useAppTheme();
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [data, setData] = useState<FindingGroupPage | null>(null);
  const [loading, setLoading] = useState(true);
  const optionsKey = JSON.stringify(options);
  useEffect(() => { setPage(1); }, [by, optionsKey]);
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
      onSummary(null, cause instanceof Error ? cause.message : '聚合结果加载失败');
    }).finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
    // options is compared through optionsKey; onSummary only forwards results.
  }, [by, page, pageSize, optionsKey, revision]);

  const statusBar = (group: FindingGroup) => {
    const tones = { OPEN: palette.severity.HIGH.solid, REOPENED: palette.severity.CRITICAL.solid, IN_PROGRESS: palette.primary, ACCEPTED_RISK: palette.severity.MEDIUM.solid, FALSE_POSITIVE: palette.textTertiary, FIXED: palette.success };
    const label = statusOrder.filter(status => group.statusCounts[status]).map(status => `${findingStatusMeta[status].label} ${group.statusCounts[status]}`).join('，');
    return <Tooltip title={label}><div role="img" aria-label={label} style={{ display: 'flex', height: 6, borderRadius: 3, overflow: 'hidden', gap: 1, background: palette.borderSubtle, minWidth: 80 }}>
      {statusOrder.map(status => group.statusCounts[status] ? <div key={status} style={{ flex: group.statusCounts[status], background: tones[status] }} /> : null)}
    </div></Tooltip>;
  };
  const versions = (installed?: string[], fixed?: string[]) => <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4, alignItems: 'baseline' }}>
    {installed?.length ? <Mono style={{ color: palette.textSecondary }}>{installed.join(' / ')}</Mono> : null}
    {installed?.length ? <span style={{ color: palette.textTertiary }}>→</span> : null}
    {fixed?.length ? <Mono style={{ color: palette.success }}>{fixed.join(' / ')}</Mono> : <span style={{ color: palette.textTertiary }}>暂无修复版本</span>}
  </span>;
  const drillButton = (group: FindingGroup) => <Button size="small" aria-label={`查看明细：${group.key}`} onClick={() => onDrill(group.key)}>查看明细</Button>;

  const columns = by === 'cve' ? [
    { title: '漏洞编号', key: 'key', width: 300, render: (_: unknown, group: FindingGroup) => <div style={{ display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 }}><Mono style={{ fontWeight: 600 }}>{group.key}</Mono>{group.title && <span style={{ color: palette.textSecondary, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={group.title}>{group.title}</span>}</div> },
    { title: '最高等级', key: 'severity', width: 100, render: (_: unknown, group: FindingGroup) => <SeverityTag value={group.maxSeverity} /> },
    { title: '受影响软件包', key: 'packages', render: (_: unknown, group: FindingGroup) => group.packages?.length ? <span style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>{group.packages.map(name => <Mono key={name} style={{ padding: '0 6px', borderRadius: 4, background: palette.bgElevated, fontSize: 12 }}>{name}</Mono>)}</span> : <span style={{ color: palette.textTertiary }}>—</span> },
    { title: '修复版本', key: 'fixed', width: 200, render: (_: unknown, group: FindingGroup) => versions(undefined, group.fixedVersions) },
    { title: '发现项', key: 'count', width: 80, render: (_: unknown, group: FindingGroup) => <Mono>{group.count}</Mono> },
    { title: '资产', key: 'assets', width: 70, render: (_: unknown, group: FindingGroup) => <Mono>{group.assetCount}</Mono> },
    { title: '处置进度', key: 'status', width: 140, render: (_: unknown, group: FindingGroup) => statusBar(group) },
    { title: '', key: 'action', width: 110, render: (_: unknown, group: FindingGroup) => drillButton(group) },
  ] : [
    { title: '软件包', key: 'key', width: 220, render: (_: unknown, group: FindingGroup) => <Mono style={{ fontWeight: 600 }}>{group.key}</Mono> },
    { title: '安装版本 → 修复版本', key: 'versions', render: (_: unknown, group: FindingGroup) => versions(group.installedVersions, group.fixedVersions) },
    { title: '漏洞数', key: 'cves', width: 80, render: (_: unknown, group: FindingGroup) => <Mono>{group.cveCount ?? 0}</Mono> },
    { title: '最高等级', key: 'severity', width: 100, render: (_: unknown, group: FindingGroup) => <SeverityTag value={group.maxSeverity} /> },
    { title: '发现项', key: 'count', width: 80, render: (_: unknown, group: FindingGroup) => <Mono>{group.count}</Mono> },
    { title: '资产', key: 'assets', width: 70, render: (_: unknown, group: FindingGroup) => <Mono>{group.assetCount}</Mono> },
    { title: '处置进度', key: 'status', width: 140, render: (_: unknown, group: FindingGroup) => statusBar(group) },
    { title: '', key: 'action', width: 110, render: (_: unknown, group: FindingGroup) => drillButton(group) },
  ];

  return <>
    <DataTable<FindingGroup>
      rowKey="key"
      dataSource={data?.items ?? []}
      loading={loading}
      columns={columns}
      scroll={{ x: 1000 }}
      locale={{ emptyText: by === 'cve' ? '没有符合条件的漏洞编号' : '没有符合条件的软件包' }}
      pagination={{ current: page, pageSize, total: data?.total ?? 0, showSizeChanger: true, pageSizeOptions: [20, 50, 100], showTotal: total => `共 ${total} 组`, onChange: (next, size) => { if (size !== pageSize) { setPageSize(size); setPage(1); } else setPage(next); } }}
    />
    {Boolean(data?.ungrouped) && <div style={{ padding: '0 4px', fontSize: 12, color: palette.textTertiary }}>另有 {data?.ungrouped} 项发现没有{by === 'cve' ? '漏洞编号' : '软件包'}信息，请在平铺视图中查看。</div>}
  </>;
};
