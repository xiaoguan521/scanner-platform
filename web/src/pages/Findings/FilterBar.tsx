import React from 'react';
import { Button, Checkbox, Input, Select, Tag } from 'antd';
import { SearchOutlined } from '@ant-design/icons';
import { useAppTheme } from '../../context/ThemeContext';
import { findingStatusMeta, severityMeta } from '../../components/Semantic';
import { confidenceLabels, methodLabels, riskLabels } from './presentation';
import { hasActiveFilters, type FindingFilters } from './filters';

const engineLabels: Record<string, string> = { trivy: '系统包 / 依赖（Trivy）', nuclei: 'Web 基线（Nuclei）', zap: '历史 ZAP 结果' };

const options = (all: string, labels: Record<string, string>) => [{ value: 'ALL', label: all }, ...Object.entries(labels).map(([value, label]) => ({ value, label }))];
const labelsOf = (meta: Record<string, { label: string }>) => Object.fromEntries(Object.entries(meta).map(([key, item]) => [key, item.label]));

/** One bar for every findings filter; each control maps to a Server query parameter. */
export const FindingFilterBar: React.FC<{
  filters: FindingFilters;
  query: string;
  businessGroups: string[];
  onQuery: (value: string) => void;
  onChange: (patch: Partial<FindingFilters>) => void;
}> = ({ filters, query, businessGroups, onQuery, onChange }) => {
  const { palette } = useAppTheme();
  const active = hasActiveFilters(filters) || query.trim() !== '';
  const clear = () => {
    onQuery('');
    onChange({ severity: 'ALL', status: 'ALL', method: 'ALL', confidence: 'ALL', risk: 'ALL', engine: 'ALL', onlyVerified: false, fixable: false, businessGroup: '', assetId: '', cve: '', package: '' });
  };
  const drill = [
    filters.cve && { key: 'cve', label: `漏洞编号：${filters.cve}`, clear: { cve: '' } },
    filters.package && { key: 'package', label: `软件包：${filters.package}`, clear: { package: '' } },
    filters.assetId && { key: 'asset', label: `资产：${filters.assetId}`, clear: { assetId: '' } },
  ].filter(Boolean) as { key: string; label: string; clear: Partial<FindingFilters> }[];
  return (
    <div role="search" aria-label="漏洞筛选" style={{ display: 'flex', flexDirection: 'column', gap: 10, padding: 12, borderRadius: 12, background: palette.bgContainer, border: `1px solid ${palette.borderSubtle}` }}>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
        <Input aria-label="按目标、软件包、CVE 或标题筛选" placeholder="按目标、软件包、CVE 或标题筛选" allowClear prefix={<SearchOutlined style={{ color: palette.textTertiary }} />} value={query} onChange={event => onQuery(event.target.value)} style={{ flex: '1 1 260px', maxWidth: 360 }} />
        <Select aria-label="严重度筛选" value={filters.severity} onChange={severity => onChange({ severity })} style={{ width: 120 }} options={options('全部等级', labelsOf(severityMeta))} />
        <Select aria-label="状态筛选" value={filters.status} onChange={status => onChange({ status })} style={{ width: 120 }} options={options('全部状态', labelsOf(findingStatusMeta))} />
        <Select aria-label="来源筛选" value={filters.engine} onChange={engine => onChange({ engine })} style={{ width: 180 }} options={options('全部来源', engineLabels)} />
        <Select aria-label="业务组筛选" value={filters.businessGroup || 'ALL'} onChange={value => onChange({ businessGroup: value === 'ALL' ? '' : value })} style={{ width: 150 }} showSearch optionFilterProp="label" options={[{ value: 'ALL', label: '全部业务组' }, ...businessGroups.map(name => ({ value: name, label: name }))]} />
        <Checkbox checked={filters.fixable} onChange={event => onChange({ fixable: event.target.checked })}>仅可修复</Checkbox>
        {active && <Button type="link" onClick={clear}>清除筛选</Button>}
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, alignItems: 'center' }}>
        <Select aria-label="风险类型筛选" value={filters.risk} onChange={risk => onChange({ risk })} style={{ width: 150 }} options={options('全部类型', riskLabels)} />
        <Select aria-label="检测方式筛选" value={filters.method} onChange={method => onChange({ method })} style={{ width: 170 }} options={options('全部检测方式', methodLabels)} />
        <Select aria-label="置信度筛选" value={filters.confidence} onChange={confidence => onChange({ confidence })} style={{ width: 140 }} options={options('全部置信度', confidenceLabels)} />
        <Checkbox checked={filters.onlyVerified} onChange={event => onChange({ onlyVerified: event.target.checked })}>仅已验证（原理验证 / 配置检查）</Checkbox>
        {drill.map(item => <Tag key={item.key} closable onClose={() => onChange(item.clear)} style={{ margin: 0 }}>{item.label}</Tag>)}
      </div>
    </div>
  );
};
