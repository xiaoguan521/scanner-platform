import type { Asset, Finding } from '../../types';
import { isVulnerability } from '../Findings/presentation';

export const severityWeights: Record<Finding['severity'], number> = {
  CRITICAL: 30,
  HIGH: 20,
  MEDIUM: 10,
  LOW: 3,
  INFO: 1,
};

const inactiveStatuses = new Set(['FIXED', 'FALSE_POSITIVE']);

export function isActiveVulnerability(finding: Finding): boolean {
  return isVulnerability(finding) && !inactiveStatuses.has(finding.status);
}

export function findingRiskContribution(finding: Finding): number {
  if (!isActiveVulnerability(finding)) return 0;
  const base = severityWeights[finding.severity] ?? 0;
  return finding.status === 'ACCEPTED_RISK' ? base * 0.25 : base;
}

export function riskScore(findings: Finding[]): number {
  return Math.min(100, Math.round(findings.reduce((total, finding) => total + findingRiskContribution(finding), 0)));
}

export function riskAssetCount(findings: Finding[]): number {
  const assets = new Set<string>();
  for (const finding of findings) {
    if (!isActiveVulnerability(finding)) continue;
    if (finding.assetId) {
      assets.add(finding.assetId);
      continue;
    }
    const separator = finding.target.lastIndexOf(':');
    assets.add(separator > 0 ? finding.target.slice(0, separator) : finding.target);
  }
  return assets.size;
}

export function severityDistribution(findings: Finding[]): Record<Finding['severity'], number> {
  const distribution: Record<Finding['severity'], number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const finding of findings) {
    if (isVulnerability(finding)) distribution[finding.severity] += 1;
  }
  return distribution;
}

export interface TrendPoint {
  date: string;
  label: string;
  count: number;
}

function dateKey(value: Date): string {
  return value.toISOString().slice(0, 10);
}

export function vulnerabilityTrend(findings: Finding[], days: 7 | 30 | 90, now = new Date()): TrendPoint[] {
  const end = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
  return Array.from({ length: days }, (_, index) => {
    const date = new Date(end);
    date.setUTCDate(end.getUTCDate() - days + index + 1);
    const bucketEnd = new Date(date);
    bucketEnd.setUTCHours(23, 59, 59, 999);
    const count = findings.filter((finding) => {
      if (!isVulnerability(finding) || inactiveStatuses.has(finding.status)) return false;
      const firstSeen = Date.parse(finding.firstSeen);
      if (!Number.isFinite(firstSeen) || firstSeen > bucketEnd.getTime()) return false;
      const resolvedAt = finding.resolvedAt ? Date.parse(finding.resolvedAt) : NaN;
      return !Number.isFinite(resolvedAt) || resolvedAt > bucketEnd.getTime();
    }).length;
    return { date: dateKey(date), label: date.toLocaleDateString('zh-CN', { month: 'numeric', day: 'numeric', timeZone: 'UTC' }), count };
  });
}

export interface RiskGroup {
  name: string;
  score: number;
  openCount: number;
}

export function topRiskGroups(findings: Finding[], limit = 5): RiskGroup[] {
  const groups = new Map<string, Finding[]>();
  for (const finding of findings) {
    if (!isActiveVulnerability(finding) || !finding.businessGroup) continue;
    const items = groups.get(finding.businessGroup) ?? [];
    items.push(finding);
    groups.set(finding.businessGroup, items);
  }
  return [...groups.entries()].map(([name, items]) => ({
    name,
    score: Math.min(100, Math.round(items.reduce((total, finding) => total + findingRiskContribution(finding), 0))),
    openCount: items.length,
  })).sort((a, b) => b.score - a.score || b.openCount - a.openCount || a.name.localeCompare(b.name)).slice(0, limit);
}

export interface RiskAsset {
  id: string;
  name: string;
  address: string;
  score: number;
  openCount: number;
}

export function topRiskAssets(assets: Asset[], findings: Finding[], limit = 5): RiskAsset[] {
  return assets.map((asset) => {
    const items = findings.filter((finding) => isActiveVulnerability(finding) && (
      finding.assetId === asset.id || finding.target === asset.address || finding.target.startsWith(`${asset.address}:`)
    ));
    return {
      id: asset.id,
      name: asset.name || asset.address,
      address: asset.address,
      score: Math.min(100, Math.round(items.reduce((total, finding) => total + findingRiskContribution(finding), 0))),
      openCount: items.length,
    };
  }).filter((asset) => asset.openCount > 0).sort((a, b) => b.score - a.score || b.openCount - a.openCount || a.name.localeCompare(b.name)).slice(0, limit);
}

const pendingStatuses = new Set<Finding['status']>(['OPEN', 'REOPENED', 'IN_PROGRESS']);
const pendingSeverityRank: Record<Finding['severity'], number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

function isPendingCriticalHigh(finding: Finding): boolean {
  return isVulnerability(finding) && (finding.severity === 'CRITICAL' || finding.severity === 'HIGH') && pendingStatuses.has(finding.status);
}

/** Findings that deserve a focused first response on the dashboard. */
export function pendingCriticalHigh(findings: Finding[], limit = 5): Finding[] {
  return findings
    .filter(isPendingCriticalHigh)
    .slice()
    .sort((a, b) => pendingSeverityRank[a.severity] - pendingSeverityRank[b.severity] || Date.parse(b.lastSeen) - Date.parse(a.lastSeen) || a.id.localeCompare(b.id))
    .slice(0, limit);
}

export function pendingCriticalHighCount(findings: Finding[]): number {
  return findings.filter(isPendingCriticalHigh).length;
}
