import ExcelJS from 'exceljs';
import {
  AlignmentType,
  BorderStyle,
  Document,
  Footer,
  HeadingLevel,
  Packer,
  Paragraph,
  ShadingType,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
  type IRunOptions,
} from 'docx';
import type { Asset, Finding, ScanTask } from '../../types';

export type ReportTemplate = 'overview' | 'asset' | 'task';
export type ReportSnapshot = {
  title: string;
  generatedAt: string;
  filters: { template: ReportTemplate; asset?: string; businessGroup?: string; task?: string; from?: string; to?: string };
  summary: { assets: number; tasks: number; findings: number; openFindings: number; severity: Record<string, number> };
  assets: Asset[];
  tasks: ScanTask[];
  findings: Finding[];
};

const severityNames: Record<string, string> = { CRITICAL: '严重', HIGH: '高危', MEDIUM: '中危', LOW: '低危', INFO: '信息' };
const statusNames: Record<string, string> = { OPEN: '待修复', REOPENED: '重新出现', IN_PROGRESS: '修复中', FIXED: '已修复', FALSE_POSITIVE: '误报', ACCEPTED_RISK: '接受风险' };
const taskStatusNames: Record<string, string> = { PENDING: '待领取', RUNNING: '执行中', WAITING_WINDOW: '等待时间窗', PAUSED_WINDOW: '等待恢复', COMPLETED: '已完成', CANCELED: '已取消', FAILED: '失败' };
const missing = '未提供';

const safe = (value: unknown): string | number => {
  if (typeof value === 'number' && Number.isFinite(value)) return value;
  const text = String(value ?? '');
  return /^[\s]*[=+@-]/.test(text) ? `'${text}` : text;
};
const dateText = (value?: string): string => value ? new Date(value).toLocaleString() : '—';
const targetHost = (target: string): string => {
  if (target.startsWith('[')) return target.slice(1, target.indexOf(']'));
  return target.split(':')[0] ?? target;
};
const hostURL = (host: string): string => host.includes(':') ? `[${host}]` : host;
const findingMatchesAsset = (target: string, address: string): boolean => target === address || target.startsWith(`${address}:`) || target.startsWith(`[${address}]:`) || target.startsWith(`${address}/`);
const portsForAsset = (asset: Asset, tasks: ScanTask[]): { approved: string; discovered: string } => {
  const approved = (asset.ports ?? []).filter(port => port.kind !== 'EXCLUDED_PROXY').map(port => String(port.port));
  const discovered = new Set<number>();
  for (const task of tasks) {
    if (task.assetId !== asset.id) continue;
    for (const result of task.portProbeResults ?? []) discovered.add(result.port);
  }
  return { approved: approved.join(', ') || '无已审批端口', discovered: [...discovered].sort((a, b) => a - b).join(', ') || '未探测' };
};

const systemStatusForAsset = (asset: Asset, tasks: ScanTask[]): string => {
  const statuses = [...new Set(tasks.filter(task => task.assetId === asset.id && task.systemScanStatus).map(task => task.systemScanStatus!))];
  return statuses.join('；') || '未采集';
};

function findingImpact(finding: Finding): string {
  return finding.description?.trim() || missing;
}

function findingTarget(finding: Finding): string {
  const target = finding.target.trim();
  if (!finding.port || target.endsWith(`:${finding.port}`)) return target;
  return `${target}:${finding.port}`;
}

function setSheet(worksheet: ExcelJS.Worksheet, headers: string[], rows: unknown[][], widths: number[]): void {
  worksheet.addRow(headers);
  for (const row of rows) worksheet.addRow(row.map(safe));
  worksheet.views = [{ state: 'frozen', ySplit: 1 }];
  worksheet.autoFilter = { from: { row: 1, column: 1 }, to: { row: Math.max(1, rows.length + 1), column: headers.length } };
  worksheet.columns = headers.map((header, index) => ({ header, key: `c${index}`, width: widths[index] ?? 18 }));
  const head = worksheet.getRow(1);
  head.height = 30;
  head.font = { bold: true, color: { argb: 'FFFFFFFF' } };
  head.alignment = { vertical: 'middle', wrapText: true };
  head.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF1D4ED8' } };
  head.eachCell(cell => { cell.border = { bottom: { style: 'thin', color: { argb: 'FF94A3B8' } } }; });
  for (let rowIndex = 2; rowIndex <= rows.length + 1; rowIndex++) {
    const row = worksheet.getRow(rowIndex);
    row.alignment = { vertical: 'top', wrapText: true };
    row.height = 30;
    if (rowIndex % 2 === 0) row.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFF3F6FA' } };
  }
}

export async function buildExcelReport(snapshot: ReportSnapshot): Promise<Blob> {
  const workbook = new ExcelJS.Workbook();
  workbook.creator = '安全扫描平台';
  workbook.created = new Date(snapshot.generatedAt);
  workbook.subject = '扫描结果快照';
  workbook.description = '根据报告生成时平台可见数据创建；缺失字段会标为未提供或未采集。';
  const summaryRows: unknown[][] = [
    ['报告名称', snapshot.title], ['生成时间', dateText(snapshot.generatedAt)],
    ['筛选资产', snapshot.filters.asset || '全部'], ['业务组', snapshot.filters.businessGroup || '全部'],
    ['任务', snapshot.filters.task || '全部'], ['时间范围', `${snapshot.filters.from || '不限开始'} 至 ${snapshot.filters.to || '不限结束'}`],
    ['资产数', snapshot.summary.assets], ['任务数', snapshot.summary.tasks], ['发现项数', snapshot.summary.findings],
    ['待处置发现项', snapshot.summary.openFindings],
    ...Object.entries(snapshot.summary.severity).map(([level, count]) => [`${severityNames[level] ?? level}发现项`, count]),
    ['报告说明', '未检出不等于不存在风险；没有采集的数据会明确标为未提供或未采集。'],
  ];
  setSheet(workbook.addWorksheet('综述'), ['项目', '内容'], summaryRows, [28, 90]);

  const assetRiskRows = snapshot.assets.map(asset => {
    const related = snapshot.findings.filter(item => findingMatchesAsset(item.target, asset.address));
    const count = (level: string) => related.filter(item => item.severity === level).length;
    return [asset.address, asset.businessGroup, asset.owner, related.length, count('CRITICAL'), count('HIGH'), count('MEDIUM'), count('LOW'), count('INFO'), asset.ports?.length ?? 0];
  });
  setSheet(workbook.addWorksheet('资产风险统计'), ['资产地址', '业务组', '负责人', '发现项总数', '严重', '高危', '中危', '低危', '信息', '已审批端口数'], assetRiskRows, [24, 22, 18, 14, 10, 10, 10, 10, 10, 16]);

  const groups = new Map<string, Finding[]>();
  for (const finding of snapshot.findings) {
    const key = `${finding.severity}\u0000${finding.title}\u0000${finding.engine}\u0000${finding.templateOrCve}`;
    groups.set(key, [...(groups.get(key) ?? []), finding]);
  }
  const impactRows = [...groups.values()].map(group => {
    const first = group[0];
    return [first.title, severityNames[first.severity] ?? first.severity, first.engine, first.templateOrCve, new Set(group.map(item => item.target)).size, group.length, findingImpact(first), missing];
  });
  setSheet(workbook.addWorksheet('漏洞影响统计'), ['漏洞 / 风险名称', '等级', '类型', 'CVE / 规则', '影响资产数', '出现次数', '影响描述（规则提供）', '整改建议'], impactRows, [36, 12, 14, 24, 14, 14, 48, 42]);

  const hostRows = snapshot.assets.filter(asset => asset.kind === 'host').map(asset => {
    const ports = portsForAsset(asset, snapshot.tasks);
    return [asset.address, asset.reachabilityStatus ?? '未检查', systemStatusForAsset(asset, snapshot.tasks), missing, ports.approved, ports.discovered, missing, missing, missing, asset.businessGroup, asset.owner];
  });
  setSheet(workbook.addWorksheet('主机资产详情'), ['主机', '可达状态', 'Linux 系统包检查状态', '操作系统版本', '已审批端口', '开放端口候选（需审批）', '中间件', '语言 / 框架', '数据库 / 应用', '业务组', '负责人'], hostRows, [24, 16, 38, 20, 28, 34, 24, 24, 28, 20, 18]);

  const websiteRows: unknown[][] = [];
  const entranceRows: unknown[][] = [];
  for (const task of snapshot.tasks) {
    const asset = snapshot.assets.find(item => item.id === task.assetId);
    const host = asset?.address ?? task.chunks.flatMap(chunk => chunk.targets).map(targetHost)[0] ?? '未知资产';
    for (const service of task.serviceResults ?? []) {
      if (service.kind !== 'HTTP' || !service.scheme) continue;
      const url = `${service.scheme}://${hostURL(host)}:${service.port}/`;
      websiteRows.push([url, host, '可连接', service.port, service.scheme.toUpperCase(), missing, missing, missing, missing, asset?.businessGroup ?? missing, asset?.owner ?? missing]);
      entranceRows.push(['未识别', host, 'HTTP(S) 服务', service.port, url, service.scheme === 'https' ? 'HTTPS' : 'HTTP', '未检测', '未检测', '未采集；未进行登录尝试', asset?.businessGroup ?? missing, asset?.owner ?? missing]);
    }
  }
  if (entranceRows.length === 0) entranceRows.push(['未采集', '—', '—', '—', '—', '—', '未检测', '未检测', '未识别登录入口；不代表不存在', '—', '—']);
  setSheet(workbook.addWorksheet('网站资产详情'), ['URL', '主机', '可用性', '端口', '协议', '中间件', '语言 / 框架', '数据库 / 应用', '页面标题', '业务组', '负责人'], websiteRows, [42, 24, 14, 10, 12, 20, 24, 24, 30, 20, 18]);

  const findingRows = snapshot.findings.map(item => [severityNames[item.severity] ?? item.severity, item.target, item.port ?? '未提供', item.title, item.engine, item.templateOrCve, item.description || missing, missing, item.fixedVersion || missing, missing, missing, missing, statusNames[item.status] ?? item.status, dateText(item.firstSeen), dateText(item.lastSeen), item.businessGroup, item.owner]);
  setSheet(workbook.addWorksheet('漏洞详情'), ['等级', '目标', '端口', '名称', '类型', 'CVE / 规则 ID', '漏洞描述', '影响', '修复版本', '修复建议', '参考资料', '证据', '状态', '首次发现', '最近发现', '业务组', '负责人'], findingRows, [12, 30, 12, 36, 14, 24, 48, 36, 18, 36, 30, 36, 14, 22, 22, 20, 18]);

  setSheet(workbook.addWorksheet('弱口令详情'), ['采集状态', '范围说明'], [['未采集', '当前扫描流程不尝试登录或测试口令；不代表不存在弱口令。']], [18, 100]);
  setSheet(workbook.addWorksheet('登录入口详情'), ['识别状态', '主机', '入口类型', '端口', 'URL', '协议', '验证码', '登录防护', '证据 / 说明', '业务组', '负责人'], entranceRows, [16, 24, 20, 10, 42, 12, 14, 16, 40, 20, 18]);
  const buffer = await workbook.xlsx.writeBuffer();
  return new Blob([buffer], { type: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' });
}

const reportFonts = { ascii: 'Arial', hAnsi: 'Arial', eastAsia: 'Microsoft YaHei', hint: 'eastAsia' };

function reportText(text: string, options: Omit<IRunOptions, 'text' | 'children' | 'font'> = {}): TextRun {
  return new TextRun({ text, font: reportFonts, language: { value: 'zh-CN', eastAsia: 'zh-CN' }, ...options });
}

function wordCell(text: string, header = false, width = 50): TableCell {
  return new TableCell({
    width: { size: width, type: WidthType.PERCENTAGE },
    shading: header ? { type: ShadingType.SOLID, color: '1D4ED8' } : undefined,
    margins: { top: 100, bottom: 100, left: 120, right: 120 },
    children: [new Paragraph({
      children: [reportText(text || '—', { bold: header, color: header ? 'FFFFFF' : '172033', size: 18 })],
      spacing: { after: 0 },
    })],
  });
}

function keyValueTable(rows: [string, string][]): Table {
  const border = { style: BorderStyle.SINGLE, size: 4, color: 'D8DEE8' };
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border },
    rows: [new TableRow({ children: [wordCell('项目', true, 32), wordCell('内容', true, 68)] }), ...rows.map(([key, value]) => new TableRow({ children: [wordCell(key, false, 32), wordCell(value, false, 68)] }))],
  });
}

function matrixTable(headers: string[], rows: string[][]): Table {
  const border = { style: BorderStyle.SINGLE, size: 4, color: 'D8DEE8' };
  const width = 100 / headers.length;
  const makeRow = (values: string[], header = false) => new TableRow({ children: values.map(value => wordCell(value, header, width)) });
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    borders: { top: border, bottom: border, left: border, right: border, insideHorizontal: border, insideVertical: border },
    rows: [makeRow(headers, true), ...(rows.length ? rows.map(row => makeRow(row)) : [makeRow(headers.map(() => '无记录'))])],
  });
}

export async function buildWordReport(snapshot: ReportSnapshot): Promise<Blob> {
  const taskRows = snapshot.tasks.map(task => [
    task.id,
    task.engines.map(engine => engine === 'auto' ? '自动综合扫描' : engine.toUpperCase()).join('、'),
    taskStatusNames[task.status] ?? task.status,
    `${task.completedChunks} / ${task.totalChunks}`,
    task.ruleVersion || '无规则包版本',
    String(task.customRuleCount ?? 0),
    task.systemScanStatus || (task.engines.includes('auto') ? '未报告' : '不适用'),
  ]);
  const assetRows = snapshot.assets.map(asset => {
    const ports = portsForAsset(asset, snapshot.tasks);
    return [asset.address, asset.kind === 'host' ? '主机' : '镜像仓库', asset.businessGroup, asset.owner, ports.approved, ports.discovered];
  });
  const serviceRows = snapshot.tasks.flatMap(task => {
    const asset = snapshot.assets.find(item => item.id === task.assetId);
    const host = asset?.address ?? task.chunks.flatMap(chunk => chunk.targets).map(targetHost)[0] ?? '未知资产';
    return (task.serviceResults ?? []).filter(service => service.kind === 'HTTP').map(service => [host, String(service.port), service.scheme?.toUpperCase() ?? 'HTTP(S)', `${service.scheme ?? 'http'}://${hostURL(host)}:${service.port}/`]);
  });
  const findingSections = snapshot.findings.flatMap(finding => [
    new Paragraph({ heading: HeadingLevel.HEADING_2, children: [reportText(`${severityNames[finding.severity] ?? finding.severity} · ${finding.title}`)] }),
    keyValueTable([
      ['规则 / CVE', `${finding.engine.toUpperCase()} · ${finding.templateOrCve}`],
      ['目标 / 端口', findingTarget(finding)],
      ['状态 / 首次与最近发现', `${statusNames[finding.status] ?? finding.status} · ${dateText(finding.firstSeen)} / ${dateText(finding.lastSeen)}`],
      ['描述', finding.description || missing], ['影响', missing], ['修复建议', missing], ['参考资料', missing], ['证据', missing],
    ]),
  ]);
  const statRows: [string, string][] = [
    ['资产数', String(snapshot.summary.assets)], ['任务数', String(snapshot.summary.tasks)],
    ['发现项数', String(snapshot.summary.findings)], ['待处置发现项', String(snapshot.summary.openFindings)],
    ...Object.entries(snapshot.summary.severity).map(([level, count]) => [`${severityNames[level] ?? level}发现项`, String(count)] as [string, string]),
  ];
  const scopeRows: [string, string][] = [
    ['资产', snapshot.filters.asset || '全部'], ['业务组', snapshot.filters.businessGroup || '全部'],
    ['任务', snapshot.filters.task || '全部'], ['时间范围', `${snapshot.filters.from || '不限开始'} 至 ${snapshot.filters.to || '不限结束'}`],
  ];
  if (findingSections.length === 0) findingSections.push(keyValueTable([['发现项', '当前筛选范围内没有已采集的发现项。未检出不代表不存在风险。']]));
  const doc = new Document({
    creator: '安全扫描平台', title: snapshot.title, subject: '扫描结果报告',
    styles: { default: { document: { run: { size: 20, color: '172033' }, paragraph: { spacing: { after: 120, line: 280 } } } } },
    sections: [{
      properties: { page: { margin: { top: 900, right: 900, bottom: 900, left: 900 } } },
      footers: { default: new Footer({ children: [new Paragraph({ alignment: AlignmentType.CENTER, children: [reportText('安全扫描平台 · 报告生成时间：' + dateText(snapshot.generatedAt), { color: '64748B' })] })] }) },
      children: [
        new Paragraph({ heading: HeadingLevel.TITLE, children: [reportText(snapshot.title)] }),
        new Paragraph({ children: [reportText(`生成时间：${dateText(snapshot.generatedAt)}`, { color: '64748B' })] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('报告范围')] }), keyValueTable(scopeRows),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('风险综述')] }), keyValueTable(statRows),
        new Paragraph({ children: [reportText('数据边界：报告仅包含生成时平台已采集的数据。空缺的操作系统、组件版本、影响、整改建议、参考资料或证据会标为“未提供/未采集”；未检出不代表不存在风险。弱口令不在扫描范围内。', { bold: true, color: '92400E' })] }),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('资产与端口')] }),
        matrixTable(['资产地址', '类型', '业务组', '负责人', '已审批端口', '开放候选端口（需审批）'], assetRows),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('识别到的 HTTP(S) 服务')] }),
        matrixTable(['主机', '端口', '协议', 'URL'], serviceRows),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('扫描任务与完整性')] }),
        matrixTable(['任务 ID', '执行方式', '状态', '进度', '规则版本', '自定义规则数', 'Linux 系统包检查状态'], taskRows),
        new Paragraph({ heading: HeadingLevel.HEADING_1, children: [reportText('漏洞与风险详情')] }), ...findingSections,
        new Paragraph({ children: [reportText('注：该文档是当前平台采集结果的整理，不替代人工复核。针对尚未采集的操作系统包、非 HTTP 中间件、应用依赖及网站登录入口，应在对应采集能力接入并成功运行后再生成结论。', { color: '64748B' })] }),
      ],
    }],
  });
  // Each finding is a compact two-column table with wrapped text and explicit
  // unavailable-data labels, rather than a grid of narrow one-cell columns.
  return Packer.toBlob(doc);
}
