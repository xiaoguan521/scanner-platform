import type { Finding } from '../../types';
export const riskLabels: Record<string,string> = {system:'系统漏洞',web:'Web 漏洞',weak_credential:'弱口令（未启用）',login_entry:'登录入口',unknown:'未核实类型'};
export const methodLabels: Record<string,string> = {principle:'原理验证',version:'版本推断（未验证）',configuration:'配置检查',unknown:'未核实检测方式'};
export const confidenceLabels: Record<string,string> = {high:'高置信度',medium:'中置信度',low:'低置信度',unknown:'置信度未核实'};
// Historical data must never acquire a verification claim from verifiedInRun.
export function isVerifiedFinding(f: Pick<Finding,'detectMethod'>): boolean { return f.detectMethod === 'principle' || f.detectMethod === 'configuration'; }
export function isVulnerability(f: Pick<Finding,'riskType'>): boolean { return f.riskType === 'system' || f.riskType === 'web'; }
export function findingCounts(items: Finding[]) { return {vulnerabilities:items.filter(isVulnerability).length,loginEntries:items.filter(f=>f.riskType==='login_entry').length,unknown:items.filter(f=>!f.riskType||!['system','web','weak_credential','login_entry'].includes(f.riskType)).length,version:items.filter(f=>isVulnerability(f)&&f.detectMethod==='version').length,verified:items.filter(f=>isVulnerability(f)&&isVerifiedFinding(f)).length}; }
