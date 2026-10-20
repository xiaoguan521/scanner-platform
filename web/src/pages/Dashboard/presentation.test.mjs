import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';

const source=await readFile(new URL('./presentation.ts',import.meta.url),'utf8');
const testSource=source.replace("import { isVulnerability } from '../Findings/presentation';", "const isVulnerability = (finding) => finding.riskType === 'system' || finding.riskType === 'web';");
const js=ts.transpileModule(testSource,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
const {findingRiskContribution,riskScore,riskAssetCount,severityDistribution,vulnerabilityTrend,topRiskGroups,topRiskAssets,pendingCriticalHigh,pendingCriticalHighCount}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
const findings=[
  {id:'critical',severity:'CRITICAL',status:'OPEN',riskType:'web',target:'192.0.2.10:80',businessGroup:'支付',assetId:'a1',firstSeen:'2026-10-01T00:00:00Z'},
  {id:'high',severity:'HIGH',status:'ACCEPTED_RISK',riskType:'system',target:'192.0.2.11:22',businessGroup:'支付',assetId:'a2',firstSeen:'2026-10-10T00:00:00Z'},
  {id:'medium',severity:'MEDIUM',status:'IN_PROGRESS',riskType:'web',target:'192.0.2.10:443',businessGroup:'数据',assetId:'a1',firstSeen:'2026-10-15T00:00:00Z'},
  {id:'fixed',severity:'HIGH',status:'FIXED',riskType:'web',target:'192.0.2.12:80',businessGroup:'历史',assetId:'a3',firstSeen:'2026-10-01T00:00:00Z',resolvedAt:'2026-10-12T00:00:00Z'},
  {id:'unknown',severity:'HIGH',status:'OPEN',target:'192.0.2.13:80',businessGroup:'其他',firstSeen:'2026-10-15T00:00:00Z'},
];
assert.equal(findingRiskContribution(findings[0]),30);
assert.equal(findingRiskContribution(findings[1]),5);
assert.equal(riskScore(findings),45);
assert.equal(riskAssetCount(findings),2);
assert.deepEqual(severityDistribution(findings),{CRITICAL:1,HIGH:2,MEDIUM:1,LOW:0,INFO:0});
const trend=vulnerabilityTrend(findings,7,new Date('2026-10-16T12:00:00Z'));
assert.equal(trend.length,7);
assert.equal(trend.at(-1).count,3);
assert.equal(trend[0].count,2);
assert.deepEqual(topRiskGroups(findings,2).map(item=>item.name),['支付','数据']);
assert.deepEqual(topRiskAssets([{id:'a1',name:'主机一',address:'192.0.2.10'},{id:'a2',name:'主机二',address:'192.0.2.11'}],findings).map(item=>item.id),['a1','a2']);
assert.deepEqual(pendingCriticalHigh(findings).map(item=>item.id),['critical']);
assert.deepEqual(pendingCriticalHigh([...findings,{...findings[0],id:'reopened',status:'REOPENED',lastSeen:'2026-10-16T02:00:00Z'}]).map(item=>item.id).sort(),['critical','reopened']);
assert.equal(pendingCriticalHighCount(findings),1);
console.log('dashboard risk, trend, drilldown checks passed');
