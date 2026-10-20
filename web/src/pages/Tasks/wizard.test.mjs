// Run from repository root: node web/src/pages/Tasks/wizard.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
async function load(relative) {
  const source=await readFile(new URL(relative,import.meta.url),'utf8');
  const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
  return import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
}
const {isAutoTaskWizard,wizardStepFields,assertTaskSubmission,getScanPlanDefaults}=await load('./wizard.ts');
const {previewProbePorts,parsePortRanges}=await load('./policy.ts');
assert.equal(isAutoTaskWizard({engine:'auto',mode:'now'},false),true);
for(const engine of ['synthetic','nuclei','trivy','zap','port-probe'])assert.equal(isAutoTaskWizard({engine,mode:'now'},false),false);
assert.equal(isAutoTaskWizard({engine:'auto',mode:'schedule'},false),false);
assert.equal(isAutoTaskWizard({engine:'auto',mode:'now'},true),false);
assert.deepEqual(wizardStepFields(0,{}),['assetId'],'target step must not validate later authorization or schedule fields');
assert.deepEqual(wizardStepFields(1,{portPreset:'custom'}),['portPreset','intensity','portExclusions','customRuleIds','portRanges']);
assert.ok(!wizardStepFields(1,{portPreset:'common'}).includes('portRanges'),'preserved custom input is irrelevant to common preset');
assert.deepEqual(wizardStepFields(2,{window:false}),['mode','window']);
assert.deepEqual(wizardStepFields(2,{window:true}),['mode','window','weekdays','start','end','timeZone']);
assert.deepEqual(wizardStepFields(3,{}),['opsApproved']);
for(const step of [0,1,2])assert.throws(()=>assertTaskSubmission({engine:'auto',opsApproved:true},true,true,step),/确认页/);
assert.throws(()=>assertTaskSubmission({engine:'auto',opsApproved:false},true,true,3),/运维授权/);
assert.throws(()=>assertTaskSubmission({engine:'auto',opsApproved:true},false,true,3),/权限/);
assert.throws(()=>assertTaskSubmission({engine:'port-probe',opsApproved:false},true,false,0),/运维授权/);
assert.doesNotThrow(()=>assertTaskSubmission({engine:'auto',opsApproved:true},true,true,3));
for(const engine of ['trivy','synthetic','nuclei','zap'])assert.doesNotThrow(()=>assertTaskSubmission({engine},true,false,0));
assert.doesNotThrow(()=>assertTaskSubmission({engine:'auto',mode:'schedule',opsApproved:true},true,false,0));
assert.deepEqual(getScanPlanDefaults('quick'),{portPreset:'common',intensity:'gentle',portRanges:'',portExclusions:'',customRuleIds:[]});
assert.deepEqual(getScanPlanDefaults('standard'),{portPreset:'common-and-custom',intensity:'standard',portRanges:'',portExclusions:'',customRuleIds:[]});
assert.deepEqual(getScanPlanDefaults('unexpected'),getScanPlanDefaults('quick'),'unknown plans fail closed to the quick preset');
const asset={id:'example-host',kind:'host',address:'192.0.2.10',ports:[{port:22,kind:'NON_WEB'},{port:80,kind:'WEB'},{port:443,kind:'EXCLUDED_PROXY'}],services:[{port:8080}],quarantinedPorts:[9000]};
const policy={commonPorts:[22,80,443,9000],exclusions:[{start:22,end:22}]};
const cases=[
  {config:{preset:'common'},requested:[22,80,443,9000],effective:[80]},
  {config:{preset:'registered'},requested:[22,80,8080],effective:[80,8080]},
  {config:{preset:'custom',ranges:parsePortRanges('79-82,80,443,9000'),exclusions:parsePortRanges('81-82')},requested:[79,80,81,82,443,9000],effective:[79,80]},
  {config:{preset:'common-and-custom',ranges:parsePortRanges('8080,9000')},requested:[22,80,443,8080,9000],effective:[80,8080]},
  {config:{preset:'custom',ranges:parsePortRanges('22,443,9000')},requested:[22,443,9000],effective:[]},
];
for(const {config,requested,effective} of cases)assert.deepEqual(previewProbePorts(asset,config,policy),{requested,effective},config.preset);
const full=previewProbePorts(asset,{preset:'full',exclusions:parsePortRanges('1-21')},policy);
assert.equal(full.requested.length,65535);
assert.equal(full.effective.length,65535-21-1-1-1);
assert.equal(full.effective[0],23);
assert.ok(!full.effective.includes(443)&&!full.effective.includes(9000));
assert.deepEqual(asset.ports.map(port=>port.port),[22,80,443],'preview must not alter asset data');
console.log('Automatic task wizard: all checks passed');
