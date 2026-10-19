// Run from repository root: node web/src/pages/Tasks/policy.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
async function load(relative) {
  const source=await readFile(new URL(relative,import.meta.url),'utf8');
  const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
  return import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
}
const {parsePortRanges,coversAllPorts,compressPorts,expandPortRanges,summarizePorts}=await load('./policy.ts');
assert.deepEqual(parsePortRanges(' 22,80,8000-8002 '),[{start:22,end:22},{start:80,end:80},{start:8000,end:8002}]);
assert.deepEqual(parsePortRanges(''),[]);
for(const invalid of ['0','65536','9-1','80,','80;443','-1','1-65536',Array(130).fill('80').join(',')])assert.throws(()=>parsePortRanges(invalid),undefined,invalid);
assert.equal(coversAllPorts(parsePortRanges('1-65535')),true,'custom full range must require confirmation');
assert.equal(coversAllPorts(parsePortRanges('30000-65535,1-29999')),true,'split full ranges must require confirmation');
assert.equal(coversAllPorts(parsePortRanges('1-32768,32768-65535')),true,'overlap still covers full range');
assert.equal(coversAllPorts(parsePortRanges('1-100,102-65535')),false,'a gap must not be treated as full coverage');
assert.equal(coversAllPorts([]),false);
assert.equal(compressPorts([443,80,81,82,80]),'80-82, 443');
assert.deepEqual(expandPortRanges('81-82,80-81'),[80,81,82]);
const full=expandPortRanges('1-65535');assert.equal(full.length,65535);assert.equal(compressPorts(full),'1-65535');
assert.ok(summarizePorts(Array.from({length:1000},(_,i)=>i*2+1)).length<240,'large separated port lists stay compact');
const {findingCounts,isVerifiedFinding,isVulnerability}=await load('../Findings/presentation.ts');
assert.equal(isVerifiedFinding({verifiedInRun:true}),false,'old completeness field cannot imply principle verification');
assert.equal(isVerifiedFinding({detectMethod:'version',verifiedInRun:true}),false,'version inference is unverified');
assert.equal(isVerifiedFinding({detectMethod:'principle'}),true);
assert.equal(isVerifiedFinding({detectMethod:'configuration'}),true);
assert.equal(isVulnerability({riskType:'login_entry'}),false);
assert.equal(isVulnerability({riskType:'weak_credential'}),false);
assert.equal(isVulnerability({}),false,'unknown historical types must not silently count as vulnerabilities');
assert.deepEqual(findingCounts([{riskType:'system',detectMethod:'version'},{riskType:'web',detectMethod:'principle'},{riskType:'login_entry',detectMethod:'configuration'},{verifiedInRun:true},{riskType:'weak_credential'}]),{vulnerabilities:2,loginEntries:1,unknown:1,version:1,verified:1});
console.log('Frontend policy and finding semantics: all checks passed');
