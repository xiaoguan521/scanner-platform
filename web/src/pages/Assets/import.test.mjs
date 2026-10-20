// Run from repository root: node web/src/pages/Assets/import.test.mjs
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import ts from 'typescript';
const source=await readFile(new URL('./import.ts',import.meta.url),'utf8');
const js=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2020,module:ts.ModuleKind.ESNext}}).outputText;
const {assertImportFile,canConfirmImport,maxAssetImportBytes}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
assert.throws(()=>assertImportFile({size:0}));
assert.throws(()=>assertImportFile({size:maxAssetImportBytes+1}));
assert.doesNotThrow(()=>assertImportFile({size:maxAssetImportBytes}));
const now=Date.parse('2026-10-20T00:00:00Z');
const preview={previewId:'example-preview',expiresAt:'2026-10-20T00:15:00Z',total:1,valid:1,invalid:0,rows:[]};
assert.equal(canConfirmImport(preview,true,false,now),true);
for(const [value,accepted,busy] of [[null,true,false],[preview,false,false],[preview,true,true],[{...preview,previewId:undefined},true,false],[{...preview,invalid:1},true,false],[{...preview,total:0,valid:0},true,false],[{...preview,valid:0},true,false],[{...preview,expiresAt:'invalid'},true,false]])assert.equal(canConfirmImport(value,accepted,busy,now),false);
assert.equal(canConfirmImport(preview,true,false,Date.parse(preview.expiresAt)),false);
const ui=await readFile(new URL('./AssetImport.tsx',import.meta.url),'utf8');
assert.ok(ui.includes('previewAssetImport(file)')&&ui.includes('confirmAssetImport(preview!.previewId!)'));
assert.ok(!ui.includes('checkAssetReachability')&&!ui.includes('testAssetAddress'));
console.log('Asset CSV import: all checks passed');
