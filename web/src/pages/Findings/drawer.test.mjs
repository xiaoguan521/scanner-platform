// Run from repository root: node web/src/pages/Findings/drawer.test.mjs
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import React from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import ts from 'typescript';

const source = await readFile(new URL('./drawer.ts', import.meta.url), 'utf8');
const js = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2020, module: ts.ModuleKind.ESNext } }).outputText;
const { detailText, detailList, detailIdentifiers, selectedFindingForDrawer: selected } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`);
for (const value of [null, undefined, '', '  ', '\n\t']) assert.equal(detailText(value), '未提供');
assert.equal(detailText(0), '0', 'zero misses/CVSS must remain visible');
assert.equal(detailText(false), 'false');
assert.equal(detailText('  evidence\nsecond line  '), '  evidence\nsecond line  ', 'preserve complete evidence');
assert.equal(detailList(), '未提供');
assert.equal(detailList([]), '未提供');
assert.equal(detailList(['https://example.com', '<script>']), 'https://example.com\n<script>');
assert.equal(detailIdentifiers({}), '未提供');
assert.equal(detailIdentifiers({ CVE: ['CVE-2026-0000'], CWE: [] }), 'CVE: CVE-2026-0000\nCWE: 未提供');
const payload = '<img src=x onerror="alert(1)">\n<script>alert(1)</script> javascript:alert(1)';
assert.equal(detailText(payload), payload, 'do not parse, remove or truncate text');
const html = renderToStaticMarkup(React.createElement('div', null, detailText(payload)));
assert.ok(html.includes('&lt;img') && html.includes('&lt;script&gt;'));
assert.ok(!html.includes('<img') && !html.includes('<script') && !html.includes('<a'), 'untrusted text stays escaped and unlinked');
const longEvidence = 'x'.repeat(100_000);
assert.equal(detailText(longEvidence), longEvidence, 'scrolling must preserve all text');

const original = { id: 'finding-1', status: 'OPEN', evidence: 'old' };
const refreshed = { ...original, status: 'IN_PROGRESS', evidence: 'new' };
assert.equal(selected([original], [original], null), undefined);
assert.equal(selected([original], [original], 'missing'), undefined);
assert.equal(selected([refreshed], [original], original.id), refreshed, 'use the current response object after polling/PATCH');
assert.equal(selected([refreshed], [], original.id), undefined, 'filtered records close');
assert.equal(selected([], [original], original.id), undefined, 'removed records close');

const page = await readFile(new URL('./index.tsx', import.meta.url), 'utf8');
const ast = ts.createSourceFile('index.tsx', page, ts.ScriptTarget.Latest, true, ts.ScriptKind.TSX);
const elements = [];
function visit(node) {
  if (ts.isJsxElement(node) || ts.isJsxSelfClosingElement(node)) elements.push(node);
  ts.forEachChild(node, visit);
}
visit(ast);
const opening = node => ts.isJsxElement(node) ? node.openingElement : node;
const named = name => elements.filter(node => opening(node).tagName.getText(ast) === name);
const attribute = (node, name) => opening(node).attributes.properties.find(prop => prop.name?.getText(ast) === name);
const text = node => node?.getText(ast) ?? '';
assert.equal(named('Drawer').length, 1);
const drawer = named('Drawer')[0];
assert.match(text(attribute(drawer, 'open')), /Boolean\(selectedFinding\)/);
for (const key of ['keyboard', 'maskClosable', 'onClose', 'afterOpenChange']) assert.ok(attribute(drawer, key), key);
assert.match(text(attribute(drawer, 'width')), /100vw/, 'drawer fits narrow screens');
assert.equal(named('Timeline').length, 0, 'existing timestamps are not status events');
assert.match(page, /暂无状态变更记录/);
assert.doesNotMatch(page, /expandable=|dangerouslySetInnerHTML|<a\b|Typography\.Link|Markdown|href=/);
assert.match(page, /\{field\.value\}/, 'long fields use React text children');
assert.match(page, /maxHeight: 240, overflowY: 'auto'/, 'full evidence remains scrollable');
assert.match(page, /detailTrigger\.current\?\.isConnected/);
assert.match(page, /detailTrigger\.current\.focus\(\)/);
assert.match(page, /if \(selectedFindingId && !selectedFinding\) setSelectedFindingId\(null\)/);
assert.doesNotMatch(page, /setSearchParams[^\n]*selectedFinding|setSearchParams[^\n]*finding\.id/, 'details are not URL state');

const buttons = named('Button');
const trigger = buttons.find(button => text(button).includes('>查看详情</Button>'));
assert.ok(trigger && attribute(trigger, 'aria-label'), 'explicit accessible keyboard trigger');
assert.match(text(attribute(trigger, 'onClick')), /event\.stopPropagation\(\)/);
assert.match(text(attribute(trigger, 'onClick')), /openFindingDetails\(r, event\.currentTarget\)/);
const statusButtons = buttons.filter(button => text(attribute(button, 'onClick')).includes('handleUpdateStatus'));
assert.equal(statusButtons.length, 4, 'check every current status action');
for (const button of statusButtons) assert.match(text(attribute(button, 'onClick')), /event\.stopPropagation\(\)/);
for (const field of ['title', 'severity', 'status', 'synthetic', 'target', 'port', 'businessGroup', 'owner', 'engine', 'templateOrCve', 'detectMethod', 'confidence', 'riskType', 'vulnCategory', 'cvssScore', 'identifiers', 'description', 'impact', 'solution', 'evidence', 'matchedPath', 'references', 'package', 'installedVersion', 'fixedVersion', 'firstSeen', 'lastSeen', 'resolvedAt', 'consecutiveMisses', 'assetId', 'taskId']) {
  assert.ok(page.includes(`selectedFinding.${field}`), `drawer field ${field}`);
}
console.log('Findings drawer: helper and source contracts passed');
