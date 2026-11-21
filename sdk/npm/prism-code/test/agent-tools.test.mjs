// DK-49: the six agent tools, named as Docker names its verbs, and an app as one content-addressed bundle: prism_push
// publishes a proved app by the BLAKE3 label of its manifest, and prism_pull admits every object by its label, then
// has Lean's kernel prove the model before anything runs. LexLean is never fetched here (PRISM_LEXLEAN_FETCH=0).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { appDir, readSession, startApp, writeSession } from '../src/journey/project.mjs';
import { TOOLS, createServer } from '../src/journey/mcp.mjs';
import { BUNDLE_SCHEMA, bundleOf, parseReference, pullBundle, pushBundle } from '../src/journey/app-bundle.mjs';
import { kappa } from '../src/blake3.mjs';
import { templateFixture } from './support/template-fixture.mjs';

process.env.PRISM_HOME = mkdtempSync(join(tmpdir(), 'prism-home-'));
process.env.PRISM_LEXLEAN_FETCH = '0';
const env = { PRISM_HOME: process.env.PRISM_HOME };
const fresh = (name) => mkdtempSync(join(tmpdir(), `prism-${name}-`));
const ruleApp = () => {
  const dir = appDir(fresh('app'));
  startApp(dir, 'rule-app');
  const session = readSession(dir);
  session.starter = 'rule-app';
  writeSession(dir, session);
  return { dir, session };
};
const serverIn = (cwd, options = {}) => {
  const sent = [];
  const server = createServer({ cwd, send: (m) => sent.push(m), ...options });
  const call = async (name, args = {}) => {
    await server.handle({ jsonrpc: '2.0', id: sent.length + 1, method: 'tools/call', params: { name, arguments: args } });
    return sent.at(-1);
  };
  return { server, sent, call };
};

test('there are six tools, named as Docker names its verbs, and no other name is answered', async () => {
  assert.deepEqual(TOOLS.map((t) => t.name), ['prism_init', 'prism_build', 'prism_run', 'prism_inspect', 'prism_push', 'prism_pull']);
  assert.deepEqual(TOOLS.find((t) => t.name === 'prism_pull').inputSchema.required, ['reference']);
  assert.equal(TOOLS.find((t) => t.name === 'prism_build').inputSchema.properties.check.type, 'boolean');
  const { sent, server, call } = serverIn(fresh('list'));
  await server.handle({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} });
  assert.deepEqual(sent.at(-1).result.tools.map((t) => t.name), TOOLS.map((t) => t.name));
  for (const name of ['prism_start', 'prism_check', 'prism_prove', 'prism_verify', 'prism_try', 'prism_status']) {
    assert.match((await call(name)).error?.message ?? '', new RegExp(`Unknown tool: ${name}`), name);
  }
  assert.match((await call('prism_build', { check: 'yes' })).result.content[0].text, /`check` must be a boolean/);
});

test('an app is one bundle: every object named by the label of its bytes, the app by the label of its manifest', () => {
  const { dir, session } = ruleApp();
  const one = bundleOf(dir, session);
  const two = bundleOf(dir, readSession(dir));
  assert.equal(one.address, two.address, 'the same app is the same address');
  assert.equal(one.manifest.schema, BUNDLE_SCHEMA);
  assert.equal(one.manifest.starter, 'rule-app');
  assert.ok(one.manifest.model['src/App.lex.tex'], 'the model is in the bundle');
  for (const [label, bytes] of one.objects) assert.equal(kappa(bytes), label);
  writeFileSync(join(dir, 'src', 'App.lex.tex'), readFileSync(join(dir, 'src', 'App.lex.tex'), 'utf8') + '\n');
  assert.notEqual(bundleOf(dir, readSession(dir)).address, one.address, 'an edit is another address');
});

test('a bundle pushed to a folder or to this machine is pulled back byte for byte', async () => {
  const { dir, session } = ruleApp();
  const bundle = bundleOf(dir, session);
  const folder = fresh('store');
  const pushed = await pushBundle(bundle, `dir://${folder}`, { env });
  assert.equal(pushed.address, bundle.address);
  assert.equal(pushed.reference, `dir://${folder}#${bundle.address}`);
  assert.equal(readdirSync(folder).length, bundle.objects.size, 'one file per object, named by its label');
  for (const reference of [pushed.reference, (await pushBundle(bundle, undefined, { env })).reference]) {
    const pulled = await pullBundle(reference, { env });
    assert.equal(pulled.address, bundle.address);
    for (const [path, label] of Object.entries(bundle.manifest.model)) assert.equal(kappa(pulled.files.get(path)), label, path);
  }
});

test('an object that does not re-derive its label is refused, and nothing is written', async () => {
  const { dir, session } = ruleApp();
  const bundle = bundleOf(dir, session);
  const folder = fresh('store');
  const { reference } = await pushBundle(bundle, `dir://${folder}`, { env });
  const model = bundle.manifest.model['src/App.lex.tex'];
  writeFileSync(join(folder, model.slice(7)), 'not the model');
  await assert.rejects(pullBundle(reference, { env }), (e) => e.code === 'bundle.altered');
  const into = fresh('into');
  const { call } = serverIn(into);
  const pulled = (await call('prism_pull', { reference })).result.structuredContent;
  assert.equal(pulled.ok, false);
  assert.equal(pulled.code, 'bundle.altered');
  assert.ok(!existsSync(join(appDir(into), 'src')), 'nothing was written');
});

test('a manifest that names a path outside the app is refused', async () => {
  const folder = fresh('store');
  const object = new TextEncoder().encode('x');
  writeFileSync(join(folder, kappa(object).slice(7)), object);
  const manifest = new TextEncoder().encode(JSON.stringify({ schema: BUNDLE_SCHEMA, starter: 'rule-app', entry: 'src/App.lex.tex', model: { '../escape.txt': kappa(object) } }));
  writeFileSync(join(folder, kappa(manifest).slice(7)), manifest);
  await assert.rejects(pullBundle(`dir://${folder}#${kappa(manifest)}`, { env }), (e) => e.code === 'bundle.path');
});

test('references: a κ-label, dir://<folder>#<κ> or https://<site>#<κ>; https is read-only, and a pull names an app', async () => {
  const label = kappa(new TextEncoder().encode('app'));
  assert.deepEqual(parseReference(label), { kind: 'local', at: null, address: label });
  assert.equal(parseReference(`https://example.github.io/apps#${label}`).kind, 'https');
  assert.throws(() => parseReference('ftp://host#x'), (e) => e.code === 'bundle.reference');
  assert.throws(() => parseReference('dir://x#not-a-label'), (e) => e.code === 'bundle.reference');
  const { dir, session } = ruleApp();
  await assert.rejects(pushBundle(bundleOf(dir, session), `https://example.github.io/apps`, { env }), (e) => e.code === 'bundle.read-only');
  await assert.rejects(pullBundle('dir://somewhere', { env }), (e) => e.code === 'bundle.reference');
});

test('prism_push publishes only a proved app', async () => {
  const cwd = fresh('push');
  const { template, fetch } = templateFixture();
  const { call } = serverIn(cwd, { template, fetch });
  assert.equal((await call('prism_push')).result.structuredContent.state, 'blocked');
  assert.equal((await call('prism_init')).result.structuredContent.ok, true);
  const pushed = (await call('prism_push', { reference: `dir://${fresh('store')}` })).result.structuredContent;
  assert.equal(pushed.ok, false);
  assert.equal(pushed.code, 'bundle.unproved');
  assert.match(pushed.message, /Call prism_build first/);
});

test('prism_pull installs the model, and nothing is proved or runs where Lean\'s kernel cannot prove it', async () => {
  const { dir, session } = ruleApp();
  const { reference } = await pushBundle(bundleOf(dir, session), `dir://${fresh('store')}`, { env });
  const into = fresh('into');
  const { call } = serverIn(into);
  const pulled = (await call('prism_pull', { reference })).result.structuredContent;
  // LexLean is not fetched in this test, so the model cannot be checked or proved here: installed, not proved.
  assert.equal(pulled.ok, false);
  assert.equal(pulled.proved.ok, false);
  assert.ok(existsSync(join(appDir(into), 'src', 'App.lex.tex')), 'the model was installed');
  assert.match(pulled.next, /did not prove this app here/);
  assert.equal(pulled.built, undefined, 'nothing was built');
});
