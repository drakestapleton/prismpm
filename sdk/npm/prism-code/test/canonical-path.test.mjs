// The canonical path is what `npx prism-code@latest setup` leads every user to: an app's one source of
// truth is its LexLean model, started from a content-addressed starter and written by the agent. There is
// no spec file. These tests hold the whole surface a new user meets to that one path, and to no other, and
// hold every part of it to saying what runs without Docker: LexLean as WebAssembly, and Lean for an app's own theorems.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { INSTRUCTIONS } from '../src/journey/mcp.mjs';

// LexLean as WebAssembly is never fetched by these tests; a test that needs it names it with PRISM_LEXLEAN_WASM.
process.env.PRISM_LEXLEAN_FETCH = '0';
const bin = fileURLToPath(new URL('../bin/prism-code.mjs', import.meta.url));
const skill = readFileSync(new URL('../skill/SKILL.md', import.meta.url), 'utf8');
const scratch = () => mkdtempSync(join(tmpdir(), 'prism-canonical-'));
const run = (args, { cwd = scratch(), env = {} } = {}) => {
  const r = spawnSync(process.execPath, [bin, ...args], { encoding: 'utf8', timeout: 120000, cwd, env: { ...process.env, ...env } });
  return { code: r.status, out: r.stdout ?? '', err: r.stderr ?? '' };
};

/** A home with the agents setup looks for, so its plan is the plan a user would get. */
function agentHome() {
  const home = scratch();
  for (const d of ['.codex', '.cursor', '.config/Code/User']) mkdirSync(join(home, d), { recursive: true });
  return { HOME: home, USERPROFILE: home, APPDATA: join(home, 'AppData'), XDG_CONFIG_HOME: join(home, '.config'), PRISM_HOME: join(home, '.prism') };
}

test('setup gives every agent the local Prism server and never the hosted one; --hosted is refused', () => {
  const env = agentHome();
  const plan = JSON.parse(run(['setup', '--dry-run', '--agents-only', '--json'], { env }).out);
  assert.ok(plan.journey.some((row) => row.status === 'configure'), 'the local prism server is added');
  assert.deepEqual(plan.agents.filter((row) => row.status === 'configure'), [], 'no agent is given the hosted server');
  const asked = run(['setup', '--dry-run', '--agents-only', '--json', '--hosted'], { env });
  assert.equal(asked.code, 64, asked.err);
  assert.match(asked.err, /setup no longer takes --hosted/);
  assert.equal(asked.out, '');
  assert.match(run(['setup', '--dry-run', '--agents-only'], { env }).out, /not added; every app is proved by Lean's kernel, as WebAssembly, on this machine, and nothing is sent/);
});

test('setup ends by telling the user that no step needs Docker, then to ask an agent for an app', () => {
  const plan = JSON.parse(run(['setup', '--dry-run', '--agents-only', '--json'], { env: agentHome() }).out);
  assert.match(plan.next.join(' '), /No step needs Docker, an image or a server\. LexLean runs as WebAssembly.*Phase 3.*Phase 4.*Nothing about the app is sent anywhere/);
  assert.doesNotMatch(plan.next.join(' '), /hosted/);
  assert.match(plan.next.at(-1), /build me a Prism app/);
});

test('the MCP instructions every agent receives name the LexLean model and the six tools, that no step needs Docker or a server, and leave the tier to the user', () => {
  assert.match(INSTRUCTIONS, /canonical template; its one source of truth is its LexLean model in app\/src\//);
  assert.match(INSTRUCTIONS, /For Prism or \/prism, call prism_init\./);
  for (const name of ['prism_build', 'prism_run', 'prism_inspect', 'prism_push', 'prism_pull']) assert.ok(INSTRUCTIONS.includes(name), name);
  assert.doesNotMatch(INSTRUCTIONS, /prism_start|prism_check|prism_prove|prism_verify|prism_try|prism_status/);
  assert.match(INSTRUCTIONS, /No step needs Docker, an image or a server\. LexLean runs as WebAssembly/);
  assert.match(INSTRUCTIONS, /Never set PRISM_CODE_TIER yourself/);
  assert.ok(INSTRUCTIONS.split(/\s+/).length < 200, 'the instructions stay short enough to be read');
});

test('the skill setup installs teaches the canonical path and no other, and says what runs without Docker', () => {
  assert.match(skill, /\*\*The canonical path\.\*\* Every Prism app is built this way, and no other/);
  assert.match(skill, /There is no second way to build a Prism app/);
  assert.match(skill, /\*\*What runs without Docker\.\*\*/);
  assert.match(skill, /PRISM_LEXLEAN_WASM/);
  assert.match(skill, /build\.frontend-unavailable/);
  // The four tools, and no hosted verifier or opt-in to one.
  for (const name of ['prism_init', 'prism_build', 'prism_run', 'prism_inspect']) assert.ok(skill.includes(`\`${name}\``), name);
  assert.doesNotMatch(skill, /PRISM_CODE_TIER=hosted|hosted verifier|--hosted\]/);
  // The routes that competed with it: a spec file, an agent drafting on the hosted server, and a repository made by hand.
  assert.doesNotMatch(skill, /spec\.json|prism\/spec\/|prism_spec|prism_answer/);
  assert.doesNotMatch(skill, /lexlean_draft_assemble|lexlean_draft_write/);
  assert.doesNotMatch(skill, /gh repo create OWNER\/NAME --template/);
});

test('a scaffolded LexLean project says a Prism app is one too, started from a starter', () => {
  const r = run(['init', join(scratch(), 'proj')]);
  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /A Prism app is a LexLean project too/);
  assert.doesNotMatch(r.out, /spec\.json/);
});

test('check takes no --spec: there is no spec to hold a holo to', () => {
  const dir = scratch();
  const policy = join(dir, 'p0.json');
  writeFileSync(policy, '{"minimum":"P0"}');
  const holo = fileURLToPath(new URL('../fixtures/Calculator.holo', import.meta.url));
  const asked = run(['check', holo, '--policy', policy, '--spec', join(dir, 'spec.json')]);
  assert.equal(asked.code, 64, asked.err || asked.out);
  const plain = run(['check', holo, '--policy', policy]);
  assert.equal(plain.code, 0, plain.err);
  assert.doesNotMatch(plain.out, /^spec /m);
});
