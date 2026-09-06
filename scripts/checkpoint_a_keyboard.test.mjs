// Owned synthetic fixtures only. No browser/native executable or live requests.
import assert from 'node:assert/strict';
import test from 'node:test';
import { EventEmitter } from 'node:events';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ORIGIN, sha256, KEYBOARD_SOURCE_FILES, FORBIDDEN_STATE, validateAdmission } from './checkpoint_a_browser_boundary.mjs';
import { validateTLSAdmission } from './checkpoint_a_tls_boundary.mjs';
import { KEYBOARD_SCOPE, KEYBOARD_STEPS, validateKeyboardAdmission, claimKeyboardDiagnostic, keyboardAssets,
  keyboardRequestAllowed, keyboardResponseAllowed, validateFocus, validateKeyboardProof } from './checkpoint_a_keyboard_boundary.mjs';
import { stage } from './checkpoint_a_browser.mjs';
import { main as controller, executeKeyboard } from './checkpoint_a_keyboard.mjs';
import { main as inner, keyboardSequence, keyboardActions } from '../tests/e2e/checkpoint_a_keyboard.mjs';

const repo = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const hash = 'a'.repeat(64), revision = 'b'.repeat(40), now = Date.parse('2026-09-06T05:00:00Z');
const focus = () => ({ dialogOpen: false, documentFocused: false, visible: true,
  triggerFocused: false, searchFocused: false, teamsFocused: false, mainFocused: false });
const admission = () => ({ format: 'stead-checkpoint-a-keyboard-admission-v1', status: 'accepted', scope: KEYBOARD_SCOPE,
  expiresAt: '2026-09-06T06:00:00.000Z', harness: { repository: '/home/fixture/harness', head: revision, tree: revision },
  source: { repository: '/home/fixture/fresh', head: revision, implementationRevision: revision, implementationTree: revision,
    templateSHA256: hash, templateReviewSHA256: hash, apiSHA256: hash },
  instance: { state: '/home/fixture/fresh/.cache/stead-dev', instanceID: '01991c05-1a00-7000-8000-000000000001', bootstrapSHA256: hash, activationDigest: 'sha256:' + hash, certificateSHA256: hash },
  files: Object.fromEntries(KEYBOARD_SOURCE_FILES.map((file) => [file, hash])),
  reviews: ['security', 'qa', 'architecture-license'].map((role) => ({ role, reviewer: '/review/' + role,
    path: '/home/fixture/' + role + '.md', sha256: hash, independentNonAuthor: true, disposition: 'accept' })) });
const proof = () => ({ format: 'stead-checkpoint-a-keyboard-proof-v1', passed: true, phase: 'complete',
  networkIsolated: true, rendererSandbox: true, csp: true, browserCleanup: true,
  steps: KEYBOARD_STEPS.map((step) => ({ step, state: focus() })), failedStep: null, lastState: null,
  sent: 4, responses: 4, blocked: 0, sessions: 1, axeObserved: true });

test('inert distinct scope cannot use TLS or full-journey admission', () => {
  assert.equal(typeof controller, 'function'); assert.equal(typeof inner, 'function');
  assert.deepEqual(validateKeyboardAdmission(admission(), now), admission());
  assert.throws(() => validateAdmission(admission(), now)); assert.throws(() => validateTLSAdmission(admission(), now));
  for (const change of [{ scope: 'one-credential-free-real-origin-tls-diagnostic' }, { status: 'proposed' },
    { cookie: 'not permitted' }, { expiresAt: '2026-09-06T04:00:00.000Z' }, { files: {} }]) {
    assert.throws(() => validateKeyboardAdmission({ ...admission(), ...change }, now));
  }
});
test('synthetic admission is checkout-independent while retained root state remains forbidden', () => {
  const value = admission();
  assert.equal(value.source.repository, '/home/fixture/fresh');
  assert.notEqual(value.source.repository, repo);
  assert.equal(value.instance.state, value.source.repository + '/.cache/stead-dev');
  assert.deepEqual(validateKeyboardAdmission(value, now), value);
  const retained = admission();
  retained.source.repository = '/home/skilgore/stead'; retained.instance.state = FORBIDDEN_STATE;
  assert.throws(() => validateKeyboardAdmission(retained, now));
});
test('exact root/assets/session GETs only; credentials redirects mutation and foreign paths fail', () => {
  const assets = keyboardAssets({ distribution_artifacts: [{ file: 'index.html', sha256: hash }, { file: 'assets/index-unit.js', sha256: hash }, { file: 'assets/index-unit.css', sha256: hash }] });
  for (const [url, type, navigation] of [[ORIGIN + '/', 'document', true], [ORIGIN + assets[0], 'script', false],
    [ORIGIN + assets[1], 'stylesheet', false], [ORIGIN + '/api/v1/session', 'fetch', false]]) {
    assert.equal(keyboardRequestAllowed('GET', url, type, navigation, {}, assets), true);
    assert.equal(keyboardResponseAllowed(url, url.endsWith('/session') ? 401 : 200, {}, assets), true);
    assert.equal(keyboardRequestAllowed('POST', url, type, navigation, {}, assets), false);
    for (const header of ['Cookie', 'authorization', 'Proxy-Authorization']) assert.equal(keyboardRequestAllowed('GET', url, type, navigation, { [header]: 'never retain' }, assets), false);
    for (const header of ['Set-Cookie', 'location']) assert.equal(keyboardResponseAllowed(url, 200, { [header]: 'never retain' }, assets), false);
  }
  for (const url of [ORIGIN + '/teams', ORIGIN + '/api/v1/organizations', ORIGIN + '/assets/unknown.js', ORIGIN + '/?x=1', 'https://foreign.invalid/']) {
    assert.equal(keyboardRequestAllowed('GET', url, 'fetch', false, {}, assets), false);
  }
  assert.equal(keyboardResponseAllowed(ORIGIN + '/api/v1/session', 200, {}, assets), false);
  assert.throws(() => keyboardAssets({ distribution_artifacts: [{ file: 'assets/x.js', sha256: 'changed' }] }));
});
test('staging and claim never include session ingress or replace the failed application marker', () => {
  const directory = mkdtempSync(path.join(tmpdir(), 'stead-keyboard-unit-'));
  try {
    const appMarker = path.join(directory, 'checkpoint-a-browser-attempt.json'); writeFileSync(appMarker, 'first failure', { mode: 0o600 });
    const privateAdmission = path.join(directory, 'admission.json'); writeFileSync(privateAdmission, '{}', { mode: 0o600 });
    claimKeyboardDiagnostic(privateAdmission, { scope: KEYBOARD_SCOPE });
    assert.throws(() => claimKeyboardDiagnostic(privateAdmission, { scope: KEYBOARD_SCOPE }));
    assert.equal(readFileSync(appMarker, 'utf8'), 'first failure');
    const fakeAxe = path.join(directory, 'axe.mjs'); writeFileSync(fakeAxe, 'owned synthetic tool bytes');
    const value = admission();
    // Only owned public source/evidence reads for staging, never live admission.
    value.source.repository = repo;
    value.files = Object.fromEntries(KEYBOARD_SOURCE_FILES.map((file) => [file, sha256(readFileSync(path.join(repo, file)))]));
    const staged = stage({ files: [{ path: fakeAxe, destination: '/tools/axe-core/axe.min.js', sha256: sha256(readFileSync(fakeAxe)), executable: false }] }, directory, value, Buffer.from('public synthetic certificate'), undefined, 'keyboard');
    assert.deepEqual(staged.args.slice(-2), ['/usr/bin/node', '/runner/tests/e2e/checkpoint_a_keyboard.mjs']);
    assert.deepEqual(readdirSync(path.join(directory, 'execution-root/fixture')).sort(), ['axe-pin.json', 'keyboard-assets.json', 'localhost.crt']);
    assert.ok(staged.args.includes('--unshare-all') && staged.args.includes('--cap-drop'));
    assert.ok(!staged.args.some((arg) => /token|cookie|\.key|dev\.env|session-binding/.test(arg)));
    assert.throws(() => stage({ files: [] }, directory, value, Buffer.from('public'), {}, 'keyboard'));
  } finally { rmSync(directory, { recursive: true }); }
});
test('all fixed substeps run in order and first failure stops without retry or raw errors', async () => {
  for (const failAt of [null, 'hidden', 'return_focus', 'route']) {
    const called = [], report = { steps: [], failedStep: null, lastState: null };
    const actions = Object.fromEntries(KEYBOARD_STEPS.map((step) => [step, async () => {
      called.push(step); if (step === failAt) throw new Error('secret exception not retained');
    }]));
    assert.equal(await keyboardSequence(actions, async () => focus(), report), failAt === null);
    const count = failAt === null ? KEYBOARD_STEPS.length : KEYBOARD_STEPS.indexOf(failAt) + 1;
    assert.deepEqual(called, KEYBOARD_STEPS.slice(0, count));
    assert.equal(report.failedStep, failAt); assert.ok(!JSON.stringify(report).includes('secret'));
    assert.equal(report.steps.length, failAt === null ? count : count - 1);
  }
});
test('actual keyboard actions retain original keys and anonymous root navigation without login', async () => {
  const calls = [];
  const locator = (name) => ({
    getByLabel: (label) => locator(label), getByRole: (_role, options) => locator(options.name),
    focus: async () => { calls.push(['focus', String(name)]); },
    waitFor: async (options) => { calls.push(['wait', String(name), options?.state ?? 'visible']); },
    fill: async (value) => { calls.push(['fill', String(name), value]); },
    press: async (key) => { calls.push(['press', String(name), key]); },
    evaluate: async () => true, count: async () => name === 'Sign out' ? 0 : 1,
  });
  const page = { getByRole: (_role, options) => locator(options.name), locator,
    goto: async (url) => { calls.push(['goto', url]); return { status: () => 200, url: () => url }; },
    keyboard: { press: async (key) => { calls.push(['key', key]); } },
    waitForFunction: async () => { calls.push(['focus-wait']); },
    waitForURL: async (url) => { calls.push(['url-wait', url]); },
  };
  const report = { steps: [], failedStep: null, lastState: null };
  assert.equal(await keyboardSequence(keyboardActions(page, async () => { calls.push(['audit']); }), async () => focus(), report), true);
  assert.deepEqual(calls.filter(([op]) => op === 'goto'), [['goto', ORIGIN + '/']]);
  assert.deepEqual(calls.filter(([op]) => op === 'key'), [['key', 'Control+k'], ['key', 'Escape'], ['key', 'Control+k'], ['key', 'Enter']]);
  assert.deepEqual(calls.filter(([op]) => op === 'fill'), [['fill', 'Search commands', 'Teams']]);
  assert.ok(calls.find(([op, name, key]) => op === 'press' && name === 'Search commands' && key === 'Tab'));
  assert.ok(calls.find(([op, url]) => op === 'url-wait' && url === ORIGIN + '/teams'));
  assert.equal(calls.filter(([op]) => op === 'audit').length, 1);
  assert.ok(!JSON.stringify(calls).includes('Setup credential'));
});
test('finite proof rejects raw DOM, omitted substeps, failures relabeled as passes and malformed focus', () => {
  assert.deepEqual(validateKeyboardProof(proof()), proof());
  for (const change of [{ blocked: 1 }, { sessions: 0 }, { responses: 3 }, { browserCleanup: false },
    { steps: [] }, { failedStep: 'private raw error' }, { dom: 'secret' }, { axeObserved: false }]) assert.throws(() => validateKeyboardProof({ ...proof(), ...change }));
  assert.throws(() => validateFocus({ ...focus(), activeElement: 'secret' }));
  assert.throws(() => validateFocus({ ...focus(), dialogOpen: null }));
  const failed = { ...proof(), passed: false, phase: 'keyboard', steps: proof().steps.slice(0, 7), failedStep: 'return_focus', lastState: focus() };
  assert.deepEqual(validateKeyboardProof(failed), failed);
});
test('child status records exact nonzero exit and spawn failure; stdin/output remain closed', async () => {
  for (const [code, signal, error] of [[0, null, false], [2, null, false], [null, 'SIGKILL', false], [null, null, true]]) {
    const actual = await executeKeyboard(['synthetic only'], (command, args, options) => {
      assert.equal(command, '/usr/bin/bwrap'); assert.deepEqual(args, ['synthetic only']);
      assert.deepEqual(options.stdio, ['ignore', 'ignore', 'ignore']);
      assert.equal(options.env.NODE_OPTIONS, undefined); assert.equal(options.env.NODE_DEBUG, undefined);
      const fake = new EventEmitter(); queueMicrotask(() => { if (error) fake.emit('error', new Error('not retained')); fake.emit('close', code, signal); }); return fake;
    });
    assert.deepEqual(actual, { code, signal, timedOut: false, spawnError: error });
  }
});
