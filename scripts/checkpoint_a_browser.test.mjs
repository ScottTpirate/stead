// Dependency-free owned-fixture tests. No tool manifest, browser, credential,
// namespace, installed service, live TLS or external process is invoked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, writeFileSync, chmodSync, symlinkSync, linkSync, readFileSync, rmSync, lstatSync, openSync, closeSync, renameSync, constants } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { allowedRequest, byteBudget, absolute, readBounded, privateDirectory,
  claimAttempt, validateAdmission, validateInnerProof, validateJourney, validateAxe,
  SOURCE_FILES, ORIGIN, FORBIDDEN_STATE, STAGES, SURFACES, OPERATIONS, sha256,
  verifyDistribution, processStat, serviceCommand, listenerInodes, browserCookie,
  preserveSession, validatePreservedSession, SESSION_FILES, openedDirectoryMatches } from './checkpoint_a_browser_boundary.mjs';
import { main as controller } from './checkpoint_a_browser.mjs';
import { main as namespace, auditSurface } from '../tests/e2e/checkpoint_a_browser.mjs';
import { runCheckpointAJourney } from '../tests/e2e/checkpoint_a_browser_journey.mjs';

const uuid = '01991962-1234-7000-8000-123456789abc';
const digest = 'a'.repeat(64), revision = 'b'.repeat(40);
const now = Date.parse('2026-09-05T00:00:00.000Z');
function admission() {
  return { format: 'stead-checkpoint-a-browser-admission-v1', status: 'accepted',
    scope: 'one-fresh-real-checkpoint-a-browser-run', expiresAt: '2026-09-05T01:00:00.000Z',
    source: { repository: '/home/fixture/repository', head: revision, implementationRevision: revision,
      implementationTree: revision, templateSHA256: digest, templateReviewSHA256: digest, apiSHA256: digest },
    instance: { state: '/home/fixture/repository/.cache/stead-dev', instanceID: uuid,
      bootstrapSHA256: digest, activationDigest: 'sha256:' + digest, certificateSHA256: digest },
    files: Object.fromEntries(SOURCE_FILES.map((file) => [file, digest])),
    reviews: ['security', 'qa', 'architecture-license'].map((role) => ({ role, reviewer: '/review/' + role,
      path: '/home/fixture/' + role + '.md', sha256: digest, independentNonAuthor: true, disposition: 'accept' })) };
}
function journey() {
  return { format: 'stead-checkpoint-a-browser-journey-v1', status: 'completed', failedStage: null,
    completed: STAGES.slice(1), timings: STAGES.slice(1).map((stage) => ({ stage, elapsedMs: 1 })), elapsedMs: 10,
    network: ['primary', 'denied'].map((principal) => ({ principal, counts: Object.fromEntries(OPERATIONS.map((op) => [op, 0])),
      requests: 0, responses: 0, failed: 0, forbidden: 0, unknownAPI: 0, overflow: false })),
    accessibility: { status: 'collected_if_reached', surfaces: SURFACES.map((surface) => ({ surface, violations: [], incomplete: [], passedRules: 1 })) },
    denialEvidence: 'ui_only_sql_fga_and_known_unknown_checks_are_separate', contextsPreserved: true };
}
function fixture(task) {
  const directory = mkdtempSync(path.join(tmpdir(), 'stead-browser-unit.')); chmodSync(directory, 0o700);
  // Only this test's freshly created, exact private fixture is removed.
  try { return task(directory); } finally { rmSync(directory, { recursive: true }); }
}
test('importing both entry points does not execute native tools or the journey', () => {
  assert.equal(typeof controller, 'function'); assert.equal(typeof namespace, 'function');
  assert.equal(typeof runCheckpointAJourney, 'function');
});
test('held BFF asset directory cannot be relabeled by replacing its pathname', () => fixture((directory) => {
  const assets = path.join(directory, 'dist'), retained = path.join(directory, 'retained-dist');
  mkdirSync(assets, { mode: 0o700 });
  const held = openSync(assets, constants.O_RDONLY | constants.O_DIRECTORY);
  try {
    assert.equal(openedDirectoryMatches(held, assets), true);
    renameSync(assets, retained); mkdirSync(assets, { mode: 0o700 });
    assert.equal(openedDirectoryMatches(held, assets), false);
    assert.equal(openedDirectoryMatches(held, retained), true);
    const current = openSync(assets, constants.O_RDONLY | constants.O_DIRECTORY);
    try { assert.equal(openedDirectoryMatches(current, assets), true); }
    finally { closeSync(current); }
  } finally { closeSync(held); }
}));
test('closed real-workload admission binds every source file and three distinct reviews', () => {
  assert.deepEqual(validateAdmission(admission(), now), admission());
  for (const mutate of [
    (a) => { a.status = 'proposed'; }, (a) => { a.scope = 'synthetic-browser-compatibility'; },
    (a) => { a.expiresAt = '2026-09-04T23:59:59.000Z'; }, (a) => { a.expiresAt = '2026-09-07T00:00:00.000Z'; },
    (a) => { a.expiresAt = now + 1000; }, (a) => { a.files[SOURCE_FILES[0]] = 'A'.repeat(64); },
    (a) => { delete a.files[SOURCE_FILES[1]]; }, (a) => { a.files['extra.mjs'] = digest; },
    (a) => { a.source.apiSHA256 = ''; }, (a) => { a.source.head = '--help'; },
    (a) => { a.instance.state = '/home/other/.cache/stead-dev'; },
    (a) => { a.source.repository = '/home/skilgore/stead'; a.instance.state = FORBIDDEN_STATE; },
    (a) => { a.reviews[1].reviewer = a.reviews[0].reviewer; }, (a) => { a.reviews[1].role = 'security'; },
    (a) => { a.reviews[0].independentNonAuthor = false; }, (a) => { a.reviews[0].disposition = 'pending'; },
    (a) => { a.instance.primaryCredential = 'never accepted'; },
  ]) { const value = admission(); mutate(value); assert.throws(() => validateAdmission(value, now)); }
});
test('only canonical paths accepted, never aliases or broad roots', () => {
  assert.equal(absolute('/home/fixture/source'), '/home/fixture/source');
  for (const file of ['/', '/home/../home/source', '/home//source', '/home/source/', './source', '/home/secret\n', '/home/a\0b', '/home/a b']) assert.throws(() => absolute(file));
});
test('owned bounded files reject symlinks, hardlinks, widened permissions and oversize', () => fixture((directory) => {
  privateDirectory(directory);
  const file = path.join(directory, 'fixture'); writeFileSync(file, 'abc', { mode: 0o600, flag: 'wx' });
  assert.equal(readBounded(file, 3, { privateMode: true }).toString(), 'abc');
  assert.throws(() => readBounded(file, 2));
  assert.throws(() => readBounded(file, 3, { owner: process.getuid() + 1 }));
  const alias = path.join(directory, 'alias'); symlinkSync(file, alias); assert.throws(() => readBounded(alias, 3));
  chmodSync(file, 0o640); assert.throws(() => readBounded(file, 3, { privateMode: true }));
  chmodSync(file, 0o622); assert.throws(() => readBounded(file, 3)); chmodSync(file, 0o600);
  linkSync(file, path.join(directory, 'linked')); assert.throws(() => readBounded(file, 3));
}));
test('one-shot marker is durable, private, exclusive and never overwritten on retry', () => fixture((directory) => {
  const file = claimAttempt(directory, { fixture: true });
  const prior = readFileSync(file); assert.equal(lstatSync(file).mode & 0o777, 0o600);
  assert.throws(() => claimAttempt(directory, { fixture: false })); assert.deepEqual(readFileSync(file), prior);
}));
test('private state rejects symlinked parent and nonprivate root', () => fixture((directory) => {
  const alias = directory + '-alias'; symlinkSync(directory, alias);
  try { assert.throws(() => privateDirectory(alias)); } finally { rmSync(alias); }
  chmodSync(directory, 0o750); assert.throws(() => privateDirectory(directory));
}));
test('actual UI-generated metadata requests and fixed asset paths are allowed', () => {
  for (const resource of ['', 'inbox', 'my-work', 'projects', 'knowledge', 'teams', 'assets/index-AbC123.js', 'assets/index-A1.css']) assert.equal(allowedRequest('GET', `${ORIGIN}/${resource}`), true);
  for (const resource of ['session', 'organizations', `organizations/${uuid}/teams`, `organizations/${uuid}/projects`]) {
    assert.equal(allowedRequest('GET', `${ORIGIN}/api/v1/${resource}`), true);
    assert.equal(allowedRequest('POST', `${ORIGIN}/api/v1/${resource}`), true);
  }
  for (const resource of ['organizations', `organizations/${uuid}/teams`, `organizations/${uuid}/projects`]) assert.equal(allowedRequest('GET', `${ORIGIN}/api/v1/${resource}?page_size=20`), true);
  assert.equal(allowedRequest('GET', `${ORIGIN}/api/v1/projects/${uuid}`), true);
});
test('network assertion rejects other origins, raw provider calls, protocols and path tricks', () => {
  for (const url of ['http://localhost:18443/', 'https://127.0.0.1:18443/', 'https://localhost:13000/',
    'https://user@localhost:18443/', 'https://localhost.:18443/', `${ORIGIN}/#`, `${ORIGIN}/api/v1/session?`,
    `${ORIGIN}/api/v1/session?token=secret`, `${ORIGIN}/api/v1/organizations?page_size=20&page_size=20`,
    `${ORIGIN}/api/v1/organizations?page_size=2000`, `${ORIGIN}/api/v1/organizations?after=${uuid}&page_size=20`,
    `${ORIGIN}/api/v1/organizations/../session`, `${ORIGIN}/api/v1/%73ession`, `${ORIGIN}/api/v1/session#x`,
    `${ORIGIN}/api/v1/repos`, `${ORIGIN}/api/v1/session/`, `${ORIGIN}/assets/../session.js`, 'file:///etc/passwd',
    'wss://localhost:18443/', `${ORIGIN}/\u000a`, `${ORIGIN}/api/v1/session\\extra`]) assert.equal(allowedRequest('GET', url), false, 'closed URL');
  for (const method of ['DELETE', 'PUT', 'PATCH', 'CONNECT', 'OPTIONS', 'get']) assert.equal(allowedRequest(method, `${ORIGIN}/api/v1/session`), false);
  assert.equal(allowedRequest('POST', `${ORIGIN}/api/v1/teams/${uuid}`), false);
});
test('byte budget is aggregate and permanently fails after overflow or invalid input', () => {
  const budget = byteBudget(10); assert.equal(budget.add(6), true); assert.equal(budget.add(4), true);
  assert.equal(budget.add(1), false); assert.equal(budget.add(0), false); assert.equal(budget.exceeded, true);
  for (const value of [-1, NaN, Infinity, 0.5, '1']) { const item = byteBudget(10); assert.equal(item.add(value), false); }
});
test('only closed proof fields are retained; DOM, secrets and raw errors cannot be added', () => {
  const good = journey(); assert.deepEqual(validateJourney(good), good);
  for (const mutate of [
    (j) => { j.error = 'secret'; }, (j) => { j.timings[0].stage = 'private title'; },
    (j) => { j.completed.reverse(); }, (j) => { j.network[0].headers = {}; },
    (j) => { j.network[0].counts.session_create = -1; }, (j) => { j.accessibility.surfaces[0].html = 'DOM'; },
    (j) => { j.accessibility.surfaces[0].violations = [{ rule: 'label', impact: 'serious', affectedNodes: 1, html: 'DOM' }]; },
    (j) => { j.failedStage = 'raw exception'; }, (j) => { j.completed.pop(); },
  ]) { const value = journey(); mutate(value); assert.throws(() => validateJourney(value)); }
  const proof = { format: 'stead-checkpoint-a-browser-proof-v1', passed: true, phase: 'complete', networkIsolated: true,
    rendererSandbox: true, cspPreserved: true, browserCleanup: true, journey: good };
  validateInnerProof(proof);
  for (const field of ['networkIsolated', 'rendererSandbox', 'cspPreserved', 'browserCleanup']) assert.throws(() => validateInnerProof({ ...proof, [field]: false }));
  assert.throws(() => validateInnerProof({ ...proof, stdout: 'secret' }));
  assert.throws(() => validateAxe({ surface: SURFACES[0], violations: [{ rule: 'label', impact: 'serious', affectedNodes: 2049 }], incomplete: [], passedRules: 1 }, SURFACES[0]));
});

test('served dist must exactly match existing bundle evidence, including hidden manifest', () => fixture((directory) => {
  const write = (file, bytes) => { mkdirSync(path.dirname(path.join(directory, file)), { recursive: true, mode: 0o700 }); writeFileSync(path.join(directory, file), bytes, { mode: 0o600 }); };
  const original = [['index.html', '<html></html>'], ['.vite/manifest.json', '{}'], ['assets/app.js', 'original_fixture']];
  original.forEach(([file, bytes]) => write(file, bytes));
  const evidence = { schema_version: '1.3', distribution_artifacts: original.map(([file, bytes]) => ({ file, sha256: sha256(bytes), uncompressed_bytes: Buffer.byteLength(bytes) })) };
  const pin = verifyDistribution(directory, evidence); assert.equal(typeof pin, 'string');
  write('assets/app.js', 'stale_ui_fixture'); assert.throws(() => verifyDistribution(directory, evidence)); write('assets/app.js', 'original_fixture');
  write('assets/extra.js', 'extra'); assert.throws(() => verifyDistribution(directory, evidence)); rmSync(path.join(directory, 'assets/extra.js'));
  rmSync(path.join(directory, '.vite/manifest.json')); assert.throws(() => verifyDistribution(directory, evidence)); write('.vite/manifest.json', '{}');
  mkdirSync(path.join(directory, 'extra-directory')); assert.throws(() => verifyDistribution(directory, evidence)); rmSync(path.join(directory, 'extra-directory'), { recursive: true });
  rmSync(path.join(directory, 'assets/app.js')); symlinkSync(path.join(directory, 'index.html'), path.join(directory, 'assets/app.js')); assert.throws(() => verifyDistribution(directory, evidence)); rmSync(path.join(directory, 'assets/app.js')); write('assets/app.js', 'original_fixture');
  assert.equal(verifyDistribution(directory, evidence), pin);
  for (const change of [
    (e) => { e.distribution_artifacts.push(e.distribution_artifacts[0]); },
    (e) => { e.distribution_artifacts[0].file = '../index.html'; },
    (e) => { e.distribution_artifacts[0].uncompressed_bytes = 8388609; },
  ]) { const value = structuredClone(evidence); change(value); assert.throws(() => verifyDistribution(directory, value)); }
}));
test('process stat retains direct parent and start identity, rejecting dead or mismatched PID', () => {
  const stat = (pid, state, parent, start) => `${pid} (test name ) with brackets) ${[state, parent, ...Array(17).fill('0'), start, '0'].join(' ')}\n`;
  assert.deepEqual(processStat(stat(100, 'S', 50, '1234'), 100), { parent: 50, start: '1234' });
  assert.notDeepEqual(processStat(stat(100, 'S', 51, '1234'), 100), { parent: 50, start: '1234' });
  assert.notDeepEqual(processStat(stat(100, 'S', 50, '1235'), 100), { parent: 50, start: '1234' });
  for (const value of [stat(101, 'S', 50, '1234'), stat(100, 'Z', 50, '1234'), stat(100, 'X', 50, '1234'), stat(100, 'S', 'bad', '1234'), stat(100, 'S', 50, '-1')]) assert.throws(() => processStat(value, 100));
});
test('BFF command binds current served assets, fixed upstream/listener and fresh TLS paths', () => {
  const repo = '/home/fixture/repository', state = repo + '/.cache/stead-dev', binary = state + '/stead-api';
  const args = [binary, 'dev-web', '--listen', '127.0.0.1:18443', '--origin', ORIGIN, '--upstream', 'http://127.0.0.1:18000',
    '--assets', repo + '/apps/web/dist', '--tls-cert', state + '/tls/localhost.crt', '--tls-key', state + '/tls/localhost.key'];
  assert.equal(serviceCommand([binary], state, repo), 'api'); assert.equal(serviceCommand(args, state, repo), 'web');
  for (const index of [0, 1, 3, 5, 7, 9, 11, 13]) { const changed = [...args]; changed[index] += '-stale'; assert.throws(() => serviceCommand(changed, state, repo)); }
  assert.throws(() => serviceCommand([...args, '--assets', repo + '/apps/web/dist'], state, repo));
  assert.throws(() => serviceCommand([binary, '--unknown'], state, repo));
});
test('only unique literal-loopback API/BFF listening socket inodes are attributable', () => {
  const header = 'sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode';
  const row = (port, inode, { address = '0100007F', uid = 1000, state = '0A' } = {}) => `0: ${address}:${port} 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 ${uid} 0 ${inode}`;
  const api = row('4650', '10001'), web = row('480B', '10002'), valid = `${header}\n${api}\n${web}\n`;
  assert.deepEqual(listenerInodes(valid, header + '\n', 1000), { api: '10001', web: '10002' });
  for (const invalid of [
    `${header}\n${api}`, `${header}\n${api}\n${web}\n${api}`,
    `${header}\n${row('4650', '10001', { address: '00000000' })}\n${web}`,
    `${header}\n${row('4650', '10001', { uid: 1001 })}\n${web}`,
    `${header}\n${row('4650', '10001', { state: '01' })}\n${web}`,
    `${header}\n${api}\n${row('480B', '10001')}`,
  ]) assert.throws(() => listenerInodes(invalid, header + '\n', 1000));
  assert.throws(() => listenerInodes(valid, `${header}\n${row('480B', '20000', { address: '00000000000000000000000000000000' })}`, 1000));
});
test('axe requires boolean eval/Function denial in the exact CSP-constrained CDP world', async () => {
  const run = async (negativeResult) => {
    const calls = []; let detached = false, evaluations = 0;
    const session = { send: async (method, args) => {
      calls.push({ method, args });
      if (method === 'Page.getFrameTree') return { frameTree: { frame: { id: 'owned-fixture-frame' } } };
      if (method === 'Page.createIsolatedWorld') return { executionContextId: 7 };
      assert.equal(method, 'Runtime.evaluate'); evaluations++;
      if (evaluations === 1) return negativeResult;
      if (evaluations === 2) return { result: {} };
      return { result: { value: { violations: [], incomplete: [], passedRules: 1 } } };
    }, detach: async () => { detached = true; } };
    const page = { context: () => ({ newCDPSession: async () => session }) };
    let result, error;
    try { result = await auditSurface(page, SURFACES[0], 'original_unit_fixture_source_not_evaluated'); }
    catch (caught) { error = caught; }
    return { calls, result, error, detached };
  };
  const good = await run({ result: { value: true } }); assert.equal(good.error, undefined); assert.equal(good.detached, true);
  const world = good.calls.find((call) => call.method === 'Page.createIsolatedWorld').args;
  assert.equal(world.grantUniveralAccess, false); assert.match(world.contentSecurityPolicy, /script-src 'self'/);
  const evaluations = good.calls.filter((call) => call.method === 'Runtime.evaluate'); assert.equal(evaluations.length, 3);
  for (const call of evaluations) { assert.equal(call.args.contextId, 7); assert.equal(call.args.allowUnsafeEvalBlockedByCSP, false); }
  assert.match(evaluations[0].args.expression, /globalThis\.eval/); assert.match(evaluations[0].args.expression, /globalThis\.Function/);
  for (const negative of [{ result: { value: false } }, { result: { value: 'true' } }, { result: { value: true }, exceptionDetails: {} }, { result: {} }]) {
    const failed = await run(negative); assert.ok(failed.error); assert.equal(failed.detached, true);
    assert.equal(failed.calls.filter((call) => call.method === 'Runtime.evaluate').length, 1);
  }
});
const unitCookie = () => ({ name: '__Host-stead_session', value: 'A'.repeat(43), domain: 'localhost', path: '/',
  expires: (now + 3600_000) / 1000, httpOnly: true, secure: true, sameSite: 'Strict' });
const unitBinding = () => ({ admissionSHA256: digest, sourceRevision: revision, instanceID: uuid });
test('private browser handoff accepts only one exact established host-only cookie', () => {
  assert.equal(browserCookie([unitCookie()], now).credential.origin, ORIGIN);
  for (const cookies of [[], [unitCookie(), unitCookie()]]) assert.throws(() => browserCookie(cookies, now));
  for (const [key, value] of [
    ['name', 'stead_session'], ['value', 'B'.repeat(43)], ['value', 'A'.repeat(42)], ['domain', '.localhost'],
    ['domain', '127.0.0.1'], ['path', '/api'], ['httpOnly', false], ['secure', false], ['sameSite', 'Lax'],
    ['expires', -1], ['expires', now / 1000], ['expires', Infinity], ['expires', (now + 86400_001) / 1000],
    ['partitionKey', 'https://localhost'],
  ]) assert.throws(() => browserCookie([{ ...unitCookie(), [key]: value }], now));
});
test('established session is source-bound in separate exclusive private files, never overwritten', () => fixture((directory) => {
  const role = 'primary', binding = unitBinding(); preserveSession(directory, role, [unitCookie()], binding, now);
  const file = path.join(directory, SESSION_FILES[role]), metadataFile = path.join(directory, 'primary-session-binding.json');
  const bytes = readFileSync(file), metadataBytes = readFileSync(metadataFile);
  assert.equal(lstatSync(file).mode & 0o777, 0o600); assert.equal(lstatSync(metadataFile).mode & 0o777, 0o600);
  const credential = JSON.parse(bytes), metadata = JSON.parse(metadataBytes);
  assert.deepEqual(Object.keys(credential).sort(), ['cookie', 'origin']);
  validatePreservedSession(credential, metadata, role, binding, now);
  assert.throws(() => preserveSession(directory, role, [unitCookie()], binding, now));
  assert.deepEqual(readFileSync(file), bytes); assert.deepEqual(readFileSync(metadataFile), metadataBytes);
  for (const [key, value] of [['role', 'denied'], ['instanceID', revision], ['sourceRevision', 'c'.repeat(40)],
    ['admissionSHA256', 'd'.repeat(64)], ['cookieSHA256', '0'.repeat(64)], ['expiresAt', now / 1000]]) {
    assert.throws(() => validatePreservedSession(credential, { ...metadata, [key]: value }, role, binding, now));
  }
  assert.throws(() => validatePreservedSession({ ...credential, body: 'not retained' }, metadata, role, binding, now));
}));
test('partial handoff stays preserved/ambiguous and missing cookies never create output', () => fixture((directory) => {
  assert.throws(() => preserveSession(directory, 'denied', [], unitBinding(), now));
  const bindingFile = path.join(directory, 'denied-session-binding.json');
  writeFileSync(bindingFile, 'original interrupted fixture', { mode: 0o600, flag: 'wx' });
  assert.throws(() => preserveSession(directory, 'denied', [unitCookie()], unitBinding(), now));
  assert.equal(readFileSync(bindingFile, 'utf8'), 'original interrupted fixture');
  const file = path.join(directory, SESSION_FILES.denied), before = readFileSync(file);
  assert.throws(() => preserveSession(directory, 'denied', [unitCookie()], unitBinding(), now));
  assert.deepEqual(readFileSync(file), before);
}));
