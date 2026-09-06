// Dependency-free owned-fixture tests. No tool manifest, browser, credential,
// namespace, installed service, live TLS or external process is invoked.
import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, chmodSync, symlinkSync, linkSync, readFileSync, rmSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { allowedRequest, byteBudget, absolute, readBounded, privateDirectory,
  claimAttempt, validateAdmission, validateInnerProof, validateJourney, validateAxe,
  SOURCE_FILES, ORIGIN, FORBIDDEN_STATE, STAGES, SURFACES, OPERATIONS } from './checkpoint_a_browser_boundary.mjs';
import { main as controller } from './checkpoint_a_browser.mjs';
import { main as namespace } from '../tests/e2e/checkpoint_a_browser.mjs';
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
