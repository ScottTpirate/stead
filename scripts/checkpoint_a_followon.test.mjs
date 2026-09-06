// SPDX-License-Identifier: Apache-2.0
// Owned synthetic filesystem/HTTP fixtures only. No live credentials or tools.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { mkdtemp, readFile, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { preserveSession, SESSION_FILES } from './checkpoint_a_browser_boundary.mjs';
import { loadEstablishedSessions, checkSession, checkBrowserBinding, readWorker, runReaders, joinReadObservations, TIMING_FIELDS, runFollowon } from './checkpoint_a_followon.mjs';

const id = (n) => '01991c05-1a00-7000-8000-' + n.toString(16).padStart(12, '0');
const ids = { known_organization: id(1), unknown_organization: id(2),
  known_team: id(3), unknown_team: id(4), known_project: id(5), unknown_project: id(6) };
const binding = { admissionSHA256: 'a'.repeat(64), sourceRevision: 'b'.repeat(40), instanceID: id(10) };
const expected = { primary: { instance_id: id(10), principal_id: id(11) },
  denied: { instance_id: id(10), principal_id: id(12) } };
const expiresAt = Math.floor(Date.now() / 1000) + 3600;
const token = (n) => Buffer.alloc(32, n).toString('base64url');
const sessions = Object.fromEntries(['primary', 'denied'].map((role, n) =>
  [role, { cookie: '__Host-stead_session=' + token(n + 1), expiresAt }]));
const cookie = (n) => [{ name: '__Host-stead_session', value: token(n), domain: 'localhost', path: '/',
  expires: expiresAt, httpOnly: true, secure: true, sameSite: 'Strict' }];
const session = (role) => ({ principal: { type: 'user', id: expected[role].principal_id },
  instance_id: id(10), expires_at: new Date(expiresAt * 1000).toISOString(), session_revision: 2 });
const presentation = { profile_id: 'commercial', profile_version: '1.0.0', policy_bundle_id: 'unit',
  label_revision: '1', renderer_id: 'unit', renderer_version: '1.0.0',
  markings: [{ kind: 'sensitivity', text: 'Internal' }], required_surfaces: ['badge'],
  warning_actions: [], text_authoritative: true, color_supplemental_only: true };
function resource(kind) {
  const resourceID = ids['known_' + kind], actor = { type: 'user', id: id(11) };
  const common = { kind, id: resourceID, uri: 'urn:uuid:' + resourceID,
    browser_url: 'https://localhost:18443/r/' + kind + '/' + resourceID,
    schema_version: '1.0', version: 1, instance_id: id(10), scope_kind: 'organization',
    scope_id: id(1), organization_id: id(1), title: 'Protected synthetic fixture',
    effective_security_label: { profile_id: 'commercial', sensitivity_level: 'internal', version: 1 },
    security_presentation: presentation };
  if (kind === 'project') return { ...common, purpose: 'Unit fixture', lifecycle_state: 'active',
    owning_team_id: id(3), authorized_capabilities: ['work', 'docs'], visible_areas: ['overview', 'work', 'docs'] };
  return { ...common, container: { kind: 'organization', id: id(1), uri: 'urn:uuid:' + id(1) },
    created_at: '2026-09-05T00:00:00Z', updated_at: '2026-09-05T00:00:00Z',
    created_by: actor, updated_by: actor, security_label_id: id(13),
    provenance: { created_at: '2026-09-05T00:00:00Z', created_by: actor },
    external_references: [], relationships: [], key: 'FIXTURE', name: common.title,
    ...(kind === 'team' ? { hierarchy_depth: 0 } : {}) };
}
const timing = () => Object.fromEntries(TIMING_FIELDS.map((field) => [field, 0]));
const problem = (correlation) => ({ type: 'about:blank', title: 'The request could not be completed.',
  status: 404, correlation_id: correlation });

function fixture(modify = () => {}) {
  const requests = [], agents = new Set(), pending = new Map(), events = [];
  let active = 0, maximum = 0;
  const request = (url, options, callback) => {
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = (outgoing) => {
      const number = requests.length + 1, correlation = number.toString(16).padStart(32, '0');
      const role = options.headers.Cookie === sessions.primary.cookie ? 'primary' : 'denied';
      assert.equal(options.headers.Cookie, sessions[role].cookie);
      assert.equal(options.method, 'GET'); assert.equal(outgoing, undefined);
      assert.equal(options.rejectUnauthorized, true); assert.equal(options.servername, 'localhost');
      assert.equal(options.agent.options.maxSockets, 1);
      assert.equal(pending.get(options.agent) ?? 0, 0);
      pending.set(options.agent, 1); agents.add(options.agent); active++; maximum = Math.max(maximum, active);
      requests.push({ url, options, correlation, role });
      const kind = url.pathname.includes('/organizations/') ? 'organization' : url.pathname.includes('/teams/') ? 'team' : 'project';
      const isSession = url.pathname === '/api/v1/session', target = url.pathname.split('/').at(-1);
      const allowed = role === 'primary' && target === ids['known_' + kind];
      const entry = { status: isSession || allowed ? 200 : 404,
        data: isSession ? session(role) : allowed ? resource(kind) : problem(correlation),
        headers: { 'x-correlation-id': correlation, 'cache-control': 'no-store',
          'content-type': isSession || allowed ? 'application/json' : 'application/problem+json',
          ...(allowed ? { 'stead-schema-version': '1.0', etag: '"1"' } : {}) } };
      modify(entry, { number, role, url, correlation, isSession });
      setTimeout(() => {
        const body = Buffer.from(JSON.stringify(entry.data) + '\n');
        const response = Readable.from([body]); response.statusCode = entry.status; response.headers = entry.headers;
        response.once('end', () => { active--; pending.set(options.agent, 0); });
        events.push({ correlation_id: correlation, status: entry.status, duration_ms: 1,
          response_bytes: body.length, sql_queries: 3, sql_writes: 1, audit_writes: 1,
          outbox_writes: 0, openfga_calls: allowed ? 1 : 0, provider_calls: 0, timing: timing() });
        callback(response);
      }, 1 + number % 3);
    };
    return req;
  };
  return { request, requests, agents, events, max: () => maximum };
}

test('import exposes only inert helpers; no live run occurs', () => {
  assert.equal(typeof runFollowon, 'function'); assert.equal(typeof readWorker, 'function');
});
test('prior browser proof binds distinct harness and frozen app without relabeling session source', () => {
  const admission = { harness: { head: 'c'.repeat(40) }, source: { head: binding.sourceRevision },
    instance: { instanceID: binding.instanceID } };
  const preceding = { format: 'stead-checkpoint-a-browser-run-v1', inputsUnchanged: true,
    admissionSHA256: binding.admissionSHA256, sourceRevision: binding.sourceRevision,
    harnessRevision: admission.harness.head, instanceID: binding.instanceID,
    sessions: { primary: 'preserved', denied: 'preserved' } };
  assert.deepEqual(checkBrowserBinding(admission, preceding, binding.admissionSHA256), binding);
  for (const change of [{ harnessRevision: binding.sourceRevision }, { harnessRevision: undefined },
    { sourceRevision: admission.harness.head }, { instanceID: id(99) },
    { admissionSHA256: 'd'.repeat(64) }, { inputsUnchanged: false },
    { sessions: { primary: 'preserved', denied: 'absent' } }]) {
    assert.throws(() => checkBrowserBinding(admission, { ...preceding, ...change }, binding.admissionSHA256));
  }
});
test('missing and partial browser handoffs never read or replay a bootstrap token', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'stead-followon-unit-'));
  try {
    await writeFile(path.join(directory, 'one-time-login-token'), 'untouched synthetic marker', { mode: 0o600 });
    await assert.rejects(loadEstablishedSessions(directory, binding));
    assert.deepEqual(await readdir(directory), ['one-time-login-token']);
    await writeFile(path.join(directory, SESSION_FILES.primary), '{"login_in_flight":true}', { mode: 0o600 });
    await assert.rejects(loadEstablishedSessions(directory, binding));
    assert.equal(await readFile(path.join(directory, 'one-time-login-token'), 'utf8'), 'untouched synthetic marker');
    assert.equal((await readdir(directory)).length, 2);
  } finally { await rm(directory, { recursive: true }); }
});
test('established files require matching source instance role digest and future expiry', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'stead-followon-unit-'));
  try {
    preserveSession(directory, 'primary', cookie(1), binding);
    preserveSession(directory, 'denied', cookie(2), binding);
    assert.deepEqual(await loadEstablishedSessions(directory, binding), sessions);
    for (const change of [{ instanceID: id(99) }, { sourceRevision: 'c'.repeat(40) }, { admissionSHA256: 'd'.repeat(64) }]) {
      await assert.rejects(loadEstablishedSessions(directory, { ...binding, ...change }));
    }
    const file = path.join(directory, 'denied-session-binding.json'), original = await readFile(file);
    for (const change of [{ role: 'primary' }, { cookieSHA256: '0'.repeat(64) }, { expiresAt: Date.now() / 1000 - 1 }]) {
      await writeFile(file, JSON.stringify({ ...JSON.parse(original), ...change }));
      await assert.rejects(loadEstablishedSessions(directory, binding));
    }
  } finally { await rm(directory, { recursive: true }); }
});
test('current session must identify the expected principal and completed exchange without extending expiry', () => {
  assert.equal(checkSession(session('primary'), expected.primary, expiresAt).revision, 2);
  for (const change of [{ principal: { type: 'user', id: id(99) } }, { instance_id: id(99) },
    { session_revision: 1 }, { session_revision: 2.5 }, { expires_at: '2000-01-01T00:00:00Z' },
    { expires_at: new Date((expiresAt + 1) * 1000).toISOString() }]) {
    assert.throws(() => checkSession({ ...session('primary'), ...change }, expected.primary, expiresAt));
  }
});
test('worker cannot login logout mutate read arbitrary IDs or use its serial slot concurrently', async () => {
  const f = fixture(), worker = readWorker(Buffer.from('unit certificate'), sessions.primary, ids, f.request);
  try {
    for (const operation of ['createSession', 'deleteSession', 'createOrganization', 'listOrganizations']) {
      await assert.rejects(worker.call(operation, {}));
    }
    await assert.rejects(worker.call('getOrganization', { path: { organization_id: id(99) } }));
    assert.equal(f.requests.length, 0);
    const running = worker.call('getSession');
    await assert.rejects(worker.call('getSession'));
    assert.equal((await running).record.status, 200);
    assert.equal(f.requests.length, 1);
  } finally { worker.close(); }
});
test('four independent workers overlap and preserve all 80 request correlations with real SDK parsing', async () => {
  const f = fixture();
  const result = await runReaders(Buffer.from('unit certificate'), sessions, expected, ids, f.request);
  assert.equal(result.passed, true, JSON.stringify(result));
  assert.equal(result.records.length, 80); assert.equal(result.client_max_in_flight, 4);
  assert.equal(result.dispatch_attempts, 80); assert.equal(result.sdk_validated_responses, 80);
  assert.equal(result.unobserved_dispatch_attempts, 0);
  assert.equal(f.max(), 4); assert.equal(f.agents.size, 4);
  assert.equal(new Set(result.records.map((r) => r.correlation_id)).size, 80);
  for (let worker = 0; worker < 4; worker++) {
    const records = result.records.filter((r) => r.worker === worker);
    assert.deepEqual(records.map((r) => r.sequence), Array.from({ length: 20 }, (_, n) => n));
    assert.equal(records.filter((r) => r.operation === 'getSession').length, 2);
    for (const record of records) assert.equal(f.requests.find((r) => r.correlation === record.correlation_id).role, record.principal);
  }
  assert.equal(result.records.filter((r) => r.status === 404).length, 54);
  const joined = joinReadObservations(result.records, f.events.map((e) => JSON.stringify(e)).join('\n'));
  assert.equal(joined.length, 80); assert.deepEqual(joined[0].api.timing, timing());
  assert.ok(!JSON.stringify(joined).includes('Protected synthetic fixture'));
  assert.ok(!JSON.stringify(joined).includes(sessions.primary.cookie));
});
test('failed preflight sessions dispatch no resource reads and never attempt a login', async () => {
  const f = fixture((entry, { role }) => { if (role === 'denied') entry.data.principal.id = id(99); });
  const result = await runReaders(Buffer.from('unit certificate'), sessions, expected, ids, f.request);
  assert.equal(result.passed, false); assert.equal(result.failed_stage, 'sessions_before');
  assert.equal(f.requests.length, 4);
  assert.ok(f.requests.every((r) => r.url.pathname === '/api/v1/session'));
});
test('completed SDK-invalid responses retain safe correlations and never report zero requests', async () => {
  const f = fixture((entry) => { entry.data = {}; });
  const result = await runReaders(Buffer.from('unit certificate'), sessions, expected, ids, f.request);
  assert.equal(result.passed, false); assert.equal(result.failed_stage, 'sessions_before');
  assert.equal(f.requests.length, 4); assert.equal(result.dispatch_attempts, 4);
  assert.equal(result.records.length, 4); assert.equal(result.sdk_validated_responses, 0);
  assert.equal(result.unobserved_dispatch_attempts, 0);
  assert.equal(new Set(result.records.map((r) => r.correlation_id)).size, 4);
  assert.ok(result.records.every((r) => r.status === 200 && r.sample === 'session_before'));
});
test('unobserved transport attempts remain explicit rather than inferred as no HTTP effects', async () => {
  let attempts = 0;
  const result = await runReaders(Buffer.from('unit certificate'), sessions, expected, ids, () => {
    attempts++; throw new Error('synthetic transport secret must not be retained');
  });
  assert.equal(result.passed, false); assert.equal(result.failed_stage, 'sessions_before');
  assert.equal(attempts, 4); assert.equal(result.dispatch_attempts, 4);
  assert.equal(result.records.length, 0); assert.equal(result.sdk_validated_responses, 0);
  assert.equal(result.unobserved_dispatch_attempts, 4);
  assert.ok(!JSON.stringify(result).includes('secret'));
});
test('session change denial leak or unexpected cookie fails without a read retry', async () => {
  for (const mutate of [
    (entry, { number, isSession }) => { if (isSession && number > 4) entry.data.session_revision = 3; },
    (entry) => { if (entry.status === 404) entry.data.detail = 'protected'; },
    (entry) => { entry.headers['set-cookie'] = ['never-retain-fixture']; },
  ]) {
    const f = fixture(mutate), result = await runReaders(Buffer.from('unit certificate'), sessions, expected, ids, f.request);
    assert.equal(result.passed, false); assert.ok(f.requests.length <= 80);
    assert.equal(f.requests.filter((r) => r.options.method !== 'GET').length, 0);
  }
});
test('numeric telemetry cannot be absent negative fractional or replaced by unrelated logs', () => {
  const record = { operation: 'getOrganization', correlation_id: 'a'.repeat(32), status: 404, response_bytes: 50 };
  const event = { ...record, duration_ms: 1, sql_queries: 1, sql_writes: 1, audit_writes: 1,
    outbox_writes: 0, openfga_calls: 0, provider_calls: 0, timing: timing() };
  for (const value of [undefined, -1, 0.5, null, '1', Number.MAX_SAFE_INTEGER + 1]) {
    assert.throws(() => joinReadObservations([record], JSON.stringify({ ...event, timing: { ...timing(), sql_client_ns: value } })));
  }
  for (const raw of ['', JSON.stringify({ ...event, correlation_id: 'b'.repeat(32) }),
    JSON.stringify(event) + '\n' + JSON.stringify(event), JSON.stringify({ ...event, provider_calls: 1 })]) {
    assert.throws(() => joinReadObservations([record], raw));
  }
  const result = joinReadObservations([record], JSON.stringify({ ...event, secret: 'must not retain', timing: { ...timing(), arbitrary: 'not retained' } }));
  assert.deepEqual(result[0].api.timing, timing());
  assert.ok(!JSON.stringify(result).includes('retain'));
});
