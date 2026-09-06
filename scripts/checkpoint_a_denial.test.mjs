// SPDX-License-Identifier: Apache-2.0
// Unit/transport fixtures only; no live service, credential or SQL evidence.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { chmod, link, mkdtemp, readFile, rm, stat, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import test from 'node:test';
import { createPlatformClient, PLATFORM_MAX_RESPONSE_BYTES } from '../packages/api-client/src/client.ts';
import { ORIGIN } from './checkpoint_a_smoke.mjs';
import { denialCookie, denialResponse, denialTransport, proveAuthenticatedDenial, validateDenialBootstrap, validateDenialDestination, validateDenialInputs } from './checkpoint_a_denial.mjs';

const id = (number) => `01991c05-1a00-7000-8000-${number.toString(16).padStart(12, '0')}`;
const ids = { known_organization: id(1), unknown_organization: id(2), known_team: id(3), unknown_team: id(4), known_project: id(5), unknown_project: id(6) };
const expected = { instance_id: id(10), principal_id: id(11) };
const bootstrap = () => ({ schema_version: '1.0.0', development_only: true, security_domain: 'stead-local-development', instance_id: expected.instance_id, principal_id: id(12), session_id: id(13), unprivileged_principal_id: expected.principal_id, unprivileged_session_id: id(14) });
const session = () => ({ instance_id: expected.instance_id, principal: { type: 'user', id: expected.principal_id }, session_revision: 2, expires_at: '2030-01-01T00:00:00Z' });
const correlation = 'a'.repeat(32);
const cookie = `__Host-stead_session=${'a'.repeat(43)}`; // Deliberately synthetic unit fixture.
const cookieHeader = `${cookie}; Path=/; Expires=Tue, 01 Jan 2030 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict`;
const problem = (extra = {}) => ({ correlation_id: correlation, status: 404, title: 'The request could not be completed.', type: 'about:blank', ...extra });
const body = (value) => Buffer.from(`${JSON.stringify(value)}\n`);
const headers = (extra = {}) => ({ 'content-type': 'application/problem+json', 'cache-control': 'no-store', 'x-correlation-id': correlation, ...extra });
const init = (method = 'GET', extra = {}) => ({ method, headers: { accept: 'application/json' }, credentials: 'same-origin', redirect: 'error', ...extra });

test('explicit known/unknown inputs are canonical, closed and distinct', () => {
  assert.equal(validateDenialInputs(ids), ids);
  for (const invalid of [null, [], {}, { ...ids, extra: id(7) }, { ...ids, known_team: ids.known_organization }, { ...ids, unknown_team: 'unknown' }, { ...ids, known_organization: ids.known_organization.toUpperCase() }, { ...ids, known_team: 3 }]) assert.throws(() => validateDenialInputs(invalid));
});

test('bootstrap proof requires distinct unprivileged local identity and session metadata', () => {
  assert.deepEqual(validateDenialBootstrap(bootstrap()), expected);
  for (const invalid of [null, {}, { ...bootstrap(), development_only: false }, { ...bootstrap(), security_domain: 'production' }, { ...bootstrap(), schema_version: '2.0.0' }, { ...bootstrap(), instance_id: 'invalid' }, { ...bootstrap(), instance_id: [id(10)] }, { ...bootstrap(), session_id: undefined }, { ...bootstrap(), unprivileged_principal_id: id(12) }, { ...bootstrap(), unprivileged_session_id: id(13) }, { ...bootstrap(), unprivileged_session_id: undefined }]) assert.throws(() => validateDenialBootstrap(invalid));
  const identityKeys = ['instance_id', 'principal_id', 'session_id', 'unprivileged_principal_id', 'unprivileged_session_id'];
  for (const left of identityKeys) for (const right of identityKeys) {
    if (left !== right) assert.throws(() => validateDenialBootstrap({ ...bootstrap(), [left]: bootstrap()[right] }));
  }
});

test('transport permits only bounded denial journey routes and never logout or primary setup routes', () => {
  for (const route of ['/api/v1/session', `/api/v1/organizations/${id(1)}`, `/api/v1/teams/${id(3)}`, `/api/v1/projects/${id(5)}`]) assert.equal(validateDenialDestination(route, init()).url.origin, ORIGIN);
  assert.equal(validateDenialDestination(`/api/v1/organizations/${id(1)}/teams`, init('POST', { body: '{}' })).method, 'POST');
  for (const route of ['https://localhost:18443/api/v1/session', '//localhost:18443/api/v1/session', '/api/v1/%73ession', '/api/v1/session\\', '/api/v1/session?x=1', '/api/v1/session#x', '/api/v1/organizations', `/api/v1/organizations/${id(1)}/projects`, '/api/v1/stores']) assert.throws(() => validateDenialDestination(route, init()));
  for (const override of [{ method: 'DELETE' }, { method: 'PUT' }, { credentials: 'include' }, { redirect: 'follow' }, { body: '{}' }, { headers: { authorization: 'unit-fixture' } }, { headers: { cookie } }, { headers: { host: 'example.com' } }]) assert.throws(() => validateDenialDestination('/api/v1/session', init('GET', override)));
  assert.throws(() => validateDenialDestination('/api/v1/organizations', init('POST', { body: '{}' })));
  assert.throws(() => validateDenialDestination('/api/v1/session', init('POST', { body: 'é'.repeat((8 << 10) + 1) })));
});

test('denial compares only generic canonical bodies and rejects resource metadata', () => {
  const first = denialResponse(body(problem()), new Headers(headers()), 404);
  const second = denialResponse(body(problem({ correlation_id: 'b'.repeat(32) })), new Headers(headers({ 'x-correlation-id': 'b'.repeat(32) })), 404);
  assert.equal(first.normalized_body, second.normalized_body);
  assert.equal(first.etag_absent, true);
  for (const key of ['etag', 'stead-schema-version', 'last-modified', 'location', 'content-location', 'link', 'set-cookie']) assert.throws(() => denialResponse(body(problem()), new Headers(headers({ [key]: 'protected' })), 404));
  for (const value of [problem({ detail: 'exists' }), problem({ title: 'Denied existing object' }), problem({ status: 403 }), problem({ correlation_id: 'b'.repeat(32) })]) assert.throws(() => denialResponse(body(value), new Headers(headers()), 404));
  for (const raw of [Buffer.from(JSON.stringify(problem())), Buffer.from(`{"title":"protected",${JSON.stringify(problem()).slice(1)}\n`), Buffer.from(`${JSON.stringify(problem()).replace('about:blank', 'about:\\u0062lank')}\n`), Buffer.from([0xff])]) assert.throws(() => denialResponse(raw, new Headers(headers()), 404));
  assert.throws(() => denialResponse(body(problem()), new Headers(headers({ 'cache-control': 'public' })), 404));
  assert.deepEqual(denialResponse(body(problem()), new Headers(headers({ 'cache-control': 'no-store, no-store' })), 404), first);
  for (const value of ['no-store, public', 'no-store, max-age=60', 'no-store,', ',no-store', '\u00a0no-store', 'no-store\u00a0', 'no-store,'.repeat(20) + 'no-store']) assert.throws(() => denialResponse(body(problem()), new Headers(headers({ 'cache-control': value })), 404));
  assert.throws(() => denialResponse(body(problem()), new Headers(headers()), 401));
});

function requestFixture(makeResponse, requests = []) {
  return (url, options, callback) => {
    const request = new EventEmitter();
    request.destroy = () => {};
    request.end = (outgoing) => {
      requests.push({ url, options, body: outgoing });
      queueMicrotask(() => {
        const fixture = makeResponse(url, options, outgoing, requests.length);
        const response = Readable.from(fixture.chunks ?? [fixture.body]);
        response.statusCode = fixture.status ?? 404;
        response.headers = fixture.headers ?? headers();
        callback(response);
      });
    };
    return request;
  };
}

test('TLS request mechanics pin trust, hostname, loopback, origin and bounded timeout', async () => {
  const requests = [];
  const certificate = Buffer.from('unit-test-certificate-fixture-not-a-trust-root');
  const transport = denialTransport(certificate, { value: cookie }, undefined, requestFixture(() => ({ body: body(problem()) }), requests));
  try {
    assert.equal((await transport.fetchImplementation(`/api/v1/teams/${id(3)}`, init())).status, 404);
    assert.equal(requests.length, 1);
    const { url, options } = requests[0];
    assert.equal(url.origin, ORIGIN);
    assert.equal(options.ca, certificate);
    assert.equal(options.rejectUnauthorized, true);
    assert.equal(options.agent.options.rejectUnauthorized, true);
    assert.equal(options.servername, 'localhost');
    assert.equal(options.family, 4);
    assert.equal(options.maxHeaderSize, 16 << 10);
    assert.equal(options.headers.Origin, ORIGIN);
    assert.equal(options.headers.Cookie, cookie);
    assert.ok(options.signal instanceof AbortSignal);
    options.lookup('ignored-host', {}, (error, address, family) => { assert.equal(error, null); assert.equal(address, '127.0.0.1'); assert.equal(family, 4); });
    options.lookup('ignored-host', { all: true }, (error, values) => { assert.equal(error, null); assert.deepEqual(values, [{ address: '127.0.0.1', family: 4 }]); });
  } finally { transport.close(); }
});

test('transport rejects redirects, oversized bodies, resource leaks and unexpected cookie rotation', async () => {
  const fixtures = [
    { status: 302, headers: headers({ location: 'https://example.com/' }), body: Buffer.from('') },
    { chunks: [Buffer.alloc(PLATFORM_MAX_RESPONSE_BYTES), Buffer.from('x')] },
    { body: body(problem({ detail: 'protected' })) },
    { body: body(problem()), headers: headers({ etag: '"protected"' }) },
    { body: body(problem()), headers: headers({ 'set-cookie': [cookieHeader] }) },
    { body: body(problem()), headers: headers({ 'x-correlation-id': 'bad' }) },
  ];
  for (const fixture of fixtures) {
    const requests = [];
    const transport = denialTransport(Buffer.from('fixture'), { value: cookie }, undefined, requestFixture(() => fixture, requests));
    try {
      await assert.rejects(transport.fetchImplementation(`/api/v1/teams/${id(3)}`, init()), /boundary rejected/u);
      assert.equal(requests.length, 1); // No redirect or operation retry.
      assert.equal(transport.last(), undefined);
    } finally { transport.close(); }
  }
});

test('dedicated cookie is exclusive, private, retained and never falls back to primary credentials', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'stead-denial-unit-'));
  try {
    await chmod(directory, 0o700);
    // Only deliberately unrelated fixtures; no live credentials are read.
    await writeFile(path.join(directory, 'one-time-login-token'), 'primary-fixture-untouched', { mode: 0o600 });
    const filename = path.join(directory, 'unprivileged-session-cookie');
    const first = await denialCookie(directory);
    assert.equal(first.cookie.value, '');
    assert.equal((await stat(filename)).mode & 0o777, 0o600);
    await assert.rejects(denialCookie(directory)); // Reserved exchange cannot be retried.
    await first.acceptCookie(cookie);
    await assert.rejects(first.acceptCookie(cookie));
    await first.close();
    const second = await denialCookie(directory);
    assert.equal(second.cookie.value, cookie);
    assert.equal(second.acceptCookie, undefined);
    await second.close();
    assert.equal(await readFile(path.join(directory, 'one-time-login-token'), 'utf8'), 'primary-fixture-untouched');
    await chmod(filename, 0o644);
    await assert.rejects(denialCookie(directory));
    await chmod(filename, 0o600);
    await link(filename, path.join(directory, 'hardlink'));
    await assert.rejects(denialCookie(directory));
  } finally { await rm(directory, { recursive: true }); }
});

test('dedicated cookie rejects symlinks and preserves an interrupted exchange marker', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'stead-denial-unit-'));
  try {
    await chmod(directory, 0o700);
    const target = path.join(directory, 'fixture');
    await writeFile(target, JSON.stringify({ origin: ORIGIN, cookie }), { mode: 0o600 });
    await symlink(target, path.join(directory, 'unprivileged-session-cookie'));
    await assert.rejects(denialCookie(directory));
    assert.equal(await readFile(target, 'utf8'), JSON.stringify({ origin: ORIGIN, cookie }));
  } finally { await rm(directory, { recursive: true }); }
  const interrupted = await mkdtemp(path.join(os.tmpdir(), 'stead-denial-unit-'));
  try {
    const first = await denialCookie(interrupted);
    await first.close();
    await assert.rejects(denialCookie(interrupted));
    assert.deepEqual(JSON.parse(await readFile(path.join(interrupted, 'unprivileged-session-cookie'))), { login_in_flight: true });
  } finally { await rm(interrupted, { recursive: true }); }
});

test('cookie persists before malformed successful-login body is rejected by generated SDK', async () => {
  let retained;
  const transport = denialTransport(Buffer.from('fixture'), { value: '' }, async (value) => { retained = value; }, requestFixture(() => ({ status: 200, body: Buffer.from('not json'), headers: headers({ 'content-type': 'application/json', 'set-cookie': [cookieHeader] }) })));
  try {
    const client = createPlatformClient({ fetchImplementation: transport.fetchImplementation });
    await assert.rejects(client.request('createSession', { body: { token: 'b'.repeat(43) } }));
    assert.equal(retained, cookie);
  } finally { transport.close(); }
});

async function fixtureJourney(modify = (fixture) => fixture) {
  const requests = [];
  const transport = denialTransport(Buffer.from('fixture'), { value: cookie }, undefined, requestFixture((url, options, outgoing, count) => modify(url.pathname === '/api/v1/session'
    ? { status: 200, body: body(session()), headers: headers({ 'content-type': 'application/json' }) }
    : { body: body(problem({ correlation_id: count.toString(16).padStart(32, '0') })), headers: headers({ 'x-correlation-id': count.toString(16).padStart(32, '0') }) }, { url, options, outgoing, count }), requests));
  const client = createPlatformClient({ fetchImplementation: transport.fetchImplementation });
  try {
    return { checks: await proveAuthenticatedDenial((operation, options) => client.request(operation, options), transport.last, expected, ids, 'DN1234ABCD'), requests };
  } finally { transport.close(); }
}

test('generated-SDK fixture proves sign-in, three known/unknown pairs and one bounded child-Team denial', async () => {
  const { checks, requests } = await fixtureJourney();
  assert.equal(Object.keys(checks).length, 5);
  assert.ok(Object.values(checks).every((value) => value === true));
  assert.equal(requests.length, 8);
  assert.equal(requests.filter((entry) => entry.options.method === 'POST').length, 1);
  assert.equal(requests[0].url.pathname, '/api/v1/session');
  assert.equal(requests.at(-1).url.pathname, `/api/v1/organizations/${ids.known_organization}/teams`);
  assert.deepEqual(JSON.parse(requests.at(-1).body), { key: 'DN1234ABCD', name: 'Checkpoint A denied child Team attempt', parent_team_id: ids.known_team });
});

test('journey fails on wrong principal, expired authentication, resource leak or apparent mutation success', async () => {
  await assert.rejects(fixtureJourney((fixture, { count }) => count === 1 ? { ...fixture, body: body({ ...session(), principal: { type: 'user', id: id(12) } }) } : fixture));
  await assert.rejects(fixtureJourney((fixture, { count }) => count === 1 ? { ...fixture, body: body({ ...session(), expires_at: '2000-01-01T00:00:00Z' }) } : fixture));
  await assert.rejects(fixtureJourney((fixture, { count }) => count === 2 ? { ...fixture, body: body(problem({ correlation_id: '2'.padStart(32, '0'), detail: 'exists' })) } : fixture));
  await assert.rejects(fixtureJourney((fixture, { count }) => count === 8 ? { status: 201, body: body({ id: id(20) }), headers: headers({ 'content-type': 'application/json' }) } : fixture));
});

test('journey requires a completed one-time exchange revision, never raw bootstrap-token authentication', async () => {
  for (const revision of [0, 1, '2', null, undefined, 2.5, Number.MAX_SAFE_INTEGER + 1]) {
    await assert.rejects(fixtureJourney((fixture, { count }) => count === 1 ? { ...fixture, body: body({ ...session(), session_revision: revision }) } : fixture));
  }
});
