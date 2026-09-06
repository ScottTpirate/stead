// SPDX-License-Identifier: Apache-2.0
// Pure boundary/unit checks only: these do not demonstrate a live product journey.
import assert from 'node:assert/strict';
import { chmod, link, mkdir, mkdtemp, rm, symlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { genericProblem, joinObservations, newProgress, ORIGIN, privateDirectory, readPrivate, sessionCookie, validateDestination, validateProgress } from './checkpoint_a_smoke.mjs';

const id = '01991c05-1a00-7000-8000-000000000001';
const request = (method = 'GET', extra = {}) => ({ method, credentials: 'same-origin', redirect: 'error', headers: { accept: 'application/json' }, ...extra });
const correlation = 'a'.repeat(32);

test('transport accepts only bounded same-origin generated API operations', () => {
  for (const target of ['/api/v1/session', '/api/v1/organizations', `/api/v1/organizations/${id}`, `/api/v1/organizations/${id}/teams?page_size=20&after=${id}`, `/api/v1/projects/${id}`]) {
    assert.equal(validateDestination(target, request()).url.origin, ORIGIN);
  }
  assert.equal(validateDestination('/api/v1/organizations', request('POST', { body: 'x'.repeat(16 << 10) })).method, 'POST');
  assert.throws(() => validateDestination('/api/v1/organizations', request('POST', { body: 'x'.repeat((16 << 10) + 1) })));
  assert.throws(() => validateDestination('/api/v1/organizations', request('POST', { body: 'é'.repeat((8 << 10) + 1) })));
  for (const target of ['https://localhost:18443/api/v1/session', '//localhost:18443/api/v1/session', 'https://example.com/', '/api/v1/../health/ready', '/api/v1/%73ession', '/api/v1/session#secret', '/api/v1/session\\', '/api/v1/stores', '/api/v1/organizations?provider=gitea', '/api/v1/organizations?page_size=0', '/api/v1/organizations?page_size=21', '/api/v1/organizations?page_size=01', '/api/v1/organizations?page_size=1&page_size=1', '/api/v1/organizations?after=unknown', `/api/v1/projects/${id}?page_size=1`]) {
    assert.throws(() => validateDestination(target, request()), target);
  }
});

test('transport cannot logout, inject credentials, redirect, or send GET bodies', () => {
  for (const extra of [{ method: 'DELETE' }, { method: 'PUT' }, { credentials: 'include' }, { redirect: 'follow' }, { headers: { authorization: 'not-a-real-secret' } }, { headers: { cookie: 'not-a-real-secret' } }, { headers: { host: 'example.com' } }, { body: '{}' }]) {
    assert.throws(() => validateDestination('/api/v1/session', request('GET', extra)));
  }
  for (const headers of [{ 'content-type': 'application/json', 'idempotency-key': 'bounded-unit-key' }, { 'if-match': '"1"' }]) {
    assert.equal(validateDestination('/api/v1/organizations', request('POST', { headers, body: '{}' })).url.origin, ORIGIN);
  }
});

test('cookie is one secure host-only strict session with bounded canonical value', () => {
  const cookie = `__Host-stead_session=${'a'.repeat(43)}`;
  const suffix = '; Path=/; Expires=Tue, 01 Jan 2030 00:00:00 GMT; HttpOnly; Secure; SameSite=Strict';
  assert.equal(sessionCookie([cookie + suffix]), cookie);
  for (const invalid of [[], [cookie + suffix, cookie + suffix], [cookie + suffix + '; Domain=localhost'], [cookie + suffix + '; Secure'], [cookie + suffix.replace('Secure; ', '')], [cookie + suffix.replace('HttpOnly; ', '')], [cookie + suffix.replace('Strict', 'Lax')], [cookie + suffix.replace('Path=/', 'Path=/api')], [cookie + suffix.replace('2030', '2000')], [cookie + suffix.replace(/; Expires=[^;]+/u, '')], [cookie + 'x' + suffix]]) {
    assert.throws(() => sessionCookie(invalid));
  }
});

test('private state and inputs reject symlinks, hard links, loose modes and oversized data', async () => {
  const directory = await mkdtemp(path.join(os.tmpdir(), 'stead-smoke-unit-'));
  try {
    await chmod(directory, 0o700);
    await privateDirectory(directory);
    const file = path.join(directory, 'secret');
    await writeFile(file, 'unit-fixture-not-a-credential', { mode: 0o600 });
    assert.equal((await readPrivate(file)).toString(), 'unit-fixture-not-a-credential');
    await assert.rejects(readPrivate(file, 1));
    await assert.rejects(readPrivate(file, -1));
    await chmod(file, 0o644);
    await assert.rejects(readPrivate(file));
    await chmod(file, 0o600);
    const alias = path.join(directory, 'alias');
    await symlink(file, alias);
    await assert.rejects(readPrivate(alias));
    await link(file, path.join(directory, 'hard'));
    await assert.rejects(readPrivate(file));
    const nested = path.join(directory, 'nested');
    await mkdir(nested, { mode: 0o700 });
    await symlink(nested, path.join(directory, 'nested-alias'));
    await assert.rejects(privateDirectory(path.join(directory, 'nested-alias')));
    await chmod(directory, 0o755);
    await assert.rejects(privateDirectory(directory));
  } finally { await rm(directory, { recursive: true }); }
});

test('progress is closed, bounded and binds canonical identifiers', () => {
  const value = newProgress();
  assert.equal(validateProgress(value), value);
  assert.equal(validateProgress({ ...value, instance_id: id, ids: { organization: id } }).instance_id, id);
  for (const invalid of [null, {}, { ...value, schema_version: 2 }, { ...value, extra: true }, { ...value, run: '../bad' }, { ...value, key_suffix: 'WRONG' }, { ...value, instance_id: 'unknown' }, { ...value, ids: { organization: 'unknown' } }, { ...value, ids: { cookie: id } }, { ...value, ids: [] }]) {
    assert.throws(() => validateProgress(invalid));
  }
});

test('denial comparison permits only generic problem fields and discards correlation identity', () => {
  const value = { type: 'about:blank', title: 'The request could not be completed.', status: 404, correlation_id: correlation };
  assert.deepEqual(genericProblem(Buffer.from(JSON.stringify(value)), 404), { type: 'about:blank', title: value.title, status: 404 });
  assert.deepEqual(genericProblem(Buffer.from(JSON.stringify({ ...value, correlation_id: 'b'.repeat(32) })), 404), genericProblem(Buffer.from(JSON.stringify(value)), 404));
  for (const invalid of [{ ...value, detail: 'exists' }, { ...value, title: 'Resource exists but denied' }, { ...value, status: 403 }, { ...value, correlation_id: 'bad' }, null, []]) {
    assert.throws(() => genericProblem(Buffer.from(JSON.stringify(invalid)), 404));
  }
});

const record = () => ({ operation: 'getOrganization', correlation_id: correlation, status: 200, duration_ms: 20, response_bytes: 100 });
const observation = () => ({ correlation_id: correlation, status: 200, duration_ms: 10, response_bytes: 100, sql_queries: 17, sql_writes: 1, audit_writes: 1, outbox_writes: 0, openfga_calls: 1, provider_calls: 0 });

test('evidence joins exact actual request counters without exposing unrelated logs', () => {
  const raw = `non-JSON startup line\nnull\n${JSON.stringify({ unrelated: 'not returned' })}\n${JSON.stringify(observation())}\n`;
  const joined = joinObservations([record()], raw);
  assert.equal(joined[0].api.sql_queries, 17);
  assert.equal(joined[0].api.openfga_calls, 1);
  assert.equal(joined[0].api.provider_calls, 0);
  assert.ok(!JSON.stringify(joined).includes('not returned'));
});

test('missing, duplicate, mismatched and invented observation counters fail closed', () => {
  const raw = JSON.stringify(observation());
  for (const invalid of ['', `${raw}\n${raw}`, JSON.stringify({ ...observation(), status: 201 }), JSON.stringify({ ...observation(), response_bytes: 101 }), JSON.stringify({ ...observation(), provider_calls: 1 }), JSON.stringify({ ...observation(), sql_queries: -1 }), JSON.stringify({ ...observation(), sql_queries: 0.5 }), JSON.stringify({ ...observation(), duration_ms: '10' })]) {
    assert.throws(() => joinObservations([record()], invalid));
  }
  assert.throws(() => joinObservations([], raw));
  assert.throws(() => joinObservations([record(), record()], raw));
  assert.throws(() => joinObservations([{ ...record(), correlation_id: undefined }], raw));
});
