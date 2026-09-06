// SPDX-License-Identifier: Apache-2.0
// Synthetic callbacks/streams only; no sockets, service or credential files.
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { Readable } from 'node:stream';
import test from 'node:test';
import { discoverResources, discoveryTransport, runDiscovery } from './checkpoint_a_discovery.mjs';

const id = (n) => '01991c05-0000-7000-8000-' + String(n).padStart(12, '0');
const expiresAt = Math.floor(Date.now() / 1000) + 3600;
const expected = { primary: { instance_id: id(10), principal_id: id(11) }, denied: { instance_id: id(10), principal_id: id(12) } };
const sessions = { primary: { expiresAt }, denied: { expiresAt } };
function fixture(change = () => {}) {
  const common = { instance_id: id(10), organization_id: id(1) };
  const responses = {
    listOrganizations: { items: [{ ...common, kind: 'organization', id: id(1), key: 'BJA7ORG' }] },
    listTeams: { items: [{ ...common, kind: 'team', id: id(2), key: 'BJA7PAR' },
      { ...common, kind: 'team', id: id(3), key: 'BJA7CHD', parent_team_id: id(2) }] },
    listProjects: { items: [{ ...common, kind: 'project', id: id(4), owning_team_id: id(3),
      title: 'Browser Journey A7 General Project', purpose: 'Synthetic browser-only Checkpoint A persistence verification.',
      authorized_capabilities: ['work', 'docs'], visible_areas: ['overview', 'work', 'docs'] }] },
  };
  change(responses); const calls = [];
  return { calls, call: async (role, operation, options) => {
    calls.push({ role, operation, options });
    if (operation === 'getSession') return { data: { principal: { type: 'user', id: expected[role].principal_id },
      instance_id: id(10), session_revision: 2, expires_at: new Date(expiresAt * 1000).toISOString() } };
    assert.equal(role, 'primary'); assert.deepEqual(options.query, { page_size: 20 });
    if (operation !== 'listOrganizations') assert.equal(options.path.organization_id, id(1));
    return { data: responses[operation] };
  } };
}
test('inert entrypoint; five fixed reads select child-owned general resources only', async () => {
  assert.equal(typeof runDiscovery, 'function'); const f = fixture();
  const ids = await discoverResources(f.call, expected, sessions);
  assert.equal(ids.known_organization, id(1)); assert.equal(ids.known_team, id(3)); assert.equal(ids.known_project, id(4));
  assert.equal(new Set(Object.values(ids)).size, 6);
  assert.deepEqual(f.calls.map((c) => c.operation), ['getSession', 'getSession', 'listOrganizations', 'listTeams', 'listProjects']);
  assert.deepEqual(Object.keys(ids).sort(), ['known_organization', 'known_project', 'known_team', 'unknown_organization', 'unknown_project', 'unknown_team']);
});
test('missing/ambiguous pages and incorrect hierarchy or software scope fail without retry', async () => {
  for (const change of [
    (r) => { r.listOrganizations.items = []; },
    (r) => { r.listOrganizations.items.push(r.listOrganizations.items[0]); },
    (r) => { r.listTeams.next_after = id(9); },
    (r) => { r.listTeams.items[1].parent_team_id = id(9); },
    (r) => { r.listProjects.items[0].owning_team_id = id(2); },
    (r) => { r.listProjects.items[0].authorized_capabilities.push('scm'); },
    (r) => { r.listProjects.items[0].visible_areas.push('code'); },
  ]) {
    const f = fixture(change); await assert.rejects(discoverResources(f.call, expected, sessions));
    assert.ok(f.calls.length <= 5);
  }
  const f = fixture();
  await assert.rejects(discoverResources(f.call, { ...expected, primary: expected.denied }, sessions));
  assert.equal(f.calls.length, 1);
});
function transportFixture(status = 200, extraHeaders = {}) {
  const calls = [], records = [];
  const wire = discoveryTransport(Buffer.from('synthetic certificate'), '__Host-stead_session=' + 'A'.repeat(43), records, (url, options, callback) => {
    const req = new EventEmitter(); req.destroy = () => {};
    req.end = (body) => {
      calls.push({ url, options, body });
      queueMicrotask(() => {
        const res = Readable.from([Buffer.from('{}')]); res.statusCode = status;
        res.headers = { 'x-correlation-id': 'a'.repeat(32), 'content-type': 'application/json', ...extraHeaders };
        callback(res);
      });
    };
    return req;
  });
  return { wire, calls, records };
}
const init = { method: 'GET', credentials: 'same-origin', redirect: 'error', headers: { accept: 'application/json' } };
test('fixed transport enforces TLS/hostname/loopback GET; closed wire failures stay visible', async () => {
  const f = transportFixture();
  try {
    await f.wire.fetchImplementation('/api/v1/organizations?page_size=20', init);
    const { url, options, body } = f.calls[0];
    assert.equal(url.origin, 'https://localhost:18443'); assert.equal(body, undefined);
    assert.equal(options.rejectUnauthorized, true); assert.equal(options.servername, 'localhost');
    options.lookup('localhost', {}, (_, address) => assert.equal(address, '127.0.0.1'));
    assert.equal(options.agent.options.maxSockets, 1); assert.equal(f.wire.dispatches(), 1);
    assert.deepEqual(f.records, [{ correlation_id: 'a'.repeat(32), status: 200 }]);
    for (const [input, config] of [['https://example.com/', init], ['/api/v1/session', { ...init, method: 'POST' }],
      ['/api/v1/organizations?page_size=20&after=' + id(9), init], ['/api/v1/teams/' + id(3), init]]) {
      await assert.rejects(f.wire.fetchImplementation(input, config));
    }
    assert.equal(f.wire.dispatches(), 1);
  } finally { f.wire.close(); }
  for (const [status, headers] of [[302, { location: 'https://example.com/' }], [200, { 'set-cookie': 'secret fixture' }]]) {
    const f = transportFixture(status, headers);
    try { await assert.rejects(f.wire.fetchImplementation('/api/v1/session', init)); assert.equal(f.wire.dispatches(), 1);
      assert.deepEqual(f.records, [{ correlation_id: 'a'.repeat(32), status }]); }
    finally { f.wire.close(); }
  }
});
