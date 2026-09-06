// SPDX-License-Identifier: Apache-2.0
// Explicit live TLS/generated-client journey, not a browser or release gate.
import { createHash, randomBytes } from 'node:crypto';
import { constants } from 'node:fs';
import { lstat, open, readFile, realpath, rename } from 'node:fs/promises';
import { Agent, request as httpsRequest } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createPlatformClient, PlatformApiError, PLATFORM_MAX_RESPONSE_BYTES } from '../packages/api-client/src/client.ts';

export const ORIGIN = 'https://localhost:18443';
const COOKIE_NAME = '__Host-stead_session';
const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const UUID_PATTERN = new RegExp(`^${UUID}$`, 'u');
const COOKIE = new RegExp(`^${COOKIE_NAME}=[A-Za-z0-9_-]{43}$`, 'u');
const failure = () => new Error('Checkpoint A proof boundary rejected');

export async function privateDirectory(directory) {
  if (!path.isAbsolute(directory) || path.resolve(directory) !== directory || await realpath(directory) !== directory) throw failure();
  const info = await lstat(directory);
  if (!info.isDirectory() || info.uid !== process.getuid() || (info.mode & 0o777) !== 0o700) throw failure();
}

export async function readPrivate(filename, maximum = 1 << 20) {
  await privateDirectory(path.dirname(filename));
  const file = await open(filename, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const info = await file.stat({ bigint: true });
    if (!Number.isSafeInteger(maximum) || maximum < 0 || !info.isFile() || info.uid !== BigInt(process.getuid()) || info.nlink !== 1n || (info.mode & 0o777n) !== 0o600n || info.size > BigInt(maximum)) throw failure();
    const data = Buffer.alloc(Number(info.size) + 1);
    let total = 0;
    while (total < data.length) {
      const { bytesRead } = await file.read(data, total, data.length - total, total);
      if (!bytesRead) break;
      total += bytesRead;
    }
    const final = await file.stat({ bigint: true });
    if (BigInt(total) !== info.size || final.size !== info.size || final.mtimeNs !== info.mtimeNs || final.ctimeNs !== info.ctimeNs) throw failure();
    return data.subarray(0, total);
  } finally { await file.close(); }
}

async function exclusiveFile(filename, data) {
  await privateDirectory(path.dirname(filename));
  const file = await open(filename, 'wx', 0o600);
  try { await file.writeFile(data); await file.sync(); } finally { await file.close(); }
}

async function saveProgress(filename, value) {
  await readPrivate(filename); // A journal is replaced only after validating its existing private target.
  const temporary = `${filename}.${randomBytes(8).toString('hex')}.tmp`;
  await exclusiveFile(temporary, JSON.stringify(value));
  await rename(temporary, filename);
  const directory = await open(path.dirname(filename), 'r');
  try { await directory.sync(); } finally { await directory.close(); }
}

export function validateDestination(input, init) {
  if (typeof input !== 'string' || !input.startsWith('/api/v1/') || input.includes('%') || input.includes('\\')) throw failure();
  const url = new URL(input, ORIGIN);
  if (url.origin !== ORIGIN || url.username || url.password || url.hash || `${url.pathname}${url.search}` !== input || init.credentials !== 'same-origin' || init.redirect !== 'error') throw failure();
  const method = init.method;
  const allowed = method === 'GET'
    ? new RegExp(`^/api/v1/(?:session|organizations(?:/${UUID}(?:/(?:teams|projects))?)?|teams/${UUID}|projects/${UUID})$`, 'u')
    : method === 'POST' ? new RegExp(`^/api/v1/(?:session|organizations(?:/${UUID}/(?:teams|projects))?)$`, 'u') : null;
  if (!allowed?.test(url.pathname) || (init.body !== undefined && (method !== 'POST' || typeof init.body !== 'string' || Buffer.byteLength(init.body) > (16 << 10)))) throw failure();
  const list = method === 'GET' && new RegExp(`^/api/v1/organizations(?:/${UUID}/(?:teams|projects))?$`, 'u').test(url.pathname);
  for (const [key, value] of url.searchParams) {
    if (!list || url.searchParams.getAll(key).length !== 1 || !['page_size', 'after'].includes(key) || (key === 'page_size' && !/^(?:[1-9]|1[0-9]|20)$/u.test(value)) || (key === 'after' && !UUID_PATTERN.test(value))) throw failure();
  }
  const headers = new Headers(init.headers);
  for (const key of headers.keys()) if (!['accept', 'content-type', 'idempotency-key', 'if-match'].includes(key)) throw failure();
  return { url, method, headers };
}

export function sessionCookie(headers) {
  if (!Array.isArray(headers) || headers.length !== 1) throw failure();
  const parts = headers[0].split(';').map((entry) => entry.trim());
  if (!COOKIE.test(parts[0])) throw failure();
  const attributes = new Map();
  for (const part of parts.slice(1)) {
    const index = part.indexOf('=');
    const key = (index < 0 ? part : part.slice(0, index)).toLowerCase();
    if (attributes.has(key)) throw failure();
    attributes.set(key, index < 0 ? '' : part.slice(index + 1));
  }
  if (attributes.get('path') !== '/' || attributes.get('secure') !== '' || attributes.get('httponly') !== '' || attributes.get('samesite')?.toLowerCase() !== 'strict' || !Number.isFinite(Date.parse(attributes.get('expires'))) || Date.parse(attributes.get('expires')) <= Date.now() || attributes.size !== 5) throw failure();
  return parts[0];
}

export function genericProblem(raw, status) {
  const value = JSON.parse(raw.toString('utf8'));
  if (JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['correlation_id', 'status', 'title', 'type']) || value.status !== status || value.type !== 'about:blank' || value.title !== 'The request could not be completed.' || !/^[0-9a-f]{32}$/u.test(value.correlation_id)) throw failure();
  return { type: value.type, title: value.title, status: value.status };
}

function tlsTransport(certificate, cookie, acceptCookie) {
  const agent = new Agent({ keepAlive: true, maxSockets: 1, ca: certificate, rejectUnauthorized: true });
  let last;
  const fetchImplementation = async (input, init) => {
    last = undefined;
    const { url, method, headers } = validateDestination(input, init);
    const outgoing = Object.fromEntries(headers);
    outgoing.Origin = ORIGIN;
    if (cookie.value) {
      if (!COOKIE.test(cookie.value)) throw failure();
      outgoing.Cookie = cookie.value;
    }
    return new Promise((resolve, reject) => {
      const request = httpsRequest(url, {
        method, headers: outgoing, agent, ca: certificate, rejectUnauthorized: true,
        servername: 'localhost', family: 4,
        lookup: (_hostname, options, callback) => options?.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4),
        signal: init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
      }, (response) => {
        void (async () => {
          try {
            if (response.statusCode >= 300 && response.statusCode < 400) throw failure();
            if (response.headers['set-cookie']) {
              if (url.pathname !== '/api/v1/session' || method !== 'POST' || response.statusCode !== 200 || !acceptCookie) throw failure();
              const value = sessionCookie(response.headers['set-cookie']);
              await acceptCookie(value); // Preserve an already-consumed credential even if later response validation fails.
              cookie.value = value;
            }
            const chunks = [];
            let length = 0;
            for await (const chunk of response) {
              length += chunk.length;
              if (length > PLATFORM_MAX_RESPONSE_BYTES) throw failure();
              chunks.push(chunk);
            }
            const body = Buffer.concat(chunks, length);
            const responseHeaders = new Headers();
            for (const [key, value] of Object.entries(response.headers)) if (key !== 'set-cookie' && value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
            const correlation = responseHeaders.get('x-correlation-id');
            if (!/^[0-9a-f]{32}$/u.test(correlation)) throw failure();
            if (response.statusCode >= 400 && JSON.parse(body.toString('utf8')).correlation_id !== correlation) throw failure();
            last = { correlation_id: correlation, status: response.statusCode, bytes: length, problem: response.statusCode >= 400 ? genericProblem(body, response.statusCode) : undefined };
            resolve(new Response(body, { status: response.statusCode, headers: responseHeaders }));
          } catch { response.destroy(); request.destroy(); reject(failure()); }
        })();
      });
      request.on('error', () => reject(failure()));
      request.end(init.body);
    });
  };
  return { fetchImplementation, last: () => last, close: () => agent.destroy() };
}

function uuid7() {
  const value = randomBytes(16);
  value.writeUIntBE(Date.now(), 0, 6);
  value[6] = value[6] & 15 | 0x70;
  value[8] = value[8] & 63 | 0x80;
  const hex = value.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export function newProgress() {
  const run = randomBytes(8).toString('hex');
  return { schema_version: 1, run, instance_id: '', ids: {}, key_suffix: run.slice(0, 6).toUpperCase() };
}

export function validateProgress(value) {
  if (!value || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify(['ids', 'instance_id', 'key_suffix', 'run', 'schema_version']) || value.schema_version !== 1 || !/^[0-9a-f]{16}$/u.test(value.run) || value.key_suffix !== value.run.slice(0, 6).toUpperCase() || (value.instance_id !== '' && !UUID_PATTERN.test(value.instance_id)) || !value.ids || typeof value.ids !== 'object' || Array.isArray(value.ids)) throw failure();
  for (const [key, id] of Object.entries(value.ids)) if (!['organization', 'parent', 'child', 'project', 'other_organization'].includes(key) || !UUID_PATTERN.test(id)) throw failure();
  return value;
}

export function joinObservations(records, raw) {
  const wanted = new Set(records.map((record) => record.correlation_id));
  if (!records.length || wanted.size !== records.length || records.some((record) => !/^[0-9a-f]{32}$/u.test(record.correlation_id))) throw failure();
  const matched = new Map();
  for (const line of raw.split('\n')) {
    let value;
    try { value = JSON.parse(line); } catch { continue; }
    if (!value || !wanted.has(value.correlation_id)) continue;
    if (matched.has(value.correlation_id)) throw failure();
    const result = {};
    for (const key of ['sql_queries', 'sql_writes', 'audit_writes', 'outbox_writes', 'openfga_calls', 'provider_calls', 'response_bytes', 'status']) {
      if (!Number.isSafeInteger(value[key]) || value[key] < 0) throw failure();
      result[key] = value[key];
    }
    if (typeof value.duration_ms !== 'number' || !Number.isFinite(value.duration_ms) || value.duration_ms < 0) throw failure();
    result.duration_ms = value.duration_ms;
    matched.set(value.correlation_id, result);
  }
  return records.map((record) => {
    const api = matched.get(record.correlation_id);
    if (!api || api.status !== record.status || api.response_bytes !== record.response_bytes || api.provider_calls !== 0) throw failure();
    return { ...record, api };
  });
}

export async function runCheckpointA(state) {
  await privateDirectory(state);
  const certificate = await readPrivate(path.join(state, 'tls/localhost.crt'), 64 << 10);
  const journal = path.join(state, 'checkpoint-a-progress.json');
  let progress;
  try { progress = validateProgress(JSON.parse(await readPrivate(journal))); }
  catch (error) {
    if (error.code !== 'ENOENT') throw error;
    progress = newProgress();
    await exclusiveFile(journal, JSON.stringify(progress));
  }
  const cookieFile = path.join(state, 'checkpoint-a-cookie.json');
  const cookie = { value: '' };
  let reserved;
  try {
    const value = JSON.parse(await readPrivate(cookieFile, 4096));
    if (value.origin !== ORIGIN || !COOKIE.test(value.cookie) || Object.keys(value).length !== 2) throw failure();
    cookie.value = value.cookie;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error; // An interrupted exchange never silently consumes the token again.
    reserved = await open(cookieFile, 'wx+', 0o600);
    await reserved.writeFile(JSON.stringify({ login_in_flight: true }));
    await reserved.sync();
  }
  const transport = tlsTransport(certificate, cookie, async (value) => {
    if (!reserved) throw failure();
    const bytes = Buffer.from(JSON.stringify({ origin: ORIGIN, cookie: value }));
    await reserved.truncate(0);
    let written = 0;
    while (written < bytes.length) {
      const { bytesWritten } = await reserved.write(bytes, written, bytes.length - written, written);
      if (!bytesWritten) throw failure();
      written += bytesWritten;
    }
    await reserved.sync();
  });
  const anonymous = tlsTransport(certificate, { value: '' });
  const observations = [];
  const clients = [transport, anonymous].map((wire) => ({ wire, client: createPlatformClient({ fetchImplementation: wire.fetchImplementation, observeNetwork: (value) => observations.push(value) }) }));
  const records = [];
  const call = async (operation, options = {}, who = 0) => {
    const count = observations.length;
    try { return await clients[who].client.request(operation, options); }
    finally {
      if (observations.length === count + 1) {
        const measured = observations.at(-1), wire = clients[who].wire.last();
        records.push({ operation, duration_ms: measured.durationMs, response_bytes: measured.responseBytes, status: measured.status, correlation_id: wire.correlation_id });
      }
    }
  };
  const digest = async (relative) => createHash('sha256').update(await readFile(new URL(relative, import.meta.url))).digest('hex');
  const report = { scope: 'live-tls-generated-client-checkpoint-a-not-browser', authenticated_denied_principal_covered: false, browser_covered: false, node_version: process.version, source: { smoke_sha256: await digest('./checkpoint_a_smoke.mjs'), sdk_sha256: await digest('../packages/api-client/src/client.ts'), generated_contract_sha256: await digest('../packages/api-client/src/generated/platform-v1.ts') }, checks: {}, records };
  const proofFile = `checkpoint-a-proof-${Date.now()}-${randomBytes(4).toString('hex')}.json`;
  let succeeded = false;
  try {
    if (!cookie.value) {
      const token = (await readPrivate(path.join(state, 'one-time-login-token'), 128)).toString('utf8');
      if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) throw failure();
      await call('createSession', { body: { token } });
    }
    const session = (await call('getSession')).data;
    if (progress.instance_id && progress.instance_id !== session.instance_id) throw failure();
    progress.instance_id = session.instance_id;
    await saveProgress(journal, progress);
    const create = async (slot, operation, body, resourcePath = undefined) => {
      if (progress.ids[slot]) return progress.ids[slot];
      const response = await call(operation, { body, ...(resourcePath ? { path: resourcePath } : {}), idempotencyKey: `checkpoint-a:${progress.run}:${slot}` });
      progress.ids[slot] = response.data.id;
      await saveProgress(journal, progress);
      return response.data.id;
    };
    const organization = await create('organization', 'createOrganization', { key: `CA${progress.key_suffix}`, name: 'Checkpoint A Workspace' });
    const scope = { organization_id: organization };
    const parent = await create('parent', 'createTeam', { key: `PA${progress.key_suffix}`, name: 'Checkpoint A Parent' }, scope);
    const child = await create('child', 'createTeam', { key: `CH${progress.key_suffix}`, name: 'Checkpoint A Child', parent_team_id: parent }, scope);
    const project = await create('project', 'createProject', { key: `PR${progress.key_suffix}`, title: 'Checkpoint A General Project', purpose: 'Real authorized and persisted generated-client proof', owning_team_id: parent }, scope);
    const other = await create('other_organization', 'createOrganization', { key: `SC${progress.key_suffix}`, name: 'Checkpoint A Scope Boundary' });
    const orgRead = (await call('getOrganization', { path: { organization_id: organization } })).data;
    const parentRead = (await call('getTeam', { path: { team_id: parent } })).data;
    const childRead = (await call('getTeam', { path: { team_id: child } })).data;
    const projectRead = (await call('getProject', { path: { project_id: project } })).data;
    if (orgRead.id !== organization || parentRead.organization_id !== organization || childRead.parent_team_id !== parent || childRead.hierarchy_depth !== parentRead.hierarchy_depth + 1 || projectRead.owning_team_id !== parent || projectRead.organization_id !== organization) throw failure();
    if (JSON.stringify(projectRead.authorized_capabilities) !== JSON.stringify(['work', 'docs']) || JSON.stringify(projectRead.visible_areas) !== JSON.stringify(['overview', 'work', 'docs'])) throw failure();
    report.checks.canonical_readback = true;
    report.checks.general_project_code_delivery_absent = true;
    const collect = async (operation, resourcePath) => {
      const ids = new Set();
      let after;
      for (let page = 0; page < 100; page++) {
        const { data } = await call(operation, { ...(resourcePath ? { path: resourcePath } : {}), query: { page_size: 1, ...(after ? { after } : {}) } });
        for (const item of data.items) { if (ids.has(item.id)) throw failure(); ids.add(item.id); }
        if (!data.next_after) return ids;
        if (data.items.length !== 1 || data.next_after !== data.items[0].id || data.next_after === after) throw failure();
        after = data.next_after;
      }
      throw failure(); // Bounded proof never claims a truncated collection is complete.
    };
    const orgIDs = await collect('listOrganizations');
    const teamIDs = await collect('listTeams', scope);
    const projectIDs = await collect('listProjects', scope);
    if (!orgIDs.has(organization) || !orgIDs.has(other) || !teamIDs.has(parent) || !teamIDs.has(child) || !projectIDs.has(project)) throw failure();
    report.checks.authorized_cursor_pages = true;
    const denied = async (operation, options, status, who = 0) => {
      try { await call(operation, options, who); } catch (error) {
        if (error instanceof PlatformApiError && error.status === status) return clients[who].wire.last().problem;
        throw error;
      }
      throw failure();
    };
    const deniedKnown = await denied('listTeams', { path: { organization_id: other }, query: { after: parent, page_size: 1 } }, 404);
    const deniedUnknown = await denied('listTeams', { path: { organization_id: other }, query: { after: uuid7(), page_size: 1 } }, 404);
    if (JSON.stringify(deniedKnown) !== JSON.stringify(deniedUnknown)) throw failure();
    report.checks.cross_organization_cursor_denial_equals_unknown = true;
    const noSessionKnown = await denied('getOrganization', { path: { organization_id: organization } }, 401, 1);
    const noSessionUnknown = await denied('getOrganization', { path: { organization_id: uuid7() } }, 401, 1);
    if (JSON.stringify(noSessionKnown) !== JSON.stringify(noSessionUnknown)) throw failure();
    report.checks.unauthenticated_known_equals_unknown = true;
    // Only wait for instrumentation flushing, after all protected responses have
    // completed. This never refreshes an authorization or retries a mutation.
    for (let attempt = 0; ; attempt++) {
      try {
        const log = (await readPrivate(path.join(state, 'stead-api.log'), 8 << 20)).toString('utf8');
        report.records = joinObservations(records, log);
        break;
      } catch (error) {
        if (attempt === 4) throw error;
        await delay(25);
      }
    }
    report.checks.actual_api_observations_joined = true;
    succeeded = true;
  } finally {
    transport.close(); anonymous.close();
    if (reserved) await reserved.close();
    report.passed = succeeded;
    await exclusiveFile(path.join(state, proofFile), JSON.stringify(report));
  }
  return { scope: report.scope, passed: true, proof_file: proofFile, checks: report.checks, requests: report.records.length, authenticated_denied_principal_covered: false, browser_covered: false, preserved_resources: true, preserved_session: true };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 3 || args[0] !== '--live' || args[1] !== '--state') {
    console.error('Usage: checkpoint_a_smoke.mjs --live --state /absolute/private/stead-state');
    process.exitCode = 1;
  } else {
    try { console.log(JSON.stringify(await runCheckpointA(args[2]))); }
    catch { console.error('Checkpoint A proof failed; private evidence, objects and session are preserved. No login retry or logout was attempted.'); process.exitCode = 1; }
  }
}
