// SPDX-License-Identifier: Apache-2.0
// Explicit live TLS/generated-client denial proof; not browser or SQL evidence.
import { createHash, randomBytes } from 'node:crypto';
import { open, readFile } from 'node:fs/promises';
import { Agent, request as httpsRequest } from 'node:https';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { createPlatformClient, PlatformApiError, PLATFORM_MAX_RESPONSE_BYTES } from '../packages/api-client/src/client.ts';
import { genericProblem, joinObservations, ORIGIN, privateDirectory, readPrivate, sessionCookie } from './checkpoint_a_smoke.mjs';

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}';
const ID = new RegExp(`^${UUID}$`, 'u');
const COOKIE = /^__Host-stead_session=[A-Za-z0-9_-]{43}$/u;
const ID_KEYS = ['known_organization', 'unknown_organization', 'known_team', 'unknown_team', 'known_project', 'unknown_project'];
const failure = () => new Error('Checkpoint A denial proof boundary rejected');

export function validateDenialInputs(value) {
  if (!value || Array.isArray(value) || JSON.stringify(Object.keys(value).sort()) !== JSON.stringify([...ID_KEYS].sort()) || Object.values(value).some((id) => typeof id !== 'string' || !ID.test(id)) || new Set(Object.values(value)).size !== ID_KEYS.length) throw failure();
  return value;
}

export function validateDenialBootstrap(value) {
  const identityKeys = ['instance_id', 'principal_id', 'session_id', 'unprivileged_principal_id', 'unprivileged_session_id'];
  if (!value || value.development_only !== true || value.security_domain !== 'stead-local-development' || value.schema_version !== '1.0.0' || identityKeys.some((key) => typeof value[key] !== 'string' || !ID.test(value[key])) || new Set(identityKeys.map((key) => value[key])).size !== identityKeys.length) throw failure();
  return { instance_id: value.instance_id, principal_id: value.unprivileged_principal_id };
}

export function validateDenialDestination(input, init) {
  if (typeof input !== 'string' || !input.startsWith('/api/v1/') || input.includes('%') || input.includes('\\')) throw failure();
  const url = new URL(input, ORIGIN);
  if (url.origin !== ORIGIN || url.username || url.password || url.search || url.hash || url.pathname !== input || init.credentials !== 'same-origin' || init.redirect !== 'error') throw failure();
  const allowed = init.method === 'GET'
    ? new RegExp(`^/api/v1/(?:session|organizations/${UUID}|teams/${UUID}|projects/${UUID})$`, 'u')
    : init.method === 'POST' ? new RegExp(`^/api/v1/(?:session|organizations/${UUID}/teams)$`, 'u') : null;
  if (!allowed?.test(input) || (init.body !== undefined && (init.method !== 'POST' || typeof init.body !== 'string' || Buffer.byteLength(init.body) > (16 << 10)))) throw failure();
  const headers = new Headers(init.headers);
  for (const key of headers.keys()) if (!['accept', 'content-type', 'idempotency-key'].includes(key)) throw failure();
  return { url, method: init.method, headers };
}

export function denialResponse(body, headers, status) {
  if (status !== 404 || headers.get('content-type') !== 'application/problem+json' || headers.get('cache-control') !== 'no-store') throw failure();
  for (const key of ['etag', 'stead-schema-version', 'last-modified', 'location', 'content-location', 'link', 'set-cookie']) if (headers.has(key)) throw failure();
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(body);
  const problem = genericProblem(body, status);
  const value = JSON.parse(raw);
  // Reject duplicate keys, hidden/escaped payloads and noncanonical encodings;
  // only the independently generated correlation identity may differ on wire.
  if (raw !== `${JSON.stringify(value)}\n` || value.correlation_id !== headers.get('x-correlation-id')) throw failure();
  value.correlation_id = '0'.repeat(32);
  return { problem, normalized_body: JSON.stringify(value), etag_absent: true };
}

// requestImplementation is solely a transport fixture seam for unit tests.
export function denialTransport(certificate, cookie, acceptCookie, requestImplementation = httpsRequest) {
  const agent = new Agent({ keepAlive: true, maxSockets: 1, ca: certificate, rejectUnauthorized: true });
  let last;
  const fetchImplementation = async (input, init) => {
    last = undefined;
    const { url, method, headers } = validateDenialDestination(input, init);
    const outgoing = { ...Object.fromEntries(headers), Origin: ORIGIN };
    if (cookie.value) {
      if (!COOKIE.test(cookie.value)) throw failure();
      outgoing.Cookie = cookie.value;
    }
    return new Promise((resolve, reject) => {
      const request = requestImplementation(url, {
        method, headers: outgoing, agent, ca: certificate, rejectUnauthorized: true,
        servername: 'localhost', family: 4, maxHeaderSize: 16 << 10,
        lookup: (_host, options, callback) => options?.all ? callback(null, [{ address: '127.0.0.1', family: 4 }]) : callback(null, '127.0.0.1', 4),
        signal: init.signal ? AbortSignal.any([init.signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
      }, (response) => {
        void (async () => {
          try {
            if (!Number.isInteger(response.statusCode) || response.statusCode < 200 || response.statusCode >= 600 || (response.statusCode >= 300 && response.statusCode < 400)) throw failure();
            if (response.headers['set-cookie']) {
              if (input !== '/api/v1/session' || method !== 'POST' || response.statusCode !== 200 || cookie.value || !acceptCookie) throw failure();
              const value = sessionCookie(response.headers['set-cookie']);
              await acceptCookie(value); // Retain consumed identity even if subsequent body validation fails.
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
            const denial = response.statusCode >= 400 ? denialResponse(body, responseHeaders, response.statusCode) : undefined;
            last = { correlation_id: correlation, status: response.statusCode, bytes: length, denial };
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

async function syncDirectory(directory) {
  const file = await open(directory, 'r');
  try { await file.sync(); } finally { await file.close(); }
}

export async function denialCookie(state) {
  await privateDirectory(state);
  const filename = path.join(state, 'unprivileged-session-cookie');
  try {
    const value = JSON.parse(await readPrivate(filename, 4096));
    if (!value || value.origin !== ORIGIN || !COOKIE.test(value.cookie) || Object.keys(value).length !== 2) throw failure();
    return { cookie: { value: value.cookie }, close: async () => {} };
  } catch (error) {
    if (error.code !== 'ENOENT') throw error; // No retry of any interrupted exchange.
  }
  const reserved = await open(filename, 'wx+', 0o600);
  try {
    await reserved.writeFile(JSON.stringify({ login_in_flight: true }));
    await reserved.sync();
    await syncDirectory(state);
  } catch (error) { await reserved.close(); throw error; }
  let consumed = false;
  return {
    cookie: { value: '' },
    acceptCookie: async (cookie) => {
      if (consumed || !COOKIE.test(cookie)) throw failure();
      consumed = true;
      const data = Buffer.from(JSON.stringify({ origin: ORIGIN, cookie }));
      await reserved.truncate(0);
      let written = 0;
      while (written < data.length) {
        const { bytesWritten } = await reserved.write(data, written, data.length - written, written);
        if (!bytesWritten) throw failure();
        written += bytesWritten;
      }
      await reserved.sync();
    },
    close: () => reserved.close(),
  };
}

export async function proveAuthenticatedDenial(call, last, expected, ids, mutationKey) {
  validateDenialInputs(ids);
  if (!/^DN[0-9A-F]{8}$/u.test(mutationKey)) throw failure();
  const session = (await call('getSession')).data;
  if (session.principal?.type !== 'user' || session.principal.id !== expected.principal_id || session.instance_id !== expected.instance_id || !Number.isSafeInteger(session.session_revision) || session.session_revision < 2 || !Number.isFinite(Date.parse(session.expires_at)) || Date.parse(session.expires_at) <= Date.now()) throw failure();
  const checks = { distinct_authenticated_principal: true };
  const denied = async (operation, options) => {
    try { await call(operation, options); }
    catch (error) {
      if (!(error instanceof PlatformApiError) || error.status !== 404 || !last()?.denial) throw failure();
      return last().denial.normalized_body;
    }
    throw failure();
  };
  for (const [kind, operation, parameter] of [['organization', 'getOrganization', 'organization_id'], ['team', 'getTeam', 'team_id'], ['project', 'getProject', 'project_id']]) {
    const known = await denied(operation, { path: { [parameter]: ids[`known_${kind}`] } });
    const unknown = await denied(operation, { path: { [parameter]: ids[`unknown_${kind}`] } });
    if (known !== unknown) throw failure();
    checks[`${kind}_known_unknown_generic_equal_no_etag`] = true;
  }
  await denied('createTeam', {
    path: { organization_id: ids.known_organization },
    body: { key: mutationKey, name: 'Checkpoint A denied child Team attempt', parent_team_id: ids.known_team },
    idempotencyKey: `checkpoint-a-denial:${mutationKey}`,
  });
  checks.child_team_mutation_generic_denial = true;
  // A denial alone cannot prove no transaction committed: retain the public key
  // and request correlation for a separate read-only domain/audit/outbox query.
  return checks;
}

async function exclusiveEvidence(filename, report) {
  await privateDirectory(path.dirname(filename));
  const file = await open(filename, 'wx', 0o600);
  try { await file.writeFile(JSON.stringify(report)); await file.sync(); } finally { await file.close(); }
  await syncDirectory(path.dirname(filename));
}

export async function runCheckpointADenial(state, ids) {
  validateDenialInputs(ids);
  await privateDirectory(state);
  const expected = validateDenialBootstrap(JSON.parse(await readPrivate(path.join(state, 'bootstrap.json'), 16 << 10)));
  const certificate = await readPrivate(path.join(state, 'tls/localhost.crt'), 64 << 10);
  const mutationKey = `DN${randomBytes(4).toString('hex').toUpperCase()}`;
  const proofFile = `checkpoint-a-denial-${Date.now()}-${randomBytes(4).toString('hex')}.json`;
  const digest = async (relative) => createHash('sha256').update(await readFile(new URL(relative, import.meta.url))).digest('hex');
  const report = {
    scope: 'live-tls-generated-client-authenticated-denial-not-browser', passed: false,
    browser_covered: false, database_no_effects_proven: false, resource_existence_independently_proven: false,
    node_version: process.version, instance_id: expected.instance_id, principal_id: expected.principal_id,
    inputs: ids, attempted_team_key: mutationKey, checks: {}, records: [],
    source: { denial_sha256: await digest('./checkpoint_a_denial.mjs'), shared_boundary_sha256: await digest('./checkpoint_a_smoke.mjs'), sdk_sha256: await digest('../packages/api-client/src/client.ts'), generated_contract_sha256: await digest('../packages/api-client/src/generated/platform-v1.ts') },
  };
  const credential = await denialCookie(state);
  const transport = denialTransport(certificate, credential.cookie, credential.acceptCookie);
  const observations = [];
  const client = createPlatformClient({ fetchImplementation: transport.fetchImplementation, observeNetwork: (value) => observations.push(value) });
  const call = async (operation, options) => {
    const before = observations.length;
    try { return await client.request(operation, options); }
    finally {
      const wire = transport.last();
      if (observations.length === before + 1 && wire) {
        const measured = observations.at(-1);
        report.records.push({ operation, duration_ms: measured.durationMs, response_bytes: measured.responseBytes, status: measured.status, correlation_id: wire.correlation_id });
      }
    }
  };
  try {
    if (!credential.cookie.value) {
      const token = (await readPrivate(path.join(state, 'one-time-unprivileged-login-token'), 128)).toString('utf8');
      if (!/^[A-Za-z0-9_-]{43}$/u.test(token)) throw failure();
      await call('createSession', { body: { token } });
      if (!credential.cookie.value) throw failure();
    }
    report.checks = await proveAuthenticatedDenial(call, transport.last, expected, ids, mutationKey);
    // Only retry reading local observations, never login, authorization or a mutation.
    for (let attempt = 0; ; attempt++) {
      try {
        report.records = joinObservations(report.records, (await readPrivate(path.join(state, 'stead-api.log'), 8 << 20)).toString('utf8'));
        break;
      } catch (error) { if (attempt === 4) throw error; await delay(25); }
    }
    report.checks.actual_api_observations_joined = true;
    report.passed = true;
  } finally {
    transport.close();
    await credential.close();
    await exclusiveEvidence(path.join(state, proofFile), report);
  }
  return { scope: report.scope, passed: report.passed, proof_file: proofFile, checks: report.checks, requests: report.records.length, browser_covered: false, database_no_effects_proven: false, resource_existence_independently_proven: false, preserved_session: true };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const flags = ID_KEYS.map((key) => `--${key.replaceAll('_', '-')}`);
  if (args.length !== 15 || args[0] !== '--live' || args[1] !== '--state' || flags.some((flag, index) => args[3 + index * 2] !== flag)) {
    console.error(`Usage: checkpoint_a_denial.mjs --live --state /absolute/private/stead-state ${flags.map((flag) => `${flag} UUID`).join(' ')}`);
    process.exitCode = 1;
  } else {
    try { console.log(JSON.stringify(await runCheckpointADenial(args[2], Object.fromEntries(ID_KEYS.map((key, index) => [key, args[4 + index * 2]]))))); }
    catch { console.error('Checkpoint A denial proof failed; private evidence and the dedicated session are preserved. No login retry, logout or primary credential access was attempted.'); process.exitCode = 1; }
  }
}
