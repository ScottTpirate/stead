// SPDX-License-Identifier: Apache-2.0
// Test-only fixed GET discovery using already preserved sessions. Inert on import.
import { spawnSync } from 'node:child_process';
import { open } from 'node:fs/promises';
import { Agent, request as httpsRequest } from 'node:https';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createPlatformClient, PLATFORM_MAX_RESPONSE_BYTES } from '../packages/api-client/src/client.ts';
import { ORIGIN, privateDirectory, readPrivate, validateDestination } from './checkpoint_a_smoke.mjs';
import { validateDenialBootstrap, validateDenialInputs } from './checkpoint_a_denial.mjs';
import { loadEstablishedSessions, checkSession, checkBrowserBinding } from './checkpoint_a_followon.mjs';
import { noSymlinks, readBounded, sha256, validateAdmission } from './checkpoint_a_browser_boundary.mjs';
import { verifyIdentity } from './checkpoint_a_browser.mjs';

const HERE = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const check = (value) => { if (!value) throw new Error('Checkpoint A discovery rejected'); };
const UNKNOWN = Object.freeze({ unknown_organization: '01991c05-ffff-7000-8000-000000000001',
  unknown_team: '01991c05-ffff-7000-8000-000000000002', unknown_project: '01991c05-ffff-7000-8000-000000000003' });
const SHARED = ['scripts/checkpoint_a_smoke.mjs', 'scripts/checkpoint_a_denial.mjs', 'packages/api-client/src/client.ts', 'packages/api-client/src/generated/platform-v1.ts'];
const HELPERS = ['scripts/checkpoint_a_browser.mjs', 'scripts/checkpoint_a_browser_boundary.mjs', 'tests/e2e/checkpoint_a_browser_journey.mjs'];
function git(repo, args, trim = true) {
  const r = spawnSync('/usr/bin/git', ['--no-optional-locks', '-c', 'core.fsmonitor=false', '-C', repo, ...args],
    { env: { PATH: '/usr/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' }, encoding: 'utf8', timeout: 5000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'ignore'] });
  check(r.status === 0 && !r.error && !r.signal); return trim ? r.stdout.trim() : r.stdout;
}

// The owned request seam is for synthetic units only, never a CLI argument.
export function discoveryTransport(certificate, cookie, records, requestImplementation = httpsRequest) {
  const agent = new Agent({ keepAlive: true, maxSockets: 1, ca: certificate, rejectUnauthorized: true });
  let dispatches = 0;
  return { close: () => agent.destroy(), dispatches: () => dispatches,
    async fetchImplementation(input, init) {
      const { url, headers } = validateDestination(input, init);
      check(init.method === 'GET' && init.body === undefined && /^__Host-stead_session=[A-Za-z0-9_-]{43}$/.test(cookie));
      check(input === '/api/v1/session' || /^\/api\/v1\/organizations(?:\/[0-9a-f-]{36}\/(?:teams|projects))?\?page_size=20$/.test(input));
      return new Promise((resolve, reject) => {
        dispatches++;
        const req = requestImplementation(url, { method: 'GET', headers: { ...Object.fromEntries(headers), Origin: ORIGIN, Cookie: cookie },
          agent, ca: certificate, rejectUnauthorized: true, servername: 'localhost', family: 4, maxHeaderSize: 16384,
          lookup: (_host, options, done) => options?.all ? done(null, [{ address: '127.0.0.1', family: 4 }]) : done(null, '127.0.0.1', 4),
          signal: AbortSignal.any([init.signal ?? AbortSignal.timeout(20_000), AbortSignal.timeout(20_000)]) }, (res) => {
          void (async () => {
            try {
              const chunks = []; let size = 0;
              for await (const chunk of res) { size += chunk.length; check(size <= PLATFORM_MAX_RESPONSE_BYTES); chunks.push(chunk); }
              const correlation = res.headers['x-correlation-id'];
              check(/^[0-9a-f]{32}$/.test(correlation) && Number.isInteger(res.statusCode) && res.statusCode >= 200 && res.statusCode < 600);
              records.push({ correlation_id: correlation, status: res.statusCode });
              check(res.statusCode === 200 && !res.headers['set-cookie'] && !res.headers.location);
              const responseHeaders = new Headers();
              for (const [key, value] of Object.entries(res.headers)) if (value !== undefined) responseHeaders.set(key, Array.isArray(value) ? value.join(', ') : value);
              resolve(new Response(Buffer.concat(chunks, size), { status: 200, headers: responseHeaders }));
            } catch { res.destroy(); req.destroy(); reject(new Error('Discovery response rejected')); }
          })();
        });
        req.on('error', () => reject(new Error('Discovery request failed'))); req.end();
      });
    } };
}

function select(page, predicate) {
  check(Array.isArray(page?.items) && page.items.length <= 20 && page.next_after === undefined);
  const found = page.items.filter(predicate); check(found.length === 1); return found[0];
}
export async function discoverResources(call, expected, sessions) {
  for (const role of ['primary', 'denied']) checkSession((await call(role, 'getSession')).data, expected[role], sessions[role].expiresAt);
  const list = async (operation, organization) => (await call('primary', operation, {
    query: { page_size: 20 }, ...(organization ? { path: { organization_id: organization } } : {}) })).data;
  const org = select(await list('listOrganizations'), (r) => r.key === 'BJA7ORG');
  check(org.kind === 'organization' && org.instance_id === expected.primary.instance_id && org.organization_id === org.id);
  const teams = await list('listTeams', org.id);
  const parent = select(teams, (r) => r.key === 'BJA7PAR'), child = select(teams, (r) => r.key === 'BJA7CHD');
  check([parent, child].every((r) => r.kind === 'team' && r.instance_id === org.instance_id && r.organization_id === org.id));
  check(parent.parent_team_id === undefined && child.parent_team_id === parent.id && parent.id !== child.id);
  // The current API does not expose Project.key: do not pretend this proves BJA7PRJ.
  const project = select(await list('listProjects', org.id), (r) => r.title === 'Browser Journey A7 General Project' &&
    r.purpose === 'Synthetic browser-only Checkpoint A persistence verification.');
  check(project.kind === 'project' && project.instance_id === org.instance_id && project.organization_id === org.id && project.owning_team_id === child.id);
  check(JSON.stringify(project.authorized_capabilities) === '["work","docs"]' && JSON.stringify(project.visible_areas) === '["overview","work","docs"]');
  return validateDenialInputs({ known_organization: org.id, known_team: child.id, known_project: project.id, ...UNKNOWN });
}

async function preflight(checkout, work, admissionFile) {
  noSymlinks(checkout); await privateDirectory(work); check(path.basename(work) === 'work');
  const bytes = await readPrivate(admissionFile, 32768), admission = validateAdmission(JSON.parse(bytes));
  check(admission.source.repository === checkout && git(HERE, ['status', '--porcelain', '--untracked-files=normal']) === '');
  noSymlinks(admission.harness.repository);
  check(git(admission.harness.repository, ['rev-parse', `${admission.harness.head}^{tree}`]) === admission.harness.tree);
  for (const [file, digest] of Object.entries(admission.files)) check(sha256(git(admission.harness.repository, ['show', `${admission.harness.head}:${file}`], false)) === digest);
  for (const review of admission.reviews) check(sha256(readBounded(review.path, 1 << 20)) === review.sha256);
  for (const file of SHARED) check(sha256(readBounded(path.join(HERE, file), 1 << 20)) === sha256(readBounded(path.join(checkout, file), 1 << 20)));
  for (const file of HELPERS) check(sha256(readBounded(path.join(HERE, file), 1 << 20)) === admission.files[file]);
  const identity = verifyIdentity(admission);
  const bootstrap = JSON.parse(await readPrivate(path.join(admission.instance.state, 'bootstrap.json'), 16384));
  const expected = { primary: { instance_id: bootstrap.instance_id, principal_id: bootstrap.principal_id }, denied: validateDenialBootstrap(bootstrap) };
  const preceding = JSON.parse(await readPrivate(path.join(path.dirname(work), 'result.json'), 65536));
  check(preceding.passed === true);
  const binding = checkBrowserBinding(admission, preceding, sha256(bytes));
  const sessions = await loadEstablishedSessions(work, binding);
  return { identity, expected, binding, sessions, source: git(HERE, ['rev-parse', 'HEAD']) };
}

export async function runDiscovery(checkout, work, admissionFile) {
  await privateDirectory(work);
  const proof = await open(path.join(work, 'checkpoint-a-discovery.json'), 'wx', 0o600);
  const report = { scope: 'fixed-established-session-resource-discovery-only', passed: false, stage: 'preflight', records: [],
    dispatch_attempts: 0, unknown_absence_proven: false, project_key_proven: false, browser_created_provenance_proven: false };
  let input, after; const transports = [];
  try {
    input = await preflight(checkout, work, admissionFile);
    Object.assign(report, input.binding, { discovery_revision: input.source });
    const clients = Object.fromEntries(['primary', 'denied'].map((role) => {
      const wire = discoveryTransport(input.identity.certificate, input.sessions[role].cookie, report.records);
      transports.push(wire); return [role, createPlatformClient({ fetchImplementation: wire.fetchImplementation })];
    }));
    report.stage = 'reads';
    const signal = AbortSignal.timeout(120_000);
    const ids = await discoverResources((role, operation, options) => clients[role].request(operation, { ...options, signal }), input.expected, input.sessions);
    check(report.records.length === 5 && new Set(report.records.map((r) => r.correlation_id)).size === 5);
    report.stage = 'recheck'; after = await preflight(checkout, work, admissionFile);
    check(JSON.stringify(after) === JSON.stringify(input));
    const file = await open(path.join(work, 'checkpoint-a-discovered-resources.json'), 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(ids) + '\n'); await file.sync(); } finally { await file.close(); }
    report.passed = true; report.stage = 'complete';
  } catch { /* Keep first failure and closed correlations; never retry or retain bodies/errors. */ }
  finally {
    for (const wire of transports) { report.dispatch_attempts += wire.dispatches(); wire.close(); }
    for (const value of [input, after]) if (value) for (const role of ['primary', 'denied']) value.sessions[role].cookie = '';
    try { await proof.writeFile(JSON.stringify(report) + '\n'); await proof.sync(); } finally { await proof.close(); }
    const dir = await open(work, 'r'); try { await dir.sync(); } finally { await dir.close(); }
  }
  return { passed: report.passed, dispatch_attempts: report.dispatch_attempts, retained_responses: report.records.length };
}
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const a = process.argv.slice(2);
  if (a.length !== 7 || a[0] !== '--live' || a[1] !== '--checkout' || a[3] !== '--browser-work' || a[5] !== '--admission') {
    console.error('Usage: checkpoint_a_discovery.mjs --live --checkout /fresh/checkout --browser-work /private/run/work --admission /private/admission.json'); process.exitCode = 1;
  } else try { const r = await runDiscovery(a[2], a[4], a[6]); console.log(JSON.stringify(r)); if (!r.passed) process.exitCode = 1; }
  catch { console.error('Checkpoint A discovery failed closed; no login or retry.'); process.exitCode = 1; }
}
