// SPDX-License-Identifier: Apache-2.0
// Test-only established-session TLS/SDK reads. No bootstrap, mutations, browser,
// service control, SQL, provider access or implicit execution on import.
import { randomBytes } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { open, readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { createPlatformClient, PlatformApiError } from '../packages/api-client/src/client.ts';
import { ORIGIN, privateDirectory, readPrivate, joinObservations } from './checkpoint_a_smoke.mjs';
import { denialTransport, validateDenialBootstrap, validateDenialInputs } from './checkpoint_a_denial.mjs';
import { noSymlinks, readBounded, sha256, validateAdmission, validatePreservedSession, SESSION_FILES } from './checkpoint_a_browser_boundary.mjs';

const HERE = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const failure = () => new Error('Checkpoint A follow-on boundary rejected');
const requireValue = (value) => { if (!value) throw failure(); };
const READS = Object.freeze([
  ['organization', 'getOrganization', 'organization_id'],
  ['team', 'getTeam', 'team_id'], ['project', 'getProject', 'project_id'],
]);
export const TIMING_FIELDS = Object.freeze([
  'sql_client_calls', 'sql_client_ns', 'sql_client_failures',
  'pool_acquire_calls', 'pool_acquire_ns', 'pool_acquire_failures',
  'anchor_lock_attempts', 'anchor_lock_wait_ns', 'anchor_lock_contentions',
  'anchor_lock_failures', 'anchor_lock_held_ns', 'anchor_sync_calls',
  'anchor_sync_ns', 'anchor_sync_failures',
]);
const SHARED_FILES = ['scripts/checkpoint_a_smoke.mjs', 'scripts/checkpoint_a_denial.mjs',
  'scripts/checkpoint_a_browser_boundary.mjs', 'packages/api-client/src/client.ts',
  'packages/api-client/src/generated/platform-v1.ts'];

export async function loadEstablishedSessions(directory, binding, now = Date.now()) {
  await privateDirectory(directory);
  const sessions = {};
  for (const role of ['primary', 'denied']) {
    // Missing/partial files fail. Deliberately never inspect a one-time token.
    const bytes = await readPrivate(path.join(directory, SESSION_FILES[role]), 512);
    try {
      const credential = JSON.parse(bytes);
      const metadata = JSON.parse(await readPrivate(path.join(directory, role + '-session-binding.json'), 1024));
      validatePreservedSession(credential, metadata, role, binding, now);
      requireValue(metadata.expiresAt * 1000 > now + 120_000);
      sessions[role] = { cookie: credential.cookie, expiresAt: metadata.expiresAt };
    } finally { bytes.fill(0); }
  }
  requireValue(sessions.primary.cookie !== sessions.denied.cookie);
  return sessions;
}

export function checkSession(value, expected, expiresAt, now = Date.now()) {
  requireValue(value?.principal?.type === 'user' && value.principal.id === expected.principal_id &&
    value.instance_id === expected.instance_id && Number.isSafeInteger(value.session_revision) &&
    value.session_revision >= 2 && Number.isFinite(Date.parse(value.expires_at)) &&
    Date.parse(value.expires_at) > now && Math.floor(Date.parse(value.expires_at) / 1000) === expiresAt);
  return { revision: value.session_revision, expires_at: value.expires_at };
}

// One worker owns one serial transport, SDK and observation array. Four such
// workers can overlap without a shared last-response slot or cookie mutation.
// requestImplementation is an owned unit-fixture seam only, never a CLI option.
export function readWorker(certificate, session, ids, requestImplementation) {
  validateDenialInputs(ids);
  const wire = denialTransport(certificate, { value: session.cookie }, undefined, requestImplementation);
  const paths = new Set(['/api/v1/session', ...READS.flatMap(([kind]) =>
    ['known', 'unknown'].map((which) => '/api/v1/' + (kind === 'organization' ? 'organizations' : kind + 's') + '/' + ids[which + '_' + kind]))]);
  const observed = [];
  let busy = false;
  const client = createPlatformClient({
    fetchImplementation: (input, init) => {
      requireValue(init.method === 'GET' && init.body === undefined && paths.has(input));
      return wire.fetchImplementation(input, init);
    },
    observeNetwork: (value) => observed.push(value),
  });
  return {
    close: wire.close,
    async call(operation, options) {
      requireValue(!busy && ['getSession', ...READS.map(([, op]) => op)].includes(operation));
      busy = true;
      const before = observed.length;
      try {
        let response, error;
        try { response = await client.request(operation, options); } catch (caught) { error = caught; }
        const actual = wire.last(), measurement = observed[before];
        requireValue(observed.length === before + 1 && actual && measurement &&
          actual.status === measurement.status && actual.bytes === measurement.responseBytes &&
          actual.correlation_id === (response?.correlationId ?? error?.correlationId));
        requireValue(!error || (error instanceof PlatformApiError && error.status === 404 && actual.denial));
        return { data: response?.data, denial: actual.denial?.normalized_body,
          record: { operation, correlation_id: actual.correlation_id, status: actual.status,
            response_bytes: measurement.responseBytes, duration_ms: measurement.durationMs } };
      } finally { busy = false; }
    },
  };
}

export async function runReaders(certificate, sessions, expected, ids, requestImplementation) {
  validateDenialInputs(ids);
  const report = { passed: false, failed_stage: 'sessions_before', records: [], client_max_in_flight: 0 };
  const cancel = new AbortController();
  const signal = AbortSignal.any([cancel.signal, AbortSignal.timeout(120_000)]);
  const workers = ['primary', 'denied', 'primary', 'denied'].map((role, index) => ({
    role, index, sequence: 0, reader: readWorker(certificate, sessions[role], ids, requestImplementation),
  }));
  let active = 0;
  const call = async (worker, operation, options, sample) => {
    requireValue(!signal.aborted);
    active++; report.client_max_in_flight = Math.max(active, report.client_max_in_flight);
    try {
      const result = await worker.reader.call(operation, { ...options, signal });
      report.records.push({ worker: worker.index, principal: worker.role, sequence: worker.sequence++, sample, ...result.record });
      return result;
    } finally { active--; }
  };
  const together = async (job) => {
    const outcomes = await Promise.allSettled(workers.map(async (worker) => {
      try { await job(worker); } catch { cancel.abort(); throw failure(); }
    }));
    requireValue(outcomes.every((entry) => entry.status === 'fulfilled'));
  };
  const before = [];
  try {
    await together(async (worker) => {
      const response = await call(worker, 'getSession', {}, 'session_before');
      before[worker.index] = checkSession(response.data, expected[worker.role], sessions[worker.role].expiresAt);
    });
    report.failed_stage = 'concurrent_reads';
    await together(async (worker) => {
      for (let round = 0; round < 3; round++) for (const [kind, operation, parameter] of READS) {
        let known;
        for (const which of round % 2 ? ['unknown', 'known'] : ['known', 'unknown']) {
          const target = ids[which + '_' + kind];
          const result = await call(worker, operation, { path: { [parameter]: target } }, which + '_' + kind);
          if (worker.role === 'primary' && which === 'known') {
            requireValue(result.record.status === 200 && result.data?.id === target &&
              result.data.kind === kind && result.data.instance_id === expected.primary.instance_id &&
              result.data.organization_id === ids.known_organization);
          } else {
            requireValue(result.record.status === 404 && typeof result.denial === 'string');
            if (worker.role === 'denied') {
              if (known === undefined) known = result.denial;
              else requireValue(known === result.denial);
            }
          }
        }
      }
    });
    report.failed_stage = 'sessions_after';
    await together(async (worker) => {
      const result = await call(worker, 'getSession', {}, 'session_after');
      const after = checkSession(result.data, expected[worker.role], sessions[worker.role].expiresAt);
      requireValue(JSON.stringify(after) === JSON.stringify(before[worker.index]));
    });
    requireValue(report.records.length === 80 && report.client_max_in_flight === 4 &&
      new Set(report.records.map((r) => r.correlation_id)).size === report.records.length);
    report.passed = true; report.failed_stage = null;
  } catch { /* Retain bounded first-failure stage and completed observations, never errors/DOM/cookies. */ }
  finally { for (const worker of workers) worker.reader.close(); }
  return report;
}

export function joinReadObservations(records, raw) {
  const joined = joinObservations(records, raw);
  const wanted = new Set(records.map((r) => r.correlation_id)), timing = new Map();
  for (const line of raw.split('\n')) {
    let entry; try { entry = JSON.parse(line); } catch { continue; }
    if (!wanted.has(entry?.correlation_id)) continue;
    const safe = {};
    for (const field of TIMING_FIELDS) {
      requireValue(Number.isSafeInteger(entry.timing?.[field]) && entry.timing[field] >= 0);
      safe[field] = entry.timing[field];
    }
    timing.set(entry.correlation_id, safe);
  }
  return joined.map((r) => ({ ...r, api: { ...r.api, timing: timing.get(r.correlation_id) } }));
}

function git(checkout, args) {
  const result = spawnSync('/usr/bin/git', ['--no-optional-locks', '-c', 'core.fsmonitor=false',
    '-c', 'core.untrackedCache=false', '-C', checkout, ...args], {
    env: { PATH: '/usr/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
    encoding: 'utf8', timeout: 5000, maxBuffer: 1 << 20, stdio: ['ignore', 'pipe', 'ignore'],
  });
  requireValue(result.status === 0 && !result.error && !result.signal);
  return result.stdout.trim();
}
async function preflight(checkout, work, admissionFile, resourcesFile) {
  noSymlinks(checkout); await privateDirectory(work);
  const admissionBytes = await readPrivate(admissionFile, 32768);
  const admission = validateAdmission(JSON.parse(admissionBytes));
  requireValue(admission.source.repository === checkout && path.basename(work) === 'work');
  const state = admission.instance.state;
  await privateDirectory(state);
  requireValue(git(checkout, ['rev-parse', 'HEAD']) === admission.source.head &&
    git(checkout, ['status', '--porcelain', '--untracked-files=normal']) === '');
  for (const [file, digest] of Object.entries(admission.files)) {
    requireValue(sha256(readBounded(path.join(checkout, file), 1 << 20)) === digest);
  }
  for (const file of SHARED_FILES) requireValue(sha256(await readFile(path.join(HERE, file))) === sha256(readBounded(path.join(checkout, file), 1 << 20)));
  requireValue(sha256(readBounded(path.join(state, 'stead-api'), 512 << 20)) === admission.source.apiSHA256);
  requireValue(sha256(readBounded(path.join(checkout, 'modules/authorization/localdata/approved-template.json'), 1 << 20)) === admission.source.templateSHA256);
  requireValue(sha256(readBounded(path.join(checkout, 'docs/governance/local-development-template-review.json'), 1 << 20)) === admission.source.templateReviewSHA256);
  const bootstrapBytes = await readPrivate(path.join(state, 'bootstrap.json'), 16384);
  requireValue(sha256(bootstrapBytes) === admission.instance.bootstrapSHA256);
  const bootstrap = JSON.parse(bootstrapBytes), denied = validateDenialBootstrap(bootstrap);
  requireValue(bootstrap.instance_id === admission.instance.instanceID && bootstrap.activation_digest === admission.instance.activationDigest);
  const certificate = await readPrivate(path.join(state, 'tls/localhost.crt'), 16384);
  requireValue(sha256(certificate) === admission.instance.certificateSHA256);
  const binding = { admissionSHA256: sha256(admissionBytes), instanceID: admission.instance.instanceID, sourceRevision: admission.source.head };
  const preceding = JSON.parse(await readPrivate(path.join(path.dirname(work), 'result.json'), 65536));
  requireValue(preceding.format === 'stead-checkpoint-a-browser-run-v1' && preceding.inputsUnchanged === true &&
    preceding.admissionSHA256 === binding.admissionSHA256 && preceding.instanceID === binding.instanceID &&
    preceding.sourceRevision === binding.sourceRevision && preceding.sessions?.primary === 'preserved' && preceding.sessions?.denied === 'preserved');
  const ids = validateDenialInputs(JSON.parse(await readPrivate(resourcesFile, 4096)));
  const sessions = await loadEstablishedSessions(work, binding);
  return { state, certificate, sessions, ids, binding,
    expected: { primary: { instance_id: bootstrap.instance_id, principal_id: bootstrap.principal_id }, denied } };
}

export async function runFollowon(checkout, work, admissionFile, resourcesFile) {
  const input = await preflight(checkout, work, admissionFile, resourcesFile);
  const report = { scope: 'established-session-tls-sdk-reads-not-browser-sql-or-release', passed: false, failed_stage: 'readers',
    ...input.binding, resources: input.ids, node_version: process.version,
    source: Object.fromEntries(await Promise.all(['scripts/checkpoint_a_followon.mjs', ...SHARED_FILES].map(async (file) => [file, sha256(await readFile(path.join(HERE, file)))]))),
    runtime_process_identity_reverified: false, database_audit_persistence_proven: false,
    resource_existence_independently_proven: false, restart_proven: false, timing_nondisclosure_proven: false,
    readers: await runReaders(input.certificate, input.sessions, input.expected, input.ids) };
  try {
    requireValue(report.readers.passed);
    report.failed_stage = 'observation_join';
    for (let attempt = 0; ; attempt++) {
      try {
        report.readers.records = joinReadObservations(report.readers.records, (await readPrivate(path.join(input.state, 'stead-api.log'), 8 << 20)).toString('utf8'));
        break;
      } catch { if (attempt === 4) throw failure(); await delay(25); }
    }
    report.failed_stage = 'binding_recheck';
    const after = await preflight(checkout, work, admissionFile, resourcesFile);
    requireValue(JSON.stringify(after.binding) === JSON.stringify(input.binding) &&
      JSON.stringify(after.ids) === JSON.stringify(input.ids) &&
      ['primary', 'denied'].every((role) => after.sessions[role].cookie === input.sessions[role].cookie));
    for (const role of ['primary', 'denied']) after.sessions[role].cookie = '';
    report.passed = true; report.failed_stage = null;
  } catch { /* Preserve incomplete correlation evidence, never retry HTTP. */ }
  finally {
    for (const role of ['primary', 'denied']) input.sessions[role].cookie = '';
    const filename = 'checkpoint-a-followon-' + Date.now() + '-' + randomBytes(4).toString('hex') + '.json';
    const file = await open(path.join(work, filename), 'wx', 0o600);
    try { await file.writeFile(JSON.stringify(report) + '\n'); await file.sync(); } finally { await file.close(); }
    const directory = await open(work, 'r');
    try { await directory.sync(); } finally { await directory.close(); }
    report.proof_file = filename;
  }
  return { scope: report.scope, passed: report.passed, requests: report.readers.records.length, proof_file: report.proof_file };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  if (args.length !== 9 || args[0] !== '--live' || args[1] !== '--checkout' ||
    args[3] !== '--browser-work' || args[5] !== '--admission' || args[7] !== '--resources') {
    console.error('Usage: checkpoint_a_followon.mjs --live --checkout /fresh/checkout --browser-work /private/run/work --admission /private/admission.json --resources /private/resources.json');
    process.exitCode = 1;
  } else {
    try { const result = await runFollowon(args[2], args[4], args[6], args[8]); console.log(JSON.stringify(result)); if (!result.passed) process.exitCode = 1; }
    catch { console.error('Checkpoint A follow-on failed closed; no login, logout or HTTP retry was attempted.'); process.exitCode = 1; }
  }
}
