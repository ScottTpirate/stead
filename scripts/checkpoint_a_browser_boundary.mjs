// Closed, dependency-free boundaries for the one-shot Checkpoint A browser run.
// Importing this module performs no filesystem, network or browser action.
import { createHash } from 'node:crypto';
import { openSync, closeSync, fstatSync, readSync, lstatSync, realpathSync, opendirSync,
  writeSync, fsyncSync, constants } from 'node:fs';
import path from 'node:path';

export const ORIGIN = 'https://localhost:18443';
export const CSP = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'";
export const OUTER_NODE = '/tmp/stead-node-toolchain-26.8.1/toolchain/node-v26.8.1-linux-x64/bin/node';
export const INPUTS = '/home/skilgore/stead-browser-runner-20260905.oT3CF17j/inputs.json';
export const INPUTS_SHA256 = '92fb28a6c55ad3510a978fbbed0069bd2edefda722402a7b569cdb6d2e8b90af';
export const FORBIDDEN_STATE = '/home/skilgore/stead/.cache/stead-dev';
export const SOURCE_FILES = Object.freeze([
  'scripts/checkpoint_a_browser.mjs', 'scripts/checkpoint_a_browser_boundary.mjs',
  'tests/e2e/checkpoint_a_browser.mjs', 'tests/e2e/checkpoint_a_browser_journey.mjs',
  'Makefile',
]);
export const PHASES = Object.freeze(['preflight', 'identity', 'tls', 'attempt', 'staging',
  'namespace', 'trust', 'browser', 'journey', 'cleanup', 'complete']);
export const STAGES = Object.freeze(['preflight', 'primary_login', 'organization_create_read',
  'parent_team_create_read', 'child_team_create_read', 'general_project_create_read',
  'reload_refresh_read', 'keyboard_palette_focus', 'denied_login_empty_views',
  'denied_organization_mutation', 'one_shot_counts']);
export const SURFACES = Object.freeze(['primary_login', 'organization_detail', 'child_team_detail',
  'general_project_detail', 'command_palette', 'denied_projects_empty', 'denied_organization_alert']);
export const OPERATIONS = Object.freeze(['session_get', 'session_create', 'organization_list',
  'organization_create', 'organization_read', 'team_list', 'team_create', 'team_read',
  'project_list', 'project_create', 'project_read']);
export const SESSION_FILES = Object.freeze({ primary: 'checkpoint-a-cookie.json', denied: 'unprivileged-session-cookie' });
export const check = (condition) => { if (!condition) throw new Error('browser_boundary'); };
export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const hash = (value) => typeof value === 'string' && /^[a-f0-9]{64}$/.test(value);
const revision = (value) => typeof value === 'string' && /^[a-f0-9]{40}$/.test(value);
const uuid = (value) => typeof value === 'string' && /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(value);
export function keys(value, expected) {
  check(value && typeof value === 'object' && !Array.isArray(value));
  check(Object.keys(value).sort().join('\0') === [...expected].sort().join('\0'));
}
export function absolute(value) {
  check(typeof value === 'string' && /^\/[A-Za-z0-9_.\/-]{1,500}$/.test(value));
  check(path.posix.normalize(value) === value && value !== '/' && !value.endsWith('/'));
  return value;
}
export function noSymlinks(file) {
  absolute(file);
  let current = '/';
  for (const part of file.split('/').filter(Boolean)) {
    current = path.join(current, part);
    check(!lstatSync(current).isSymbolicLink());
  }
  check(realpathSync(file) === file);
}
export function privateDirectory(directory) {
  noSymlinks(directory);
  const stat = lstatSync(directory);
  check(stat.isDirectory() && stat.uid === process.getuid() && (stat.mode & 0o777) === 0o700);
}
// O_NOFOLLOW + opened-file checks, not a pathname check followed by an unchecked
// read. Same-user concurrent mutation is not a hostile-user security boundary.
export function readBounded(file, limit, { owner = process.getuid(), privateMode = false } = {}) {
  noSymlinks(file);
  const descriptor = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const stat = fstatSync(descriptor);
    check(stat.isFile() && stat.nlink === 1 && stat.uid === owner && !(stat.mode & 0o6022));
    check(!privateMode || (stat.mode & 0o777) === 0o600);
    check(stat.size > 0 && stat.size <= limit);
    const bytes = Buffer.alloc(stat.size + 1); let total = 0;
    while (total < bytes.length) {
      const count = readSync(descriptor, bytes, total, bytes.length - total, null);
      if (count === 0) break;
      total += count;
    }
    check(total === stat.size && total <= limit);
    return bytes.subarray(0, total);
  } finally { closeSync(descriptor); }
}
export function claimAttempt(state, record) {
  privateDirectory(state);
  const file = path.join(state, 'checkpoint-a-browser-attempt.json');
  const descriptor = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(descriptor, JSON.stringify(record) + '\n'); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
  const directory = openSync(state, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(directory); } finally { closeSync(directory); }
  return file;
}
export function validateAdmission(value, now = Date.now()) {
  keys(value, ['format', 'status', 'scope', 'expiresAt', 'source', 'instance', 'files', 'reviews']);
  check(value.format === 'stead-checkpoint-a-browser-admission-v1' && value.status === 'accepted');
  check(value.scope === 'one-fresh-real-checkpoint-a-browser-run');
  check(typeof value.expiresAt === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$/.test(value.expiresAt));
  const expiry = Date.parse(value.expiresAt);
  check(Number.isFinite(expiry) && expiry > now && expiry <= now + 86400_000);
  keys(value.source, ['repository', 'head', 'implementationRevision', 'implementationTree', 'templateSHA256', 'templateReviewSHA256', 'apiSHA256']);
  absolute(value.source.repository);
  for (const field of ['head', 'implementationRevision', 'implementationTree']) check(revision(value.source[field]));
  for (const field of ['templateSHA256', 'templateReviewSHA256', 'apiSHA256']) check(hash(value.source[field]));
  keys(value.instance, ['state', 'instanceID', 'bootstrapSHA256', 'activationDigest', 'certificateSHA256']);
  check(value.instance.state === value.source.repository + '/.cache/stead-dev' && value.instance.state !== FORBIDDEN_STATE);
  check(uuid(value.instance.instanceID) && hash(value.instance.bootstrapSHA256) && hash(value.instance.certificateSHA256));
  check(/^sha256:[a-f0-9]{64}$/.test(value.instance.activationDigest));
  keys(value.files, SOURCE_FILES);
  for (const digest of Object.values(value.files)) check(hash(digest));
  check(Array.isArray(value.reviews) && value.reviews.length === 3);
  const roles = new Set(), reviewers = new Set();
  for (const review of value.reviews) {
    keys(review, ['role', 'reviewer', 'path', 'sha256', 'independentNonAuthor', 'disposition']);
    check(['security', 'qa', 'architecture-license'].includes(review.role));
    check(typeof review.reviewer === 'string' && /^\/[a-z0-9_/-]{1,160}$/.test(review.reviewer));
    check(!roles.has(review.role) && !reviewers.has(review.reviewer));
    check(review.independentNonAuthor === true && review.disposition === 'accept' && hash(review.sha256));
    absolute(review.path); roles.add(review.role); reviewers.add(review.reviewer);
  }
  return value;
}
// Secondary browser routing assertion. The separate network namespace and fixed
// byte relay enforce destination confinement even when a request bypasses this.
export function allowedRequest(method, value) {
  try {
    const url = new URL(value);
    if (value !== url.href || value !== ORIGIN + url.pathname + url.search || url.origin !== ORIGIN || url.username || url.password || url.hash) return false;
    const id = '[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}';
    const collection = /^\/api\/v1\/organizations$/.test(url.pathname) || new RegExp(`^/api/v1/organizations/${id}/(?:teams|projects)$`).test(url.pathname);
    if (url.search && !(method === 'GET' && collection && url.search === '?page_size=20')) return false;
    if (method === 'GET' && (/^\/(?:|inbox|my-work|projects|knowledge|teams)$/.test(url.pathname) ||
        /^\/assets\/[A-Za-z0-9_-]+\.(?:js|css|woff2)$/.test(url.pathname))) return true;
    if (!['GET', 'POST'].includes(method)) return false;
    if (/^\/api\/v1\/(?:session|organizations)$/.test(url.pathname)) return true;
    if (new RegExp(`^/api/v1/organizations/${id}/(?:teams|projects)$`).test(url.pathname)) return true;
    return method === 'GET' && new RegExp(`^/api/v1/(?:organizations|teams|projects)/${id}$`).test(url.pathname);
  } catch { return false; }
}
export function byteBudget(limit = 128 * 1024 * 1024) {
  check(Number.isSafeInteger(limit) && limit > 0 && limit <= 128 * 1024 * 1024);
  let used = 0, exceeded = false;
  return { add(count) { if (!Number.isSafeInteger(count) || count < 0 || count > limit - used) exceeded = true;
    if (!exceeded) used += count; return !exceeded; }, get exceeded() { return exceeded; } };
}
const integer = (value, max) => Number.isSafeInteger(value) && value >= 0 && value <= max;
export function validateAxe(value, surface) {
  keys(value, ['surface', 'violations', 'incomplete', 'passedRules']);
  check(value.surface === surface && SURFACES.includes(surface) && integer(value.passedRules, 256));
  for (const field of ['violations', 'incomplete']) {
    check(Array.isArray(value[field]) && value[field].length <= 64);
    for (const finding of value[field]) {
      keys(finding, ['rule', 'impact', 'affectedNodes']);
      check(/^[a-z0-9-]{1,80}$/.test(finding.rule) && [null, 'minor', 'moderate', 'serious', 'critical'].includes(finding.impact));
      check(integer(finding.affectedNodes, 2048));
    }
  }
  return value;
}
export function validateJourney(value) {
  keys(value, ['format', 'status', 'failedStage', 'completed', 'timings', 'elapsedMs', 'network', 'accessibility', 'denialEvidence', 'contextsPreserved']);
  check(value.format === 'stead-checkpoint-a-browser-journey-v1' && ['completed', 'failed'].includes(value.status));
  check(value.failedStage === null || STAGES.includes(value.failedStage));
  check(Array.isArray(value.completed) && value.completed.length <= 10 && value.completed.every((stage, i) => stage === STAGES[i + 1]));
  check(Array.isArray(value.timings) && value.timings.length === value.completed.length);
  value.timings.forEach((entry, i) => { keys(entry, ['stage', 'elapsedMs']); check(entry.stage === value.completed[i] && integer(entry.elapsedMs, 240_000)); });
  check(integer(value.elapsedMs, 240_000) && Array.isArray(value.network) && value.network.length <= 2);
  value.network.forEach((entry, i) => {
    keys(entry, ['principal', 'counts', 'requests', 'responses', 'failed', 'forbidden', 'unknownAPI', 'overflow']);
    check(entry.principal === ['primary', 'denied'][i] && typeof entry.overflow === 'boolean');
    keys(entry.counts, OPERATIONS);
    Object.values(entry.counts).forEach((count) => check(integer(count, 256)));
    for (const key of ['requests', 'responses', 'failed', 'forbidden', 'unknownAPI']) check(integer(entry[key], 256));
  });
  keys(value.accessibility, ['status', 'surfaces']);
  check(value.accessibility.status === 'collected_if_reached' && Array.isArray(value.accessibility.surfaces) && value.accessibility.surfaces.length <= 7);
  value.accessibility.surfaces.forEach((surface, i) => validateAxe(surface, SURFACES[i]));
  check(value.denialEvidence === 'ui_only_sql_fga_and_known_unknown_checks_are_separate' && value.contextsPreserved === true);
  if (value.status === 'completed') check(value.completed.length === 10 && value.failedStage === null && value.network.length === 2 && value.accessibility.surfaces.length === 7);
  return value;
}
export function validateInnerProof(value) {
  keys(value, ['format', 'passed', 'phase', 'networkIsolated', 'rendererSandbox', 'cspPreserved', 'browserCleanup', 'journey']);
  check(value.format === 'stead-checkpoint-a-browser-proof-v1' && typeof value.passed === 'boolean' && PHASES.includes(value.phase));
  for (const field of ['networkIsolated', 'rendererSandbox', 'cspPreserved', 'browserCleanup']) check(typeof value[field] === 'boolean');
  if (value.journey !== null) validateJourney(value.journey);
  if (value.passed) check(value.phase === 'complete' && value.networkIsolated && value.rendererSandbox && value.cspPreserved && value.browserCleanup && value.journey?.status === 'completed');
  return value;
}

// Reuse the existing committed bundle inventory; no new bundle format or build.
// The caller compares these evidence bytes with HEAD before this local check.
export function verifyDistribution(directory, evidence) {
  noSymlinks(directory);
  check(evidence.schema_version === '1.3' && Array.isArray(evidence.distribution_artifacts));
  const artifacts = evidence.distribution_artifacts;
  check(artifacts.length > 0 && artifacts.length <= 1024);
  const files = new Map(), directories = new Set(['']); let total = 0;
  for (const entry of artifacts) {
    keys(entry, ['file', 'sha256', 'uncompressed_bytes']);
    check(typeof entry.file === 'string' && /^[A-Za-z0-9_./-]{1,500}$/.test(entry.file));
    check(!entry.file.startsWith('/') && path.posix.normalize(entry.file) === entry.file && !entry.file.split('/').some((part) => part === '.' || part === '..'));
    check(hash(entry.sha256) && integer(entry.uncompressed_bytes, 8388608) && entry.uncompressed_bytes > 0 && !files.has(entry.file));
    total += entry.uncompressed_bytes; check(total <= 33554432); files.set(entry.file, entry);
    let parent = path.posix.dirname(entry.file);
    while (parent !== '.') { directories.add(parent); parent = path.posix.dirname(parent); }
  }
  check(files.has('index.html') && files.has('.vite/manifest.json'));
  const seen = new Set(); let entries = 0;
  const walk = (relative, depth) => {
    check(depth <= 16); const current = path.join(directory, relative); noSymlinks(current);
    const stat = lstatSync(current); check(stat.isDirectory() && stat.uid === process.getuid() && !(stat.mode & 0o022));
    const stream = opendirSync(current);
    try {
      for (let entry; (entry = stream.readSync()) !== null;) {
        check(++entries <= 1024);
        const name = relative ? relative + '/' + entry.name : entry.name;
        if (entry.isDirectory()) { check(directories.has(name)); walk(name, depth + 1); }
        else {
          check(entry.isFile() && files.has(name)); const expected = files.get(name);
          const bytes = readBounded(path.join(directory, name), 8388608);
          check(bytes.length === expected.uncompressed_bytes && sha256(bytes) === expected.sha256); seen.add(name);
        }
      }
    } finally { stream.closeSync(); }
  };
  walk('', 0); check(seen.size === files.size);
  return sha256(JSON.stringify(artifacts));
}

// The BFF retains an opened os.Root, so an equal pathname is insufficient after
// a directory replacement. Compare the actual held directory, not its spelling.
export function openedDirectoryMatches(descriptor, directory) {
  const held = fstatSync(descriptor, { bigint: true });
  const current = lstatSync(directory, { bigint: true });
  return held.isDirectory() && current.isDirectory() && held.dev === current.dev && held.ino === current.ino;
}

export function processStat(text, expectedPID) {
  check(typeof text === 'string' && text.length < 8192);
  const close = text.lastIndexOf(') '); check(close > 2 && text.startsWith(`${expectedPID} (`));
  const fields = text.slice(close + 2).trim().split(/\s+/);
  check(fields.length >= 20 && fields[0] !== 'Z' && fields[0] !== 'X');
  check(/^[1-9][0-9]*$/.test(fields[1]) && /^[0-9]{1,20}$/.test(fields[19]));
  const parent = Number(fields[1]); check(Number.isSafeInteger(parent));
  return { parent, start: fields[19] };
}
export function serviceCommand(args, state, repository) {
  check(Array.isArray(args) && args.every((value) => typeof value === 'string'));
  const binary = path.join(state, 'stead-api');
  if (args.length === 1 && args[0] === binary) return 'api';
  const web = [binary, 'dev-web', '--listen', '127.0.0.1:18443', '--origin', ORIGIN,
    '--upstream', 'http://127.0.0.1:18000', '--assets', path.join(repository, 'apps/web/dist'),
    '--tls-cert', path.join(state, 'tls/localhost.crt'), '--tls-key', path.join(state, 'tls/localhost.key')];
  check(args.length === web.length && args.every((value, index) => value === web[index]));
  return 'web';
}
export function listenerInodes(tcp, tcp6, uid) {
  const result = {};
  for (const [text, ipv6] of [[tcp, false], [tcp6, true]]) {
    check(typeof text === 'string' && text.length <= 1048576);
    const lines = text.trim().split('\n'); check(lines.length <= 4096 && lines[0].includes('local_address'));
    for (const line of lines.slice(1)) {
      const fields = line.trim().split(/\s+/); check(fields.length >= 10);
      const [address, port] = fields[1].split(':');
      if (!['4650', '480B'].includes(port) || fields[3] !== '0A') continue;
      const role = port === '4650' ? 'api' : 'web';
      check(!ipv6 && address === '0100007F' && !result[role] && fields[7] === String(uid) && /^[1-9][0-9]*$/.test(fields[9]));
      result[role] = fields[9];
    }
  }
  check(result.api && result.web && result.api !== result.web); return result;
}

function sessionBinding(value) {
  keys(value, ['admissionSHA256', 'instanceID', 'sourceRevision']);
  check(hash(value.admissionSHA256) && uuid(value.instanceID) && revision(value.sourceRevision));
}
export function browserCookie(cookies, now = Date.now()) {
  check(Array.isArray(cookies) && cookies.length === 1);
  const cookie = cookies[0];
  keys(cookie, ['name', 'value', 'domain', 'path', 'expires', 'httpOnly', 'secure', 'sameSite']);
  check(cookie.name === '__Host-stead_session' && typeof cookie.value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(cookie.value));
  check(Buffer.from(cookie.value, 'base64url').toString('base64url') === cookie.value);
  check(cookie.domain === 'localhost' && cookie.path === '/' && cookie.secure === true && cookie.httpOnly === true && cookie.sameSite === 'Strict');
  check(typeof cookie.expires === 'number' && Number.isFinite(cookie.expires) && cookie.expires * 1000 > now && cookie.expires * 1000 <= now + 86400_000);
  return { credential: { origin: ORIGIN, cookie: '__Host-stead_session=' + cookie.value }, expiresAt: cookie.expires };
}
function exclusivePrivate(file, value) {
  const bytes = Buffer.from(JSON.stringify(value) + '\n');
  const descriptor = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try {
    let written = 0;
    while (written < bytes.length) { const count = writeSync(descriptor, bytes, written, bytes.length - written); check(count > 0); written += count; }
    fsyncSync(descriptor);
  } finally { bytes.fill(0); closeSync(descriptor); }
  const directory = openSync(path.dirname(file), constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(directory); } finally { closeSync(directory); }
}
export function preserveSession(directory, role, cookies, binding, now = Date.now()) {
  privateDirectory(directory); check(Object.hasOwn(SESSION_FILES, role)); sessionBinding(binding);
  const { credential, expiresAt } = browserCookie(cookies, now);
  // Two fixed private files: legacy exact {origin,cookie} format, plus private
  // source/instance/role/expiry binding. Neither is public diagnostic evidence.
  // Partial writes are retained and never overwritten or automatically retried.
  exclusivePrivate(path.join(directory, SESSION_FILES[role]), credential);
  exclusivePrivate(path.join(directory, `${role}-session-binding.json`), {
    ...binding, role, expiresAt, cookieSHA256: sha256(credential.cookie),
  });
}
export function validatePreservedSession(credential, metadata, role, binding, now = Date.now()) {
  sessionBinding(binding); check(Object.hasOwn(SESSION_FILES, role));
  keys(credential, ['origin', 'cookie']);
  check(credential.origin === ORIGIN && typeof credential.cookie === 'string' && /^__Host-stead_session=[A-Za-z0-9_-]{43}$/.test(credential.cookie));
  check(Buffer.from(credential.cookie.slice(21), 'base64url').toString('base64url') === credential.cookie.slice(21));
  keys(metadata, ['admissionSHA256', 'instanceID', 'sourceRevision', 'role', 'expiresAt', 'cookieSHA256']);
  check(metadata.role === role && metadata.admissionSHA256 === binding.admissionSHA256 && metadata.instanceID === binding.instanceID && metadata.sourceRevision === binding.sourceRevision);
  check(typeof metadata.expiresAt === 'number' && Number.isFinite(metadata.expiresAt) && metadata.expiresAt * 1000 > now && metadata.expiresAt * 1000 <= now + 86400_000);
  check(metadata.cookieSHA256 === sha256(credential.cookie));
}
