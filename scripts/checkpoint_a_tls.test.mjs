// Owned dependency-free synthetic fixtures only. No native executable, live
// service, public/private instance file, credential, browser or relay execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdtempSync, writeFileSync, readFileSync, readdirSync, rmSync, lstatSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ORIGIN, serverTrustCommands, TLS_SOURCE_FILES, SOURCE_FILES, sha256, validateAdmission } from './checkpoint_a_browser_boundary.mjs';
import { TLS_SCOPE, TLS_PROFILES, WRONG_ORIGIN, WRONG_HOST_RULE, TLS_ERRORS,
  validateTLSAdmission, claimTLSDiagnostic, classifyTLSError, tlsNavigationAllowed,
  trialPass, validateTLSProof } from './checkpoint_a_tls_boundary.mjs';
import { stage } from './checkpoint_a_browser.mjs';
import { main as controller } from './checkpoint_a_tls.mjs';
import { main as diagnostic, launchOptions } from '../tests/e2e/checkpoint_a_tls.mjs';

const repo = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const revision = 'a'.repeat(40), digest = 'b'.repeat(64);
const now = Date.parse('2026-09-06T01:00:00Z');
function admission() {
  return { format: 'stead-checkpoint-a-tls-admission-v1', status: 'accepted', scope: TLS_SCOPE,
    expiresAt: '2026-09-06T02:00:00.000Z', harness: { repository: '/home/fixture/harness', head: revision, tree: revision },
    source: { repository: '/home/fixture/app', head: revision, implementationRevision: revision, implementationTree: revision,
      templateSHA256: digest, templateReviewSHA256: digest, apiSHA256: digest },
    instance: { state: '/home/fixture/app/.cache/stead-dev', instanceID: '01991c05-1a00-7000-8000-000000000001',
      bootstrapSHA256: digest, activationDigest: 'sha256:' + digest, certificateSHA256: digest },
    files: Object.fromEntries(TLS_SOURCE_FILES.map((file) => [file, digest])),
    reviews: ['security', 'qa', 'architecture-license'].map((role) => ({ role, reviewer: '/review/' + role,
      path: '/home/fixture/' + role + '.md', sha256: digest, independentNonAuthor: true, disposition: 'accept' })) };
}
const trial = (profile) => ({ profile, status: profile === 'peer' ? 200 : null,
  error: profile === 'peer' ? 'none' : profile === 'wrong_name' ? 'certificate_name' : 'certificate_authority',
  sent: 1, responses: profile === 'peer' ? 1 : 0, failed: profile === 'peer' ? 0 : 1,
  blocked: 0, overflow: false, csp: profile === 'peer', sandbox: profile === 'peer' });
const proof = () => ({ format: 'stead-checkpoint-a-tls-proof-v1', passed: true, phase: 'complete',
  networkIsolated: true, browserCleanup: true, trials: TLS_PROFILES.map(trial) });
function fixture(job) {
  const directory = mkdtempSync(path.join(tmpdir(), 'stead-tls-unit-'));
  try { return job(directory); } finally { rmSync(directory, { recursive: true }); }
}

test('diagnostic imports are inert and distinct from the browser journey entry point', () => {
  assert.equal(typeof controller, 'function'); assert.equal(typeof diagnostic, 'function');
});
test('journey and peer profiles use P,, while the explicit comparison alone uses C,,', () => {
  const homes = new Set();
  for (const profile of ['journey', ...TLS_PROFILES]) {
    const { home, database, commands } = serverTrustCommands(profile);
    assert.ok(!homes.has(home)); homes.add(home);
    assert.equal(database, home + '/.local/share/pki/nssdb');
    assert.deepEqual(commands[0], ['-N', '--empty-password', '-d', 'sql:' + database]);
    if (profile === 'untrusted') assert.equal(commands.length, 1);
    else assert.deepEqual(commands[1], ['-A', '-d', 'sql:' + database, '-n', 'stead-fresh-local-instance',
      '-t', profile === 'ca' ? 'C,,' : 'P,,', '-i', '/fixture/localhost.crt']);
  }
  for (const value of ['custom', '../trusted', '', {}, undefined]) assert.throws(() => serverTrustCommands(value));
});
test('TLS admission retains exact identity/reviews but cannot authorize the real browser path', () => {
  assert.deepEqual(validateTLSAdmission(admission(), now), admission());
  assert.throws(() => validateAdmission(admission(), now));
  for (const mutate of [
    (a) => { a.status = 'proposed'; }, (a) => { a.scope = 'one-fresh-real-checkpoint-a-browser-run'; },
    (a) => { a.format = 'stead-checkpoint-a-browser-admission-v1'; },
    (a) => { a.files = Object.fromEntries(SOURCE_FILES.map((file) => [file, digest])); },
    (a) => { a.files.extra = digest; }, (a) => { a.reviews[1].reviewer = a.reviews[0].reviewer; },
    (a) => { a.instance.key = '/private/key'; }, (a) => { a.credential = '/private/token'; },
    (a) => { a.source.head = '--help'; }, (a) => { a.expiresAt = '2026-09-05T00:00:00.000Z'; },
  ]) { const value = admission(); mutate(value); assert.throws(() => validateTLSAdmission(value, now)); }
});
test('credential-free staging has only a fixed diagnostic executable and no session ingress file', () => fixture((directory) => {
  const value = admission();
  value.files = Object.fromEntries(TLS_SOURCE_FILES.map((file) => [file, sha256(readFileSync(path.join(repo, file)))]));
  const staged = stage({ files: [] }, directory, value, Buffer.from('public owned certificate fixture'), undefined, true);
  assert.deepEqual(staged.args.slice(-2), ['/usr/bin/node', '/runner/tests/e2e/checkpoint_a_tls.mjs']);
  assert.deepEqual(readdirSync(path.join(directory, 'execution-root/fixture')), ['localhost.crt']);
  assert.deepEqual(readdirSync(staged.work), []);
  assert.ok(staged.args.includes('--unshare-all') && staged.args.includes('--cap-drop'));
  assert.ok(!staged.args.some((arg) => /token|cookie|\.key|dev\.env|session-binding/.test(arg)));
  assert.throws(() => stage({ files: [] }, directory, value, Buffer.from('public'), {}, true));
  assert.throws(() => stage({ files: [] }, directory, value, Buffer.from('public')));
}));
test('diagnostic claim is separate private exclusive evidence and never touches application attempt state', () => fixture((directory) => {
  const admitted = path.join(directory, 'diagnostic.json'); writeFileSync(admitted, '{}', { mode: 0o600 });
  const original = path.join(directory, 'checkpoint-a-browser-attempt.json');
  writeFileSync(original, 'preserved first failed browser marker', { mode: 0o600 });
  const marker = claimTLSDiagnostic(admitted, { scope: TLS_SCOPE });
  assert.equal(lstatSync(marker).mode & 0o777, 0o600);
  assert.throws(() => claimTLSDiagnostic(admitted, { scope: TLS_SCOPE }));
  assert.equal(readFileSync(original, 'utf8'), 'preserved first failed browser marker');
}));
test('only one fixed document GET is routable; API mutations assets and hostname tricks are blocked', () => {
  for (const profile of TLS_PROFILES) {
    const target = (profile === 'wrong_name' ? WRONG_ORIGIN : ORIGIN) + '/';
    assert.equal(tlsNavigationAllowed(profile, 'GET', target, 'document', true), true);
    for (const args of [ ['POST', target, 'document', true], ['GET', target + 'api/v1/session', 'document', true],
      ['GET', target, 'script', false], ['GET', target, 'document', false], ['GET', target + '?probe=1', 'document', true],
      ['GET', 'https://localhost:18000/', 'document', true], ['GET', target.replace('https:', 'http:'), 'document', true],
      ['GET', 'https://foreign.invalid:18443/', 'document', true] ]) assert.equal(tlsNavigationAllowed(profile, ...args), false);
    const options = launchOptions(profile);
    assert.equal(options.chromiumSandbox, true);
    assert.ok(!options.args.some((arg) => /ignore-certificate|insecure-localhost|no-sandbox|proxy-server|disable-web-security/.test(arg)));
    assert.deepEqual(options.args.filter((arg) => arg.startsWith('--host-resolver-rules')),
      profile === 'wrong_name' ? ['--host-resolver-rules=' + WRONG_HOST_RULE] : []);
  }
  assert.throws(() => launchOptions('arbitrary-host'));
});
test('navigation errors emit only a closed category and never retain raw messages', () => {
  const entries = [['net::ERR_CERT_AUTHORITY_INVALID at fixed origin', 'certificate_authority'],
    ['net::ERR_CERT_COMMON_NAME_INVALID', 'certificate_name'], ['net::ERR_CERT_DATE_INVALID', 'certificate_date'],
    ['net::ERR_CERT_INVALID', 'certificate_other'], ['net::ERR_SSL_PROTOCOL_ERROR', 'tls'],
    ['net::ERR_CONNECTION_REFUSED', 'connection'], ['Timeout 12000ms exceeded', 'timeout'],
    ['private raw error body must not persist', 'other'], ['x'.repeat(8193), 'other']];
  for (const [message, category] of entries) {
    const actual = classifyTLSError(new Error(message)); assert.equal(actual, category);
    assert.ok(TLS_ERRORS.includes(actual)); assert.ok(!actual.includes('private'));
  }
  assert.equal(classifyTLSError(undefined), 'other');
});
test('a TLS proof requires all four real outcomes and excludes DOM errors headers and fabricated passes', () => {
  assert.deepEqual(validateTLSProof(proof()), proof());
  for (const mutate of [
    (p) => { p.trials.pop(); }, (p) => { p.trials[0].error = 'connection'; },
    (p) => { p.trials[1].status = 200; }, (p) => { p.trials[2].csp = false; },
    (p) => { p.trials[2].sandbox = false; }, (p) => { p.trials[3].error = 'certificate_authority'; },
    (p) => { p.trials[3].overflow = true; }, (p) => { p.trials[3].sent = 2; },
    (p) => { p.browserCleanup = false; }, (p) => { p.trials[0].headers = {}; },
    (p) => { p.trials[0].rawError = 'forbidden'; }, (p) => { p.dom = 'forbidden'; },
  ]) { const value = proof(); mutate(value); assert.throws(() => validateTLSProof(value)); }
  assert.equal(trialPass({ ...trial('peer'), error: 'certificate_name' }), false);
  const caContradiction = proof(); caContradiction.trials[1] = { ...trial('peer'), profile: 'ca' };
  assert.deepEqual(validateTLSProof(caContradiction), caContradiction);
  const firstFailure = { ...proof(), passed: false, phase: 'navigation', trials: [{ ...trial('untrusted'), error: 'connection' }] };
  assert.deepEqual(validateTLSProof(firstFailure), firstFailure);
});
