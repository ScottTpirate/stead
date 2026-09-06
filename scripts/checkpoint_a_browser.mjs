// One-shot real Checkpoint A workload. No tool download or implicit admission.
import { readFileSync, lstatSync, mkdirSync, mkdtempSync, copyFileSync, chmodSync,
  writeFileSync, existsSync, constants } from 'node:fs';
import { createServer, connect } from 'node:net';
import { connect as tlsConnect } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { pathToFileURL, fileURLToPath } from 'node:url';
import path from 'node:path';
import { check, sha256, readBounded, privateDirectory, noSymlinks, validateAdmission,
  validateInnerProof, claimAttempt, byteBudget, SOURCE_FILES, OUTER_NODE, INPUTS,
  INPUTS_SHA256, FORBIDDEN_STATE } from './checkpoint_a_browser_boundary.mjs';

const environment = { PATH: '/usr/bin', HOME: '/home/controller', LANG: 'C.UTF-8', TZ: 'UTC', FONTCONFIG_FILE: '/fixture/fonts.conf' };
const REPO = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const digestFile = (file, options) => sha256(readBounded(file, 512 * 1024 * 1024, options));
function git(repository, args) {
  const run = spawnSync('/usr/bin/git', ['--no-optional-locks', '-C', repository, ...args], {
    env: { PATH: '/usr/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
    timeout: 5000, maxBuffer: 1 << 20, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'],
  });
  check(run.status === 0 && !run.error && !run.signal); return run.stdout.trim();
}
function verifyIdentity(admission) {
  const { source, instance } = admission;
  noSymlinks(source.repository); privateDirectory(instance.state);
  check(instance.state !== FORBIDDEN_STATE && source.repository === REPO);
  check(git(REPO, ['rev-parse', '--show-toplevel']) === REPO && git(REPO, ['rev-parse', 'HEAD']) === source.head);
  check(git(REPO, ['status', '--porcelain', '--untracked-files=normal']) === '');
  check(git(REPO, ['rev-parse', `${source.implementationRevision}^{tree}`]) === source.implementationTree);
  git(REPO, ['merge-base', '--is-ancestor', source.implementationRevision, source.head]);
  const changed = git(REPO, ['diff', '--no-ext-diff', '--name-only', source.implementationRevision, source.head]).split('\n').filter(Boolean).sort();
  check(changed.length <= 2 && changed.every((file) => ['modules/authorization/localdata/approved-template.json', 'docs/governance/local-development-template-review.json'].includes(file)));
  for (const [file, digest] of Object.entries(admission.files)) check(digestFile(path.join(REPO, file)) === digest);
  const templateFile = path.join(REPO, 'modules/authorization/localdata/approved-template.json');
  const reviewFile = path.join(REPO, 'docs/governance/local-development-template-review.json');
  check(digestFile(templateFile) === source.templateSHA256 && digestFile(reviewFile) === source.templateReviewSHA256);
  const template = JSON.parse(readBounded(templateFile, 1 << 20)), review = JSON.parse(readBounded(reviewFile, 1 << 20));
  check(template.status === 'approved' && review.status === 'accepted' && template.core.source_revision === source.implementationRevision && template.core.source_tree === source.implementationTree);
  check(review.source_revision === source.implementationRevision && review.source_tree === source.implementationTree);
  check(digestFile(path.join(instance.state, 'stead-api')) === source.apiSHA256);
  const bootstrapBytes = readBounded(path.join(instance.state, 'bootstrap.json'), 16384, { privateMode: true });
  check(sha256(bootstrapBytes) === instance.bootstrapSHA256);
  const bootstrap = JSON.parse(bootstrapBytes);
  check(bootstrap.schema_version === '1.0.0' && bootstrap.development_only === true && bootstrap.security_domain === 'stead-local-development');
  check(bootstrap.instance_id === instance.instanceID && bootstrap.activation_digest === instance.activationDigest);
  const ids = ['instance_id', 'principal_id', 'session_id', 'unprivileged_principal_id', 'unprivileged_session_id', 'label_id'].map((field) => bootstrap[field]);
  check(ids.every((id) => typeof id === 'string' && /^[a-f0-9]{8}-(?:[a-f0-9]{4}-){3}[a-f0-9]{12}$/.test(id)) && new Set(ids).size === ids.length);
  const running = JSON.parse(readBounded(path.join(instance.state, 'running.json'), 16384, { privateMode: true }));
  check(running.ready === true && running.stopped !== true && running.repository === REPO && Number.isSafeInteger(running.pid) && running.pid > 1);
  const stat = readFileSync(`/proc/${running.pid}/stat`, 'utf8'); check(stat.length < 8192);
  check(stat.slice(stat.lastIndexOf(') ') + 2).trim().split(/\s+/)[19] === running.startTime);
  const cmdline = readFileSync(`/proc/${running.pid}/cmdline`); check(cmdline.length < 8192);
  const args = cmdline.toString('utf8').split('\0').filter(Boolean);
  check(args.length === 3 && args[0] === OUTER_NODE && args[1] === path.join(REPO, 'scripts/dev_stack.mjs') && args[2] === '__run');
  for (const marker of ['checkpoint-a-browser-attempt.json', 'checkpoint-a-cookie.json', 'checkpoint-a-progress.json', 'unprivileged-session-cookie']) check(!existsSync(path.join(instance.state, marker)));
  const certificate = readBounded(path.join(instance.state, 'tls/localhost.crt'), 16384, { privateMode: true });
  check(sha256(certificate) === instance.certificateSHA256);
  return certificate;
}
async function verifyTLSPeer(certificate) {
  const expected = new X509Certificate(certificate);
  check(expected.checkHost('localhost') === 'localhost');
  await new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: '127.0.0.1', port: 18443, servername: 'localhost', ca: certificate,
      rejectUnauthorized: true, minVersion: 'TLSv1.2' });
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('tls_timeout')); }, 3000);
    socket.once('error', () => { clearTimeout(timer); socket.destroy(); reject(new Error('tls_identity')); });
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const valid = socket.authorized && socket.getPeerCertificate().raw?.equals(expected.raw);
      socket.destroy(); if (valid) resolve(); else reject(new Error('tls_identity'));
    });
  });
}
function verifyInputs() {
  const bytes = readBounded(INPUTS, 1 << 20); check(sha256(bytes) === INPUTS_SHA256);
  const inputs = JSON.parse(bytes);
  check(inputs.files.length === 512 && inputs.host.length === 15);
  const verify = (entry, host = false) => {
    const owner = host && entry.path !== OUTER_NODE ? 0 : process.getuid();
    const bytes = readBounded(entry.path, 512 * 1024 * 1024, { owner });
    check(bytes.length === entry.bytes && sha256(bytes) === entry.sha256);
  };
  inputs.files.forEach((entry) => verify(entry)); inputs.host.forEach((entry) => verify(entry, true));
  check(process.execPath === OUTER_NODE && process.execArgv.length === 0 && process.getuid() !== 0);
  check(inputs.host.find((entry) => entry.path === OUTER_NODE)?.sha256 === '19235a9b678f84729464c52623f92de130a165452747c6826d3fdc13df3abcc3');
  check(inputs.host.find((entry) => entry.path === '/usr/bin/bwrap')?.sha256 === '6ad2138a73d592acb43525432965e3c66f6fad8a2f3d610c6ca0b6855e993cbe');
  check(digestFile(inputs.nativeSelection.path) === inputs.nativeSelection.sha256);
  check(digestFile('/home/skilgore/stead-browser-axe-intake.kTB8mQ/USER_TERMS_ACCEPTANCE.md') === inputs.consentSHA256);
  return inputs;
}
function stage(inputs, directory, admission, certificate) {
  const ready = path.join(directory, 'execution-root'), work = path.join(directory, 'work');
  mkdirSync(ready, { mode: 0o700 }); mkdirSync(work, { mode: 0o700 });
  const selected = inputs.files.filter((entry) => !['/fixture/compatibility.test.mjs', '/fixture/https-fixture'].includes(entry.destination));
  for (const file of SOURCE_FILES.filter((file) => file.endsWith('.mjs'))) selected.push({ path: path.join(REPO, file), destination: '/runner/' + file, sha256: admission.files[file], executable: false });
  const extra = [
    { name: 'localhost.crt', data: certificate },
    { name: 'axe-pin.json', data: Buffer.from(JSON.stringify({ sha256: inputs.files.find((entry) => entry.destination === '/tools/axe-core/axe.min.js').sha256 })) },
  ];
  for (const entry of extra) {
    const file = path.join(directory, entry.name); writeFileSync(file, entry.data, { mode: 0o600, flag: 'wx' });
    selected.push({ path: file, destination: '/fixture/' + entry.name, sha256: sha256(entry.data), executable: false });
  }
  const directories = new Set(['/etc', '/usr', '/usr/bin', '/usr/lib', '/lib64', '/browser', '/tools', '/fixture', '/runner']);
  const seen = new Set(), bindings = [], copies = [];
  for (const entry of selected) {
    const target = entry.destination;
    check(/^\/(?:browser|usr|lib64|tools|fixture|etc|runner)\//.test(target) && path.posix.normalize(target) === target && !seen.has(target));
    seen.add(target); let parent = path.posix.dirname(target);
    while (parent !== '/') { directories.add(parent); parent = path.posix.dirname(parent); }
    const copy = path.join(ready, target.slice(1)); mkdirSync(path.dirname(copy), { recursive: true, mode: 0o700 });
    copyFileSync(entry.path, copy, constants.COPYFILE_EXCL); chmodSync(copy, entry.executable ? 0o755 : 0o644);
    check(digestFile(copy) === entry.sha256); copies.push({ path: copy, sha256: entry.sha256 });
    bindings.push('--ro-bind', copy, target);
  }
  const mkdirs = [...directories].sort((a, b) => a.split('/').length - b.split('/').length || a.localeCompare(b)).flatMap((directory) => ['--dir', directory]);
  return { work, copies, args: ['--tmpfs', '/', '--unshare-all', '--unshare-user', '--uid', '1000', '--gid', '1000',
    '--cap-drop', 'ALL', '--new-session', '--die-with-parent', '--as-pid-1', ...mkdirs, ...bindings,
    '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--tmpfs', '/home', '--dir', '/home/controller',
    '--bind', work, '/work', '--bind', path.join(directory, 'relay.sock'), '/relay.sock', '--chdir', '/work', '--remount-ro', '/',
    '/usr/bin/node', '/runner/tests/e2e/checkpoint_a_browser.mjs'] };
}
async function relay(socketPath) {
  const budget = byteBudget(), sockets = new Set(); let count = 0, failed = false;
  const server = createServer((incoming) => {
    if (++count > 256 || sockets.size >= 64) { failed = true; incoming.destroy(); return; }
    // No caller-supplied address, HTTP CONNECT, TLS termination or DNS lookup.
    const outgoing = connect({ host: '127.0.0.1', port: 18443 });
    for (const socket of [incoming, outgoing]) {
      sockets.add(socket); socket.setTimeout(30_000, () => socket.destroy());
      socket.on('error', () => { incoming.destroy(); outgoing.destroy(); });
      socket.once('close', () => sockets.delete(socket));
      socket.on('data', (chunk) => { if (!budget.add(chunk.length)) { failed = true; incoming.destroy(); outgoing.destroy(); } });
    }
    incoming.pipe(outgoing); outgoing.pipe(incoming);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  chmodSync(socketPath, 0o600); server.on('error', () => { failed = true; });
  return { good: () => !failed && !budget.exceeded,
    close: async () => { sockets.forEach((socket) => socket.destroy()); await new Promise((resolve) => server.close(resolve)); } };
}
async function execute(args, credentials) {
  return new Promise((resolve) => {
    const child = spawn('/usr/bin/bwrap', args, { env: environment, detached: true, stdio: ['pipe', 'ignore', 'ignore'] });
    const timer = setTimeout(() => { try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 300_000);
    child.on('error', () => { clearTimeout(timer); resolve(false); });
    child.once('close', (code, signal) => { clearTimeout(timer); resolve(code === 0 && signal === null); });
    child.stdin.on('error', () => {}); child.stdin.end(credentials);
  });
}
export async function main(argv = process.argv.slice(2)) {
  let phase = 'preflight', directory, transport, inputs, staged, admissionBytes, admission, inner = null;
  let passed = false, inputsUnchanged = false, credentials;
  try {
    check(argv.length === 2 && argv[0] === '--review');
    check(!Object.keys(process.env).some((name) => !['PATH', 'LANG', 'TZ'].includes(name)));
    check(/^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$/m.test(readFileSync('/proc/self/limits', 'utf8')));
    admissionBytes = readBounded(argv[1], 32768, { privateMode: true });
    admission = validateAdmission(JSON.parse(admissionBytes));
    for (const review of admission.reviews) check(digestFile(review.path) === review.sha256);
    inputs = verifyInputs();
    phase = 'identity'; const certificate = verifyIdentity(admission);
    phase = 'tls'; await verifyTLSPeer(certificate);
    // A failed or interrupted attempt is not automatically reusable. This record
    // is intentionally retained even when no login was dispatched.
    phase = 'attempt'; claimAttempt(admission.instance.state, { format: 'stead-checkpoint-a-browser-attempt-v1',
      admissionSHA256: sha256(admissionBytes), instanceID: admission.instance.instanceID, sourceRevision: admission.source.head, startedAt: new Date().toISOString() });
    directory = mkdtempSync('/home/skilgore/stead-checkpoint-a-browser-run.'); chmodSync(directory, 0o700);
    phase = 'staging'; staged = stage(inputs, directory, admission, certificate);
    transport = await relay(path.join(directory, 'relay.sock'));
    const primary = readBounded(path.join(admission.instance.state, 'one-time-login-token'), 43, { privateMode: true });
    const denied = readBounded(path.join(admission.instance.state, 'one-time-unprivileged-login-token'), 43, { privateMode: true });
    try {
      check(primary.length === 43 && denied.length === 43 && !primary.equals(denied));
      check(/^[A-Za-z0-9_-]{43}$/.test(primary.toString()) && /^[A-Za-z0-9_-]{43}$/.test(denied.toString()));
      credentials = Buffer.from(JSON.stringify({ primary: primary.toString(), denied: denied.toString() }));
    } finally { primary.fill(0); denied.fill(0); }
    phase = 'namespace'; const completed = await execute(staged.args, credentials); credentials.fill(0); credentials = undefined;
    inner = validateInnerProof(JSON.parse(readBounded(path.join(staged.work, 'result.json'), 65536, { privateMode: true })));
    passed = completed && inner.passed && transport.good();
    phase = inner.phase;
  } catch { passed = false; } // No exception strings, native output or secret logs.
  finally {
    credentials?.fill(0);
    try { if (transport) await transport.close(); } catch { passed = false; }
    if (admission && inputs && staged) {
      try {
        verifyInputs(); check(sha256(readBounded(argv[1], 32768, { privateMode: true })) === sha256(admissionBytes));
        staged.copies.forEach((entry) => check(digestFile(entry.path) === entry.sha256));
        for (const file of SOURCE_FILES) check(digestFile(path.join(REPO, file)) === admission.files[file]);
        inputsUnchanged = true;
      } catch { passed = false; }
    }
  }
  const report = { format: 'stead-checkpoint-a-browser-run-v1', passed: passed && inputsUnchanged, phase,
    inputsUnchanged, inputsSHA256: INPUTS_SHA256, admissionSHA256: admissionBytes ? sha256(admissionBytes) : null,
    sourceRevision: admission?.source.head ?? null, instanceID: admission?.instance.instanceID ?? null,
    scope: 'real-ui-only-not-sql-provider-or-release-proof', proof: inner };
  if (directory) writeFileSync(path.join(directory, 'result.json'), JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
  // Path is controller-generated, never a browser/provider/exception value.
  process.stdout.write(JSON.stringify({ passed: report.passed, phase, resultDirectory: directory ?? null }) + '\n');
  process.exitCode = report.passed ? 0 : 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.stdout.write('{"passed":false,"phase":"cleanup"}\n'); process.exitCode = 1; });
}
