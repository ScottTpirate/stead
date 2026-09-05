#!/usr/bin/env node
// SPDX-License-Identifier: Apache-2.0
import { randomBytes } from 'node:crypto';
import { spawn, spawnSync } from 'node:child_process';
import { createWriteStream, appendFileSync, readdirSync, readlinkSync } from 'node:fs';
import { mkdir, mkdtemp, readFile, writeFile, lstat, realpath, access } from 'node:fs/promises';
import { request } from 'node:https';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { acquireImage, sha256 } from './dev_image.mjs';
import { serviceNames, servicePorts as ports, postgresURL, giteaConfig, natsConfig, openfgaEnvironment } from './dev_stack_config.mjs';

const repository = await realpath(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..'));
let state = path.join(repository, '.cache', 'stead-dev');
const pins = JSON.parse(await readFile(path.join(repository, 'deploy/compose/dev-services.json'), 'utf8'));
const delay = (milliseconds) => new Promise((resolve) => setTimeout(resolve, milliseconds));
const baseEnvironment = { PATH: '/usr/local/bin:/usr/bin:/bin', LANG: 'C.UTF-8' };

async function privateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const info = await lstat(directory);
  if (!info.isDirectory() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077)) {
    throw new Error('Development state must be a private directory owned by the current user');
  }
  if ((await realpath(directory)) !== directory) throw new Error('Development state must not traverse symlinks');
}

async function privateFile(name, contents, exclusive = false) {
  const filename = path.join(state, name);
  try {
    const info = await lstat(filename);
    if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077)) throw new Error('Refusing to overwrite an unsafe development file');
  } catch (error) { if (error.code !== 'ENOENT') throw error; }
  await writeFile(filename, contents, { mode: 0o600, flag: exclusive ? 'wx' : 'w' });
}

async function readPrivate(name) {
  const filename = path.join(state, name);
  const info = await lstat(filename);
  if (!info.isFile() || info.isSymbolicLink() || info.uid !== process.getuid() || (info.mode & 0o077)) throw new Error('Invalid private development file');
  return readFile(filename, 'utf8');
}

async function secretState() {
  await privateDirectory(state);
  try {
    const result = JSON.parse(await readPrivate('secrets.json'));
    if (result.repository !== repository) throw new Error('Development credentials belong to another checkout');
    if (result.securityDomain !== 'stead-local-development') throw new Error('Development state does not match the reviewed fixed policy domain');
    for (const name of ['adminPassword', 'apiPassword', 'giteaPassword', 'openfgaPassword', 'openfgaKey', 'natsPublisher', 'natsConsumer', 'natsMaintenance', 'giteaSecret', 'giteaInternalToken']) {
      if (!/^[a-f0-9]{64}$/.test(result[name])) throw new Error('Invalid generated development credential format');
    }
    return result;
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  const names = ['adminPassword', 'apiPassword', 'giteaPassword', 'openfgaPassword', 'openfgaKey', 'natsPublisher', 'natsConsumer', 'natsMaintenance', 'giteaSecret', 'giteaInternalToken'];
  const secret = Object.fromEntries(names.map((name) => [name, randomBytes(32).toString('hex')]));
  const time = Date.now().toString(16).padStart(12, '0');
  const rest = randomBytes(10).toString('hex');
  secret.instanceID = `${time.slice(0, 8)}-${time.slice(8)}-7${rest.slice(0, 3)}-8${rest.slice(3, 6)}-${rest.slice(6, 18)}`;
  secret.repository = repository;
  secret.securityDomain = 'stead-local-development';
  await privateFile('secrets.json', JSON.stringify(secret), true);
  return secret;
}

function checkedCommand(command, args, options = {}) {
  const result = spawnSync(command, args, { cwd: repository, env: baseEnvironment, stdio: 'inherit', ...options });
  if (result.status !== 0) {
    const diagnostic = String(result.stderr ?? result.error?.code ?? '').replace(/[a-f0-9]{64}/g, '[REDACTED]').replace(/(postgres(?:ql)?:\/\/)[^@\s]+@/g, '$1[REDACTED]@');
    appendFileSync(path.join(state, 'command-failure.log'), `${path.basename(command)}: ${diagnostic}\n`, { mode: 0o600 });
    throw new Error(`Development command failed: ${path.basename(command)}; inspect private command-failure.log`);
  }
  return result;
}

function requireApproval() {
  for (const [name, pin] of Object.entries(pins.services)) {
    if (pin.review !== 'approved') throw new Error(`${name} exact candidate still requires recorded independent review/activation`);
  }
}

async function prepare(intakeOnly = false) {
  if (!intakeOnly) requireApproval();
  await privateDirectory(state);
  await privateDirectory(path.join(state, 'images'));
  const roots = {};
  for (const [name, pin] of Object.entries(pins.services)) {
    if (!pin.image) continue;
    console.log(`Preparing pinned non-distributed ${name} ${pin.version}`);
    roots[name] = (await acquireImage(pin.image, path.join(state, 'images'))).rootfs;
  }
  const fga = pins.services.openfga;
  const source = path.join(state, 'openfga-source');
  try { await access(path.join(source, '.git')); } catch {
    checkedCommand('git', ['clone', '--filter=blob:none', '--no-checkout', fga.source, source]);
    checkedCommand('git', ['-C', source, 'checkout', '--detach', fga.commit]);
  }
  const revision = checkedCommand('git', ['-C', source, 'rev-parse', 'HEAD'], { encoding: 'utf8', stdio: 'pipe' }).stdout.trim();
  const dirty = checkedCommand('git', ['-C', source, 'status', '--porcelain'], { encoding: 'utf8', stdio: 'pipe' }).stdout;
  if (revision !== fga.commit || dirty) throw new Error('OpenFGA source differs from the reviewed stock revision');
  checkedCommand(path.join(repository, 'scripts/run_pinned_go.sh'), ['go', '-C', source, 'build', '-mod=readonly', '-trimpath', `-ldflags=-X github.com/openfga/openfga/internal/build.Version=${fga.version} -X github.com/openfga/openfga/internal/build.Commit=${fga.commit} -X github.com/openfga/openfga/internal/build.Date=${fga.commit_date}`, '-o', path.join(state, 'openfga'), './cmd/openfga'], { env: { ...baseEnvironment, CGO_ENABLED: '0', GOTOOLCHAIN: 'local' } });
  if (sha256(await readFile(path.join(state, 'openfga'))) !== fga.binary_sha256) throw new Error('Rebuilt OpenFGA binary differs from reviewed bytes');
  for (const [binary, sourcePath] of intakeOnly ? [] : [['stead-api', './apps/core'], ['stead-worker', './apps/worker']]) {
    checkedCommand(path.join(repository, 'scripts/run_pinned_go.sh'), ['go', 'build', '-mod=readonly', '-o', path.join(state, binary), sourcePath], { env: { ...baseEnvironment, CGO_ENABLED: '0', GOTOOLCHAIN: 'local' } });
  }
  if (!intakeOnly) {
    checkedCommand(path.join(repository, 'scripts/run_pinned_node.sh'), ['npm', 'ci', '--ignore-scripts', '--no-audit', '--no-fund']);
    checkedCommand(path.join(repository, 'scripts/run_pinned_node.sh'), ['npm', 'run', 'build']);
  }
  await privateFile('roots.json', JSON.stringify(roots));
}

function sandbox(rootfs, uid, command, args = [], binds = []) {
  // A temporary root lets scratch images receive standard /proc, /dev and /tmp
  // mount points. Every image entry remains read-only; seal the root after adding
  // the explicit service mounts. Never bind the workstation root into a service.
  const imageMounts = readdirSync(rootfs, { withFileTypes: true }).filter((entry) => !['proc', 'dev', 'tmp'].includes(entry.name)).flatMap((entry) => entry.isSymbolicLink()
    ? ['--symlink', readlinkSync(path.join(rootfs, entry.name)), `/${entry.name}`]
    : ['--ro-bind', path.join(rootfs, entry.name), `/${entry.name}`]);
  return ['--tmpfs', '/', ...imageMounts, '--unshare-all', '--share-net', '--uid', String(uid), '--gid', String(uid), '--cap-drop', 'ALL', '--proc', '/proc', '--dev', '/dev', '--tmpfs', '/tmp', '--new-session', '--die-with-parent', '--as-pid-1', ...binds.flatMap(([source, target, writable]) => [writable ? '--bind' : '--ro-bind', source, target]), '--remount-ro', '/', command, ...args];
}

async function portAvailable(port) {
  const server = net.createServer();
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(port, '127.0.0.1', resolve); });
  await new Promise((resolve) => server.close(resolve));
}

async function processIdentity(pid) {
  const stat = await readFile(`/proc/${pid}/stat`, 'utf8');
  return stat.slice(stat.lastIndexOf(')') + 2).split(' ')[19];
}

async function status() {
  try {
    const current = JSON.parse(await readPrivate('running.json'));
    if (current.repository !== repository || await processIdentity(current.pid) !== current.startTime) return { running: false };
    const command = await readFile(`/proc/${current.pid}/cmdline`, 'utf8');
    if (!command.includes(fileURLToPath(import.meta.url)) || !command.includes('__run')) return { running: false };
    return { running: true, ...current };
  } catch (error) {
    if (['ENOENT', 'ESRCH'].includes(error.code)) return { running: false };
    throw error;
  }
}

async function httpProbe(name, url, tls = false) {
  const started = performance.now();
  if (tls) {
    const ca = await readFile(path.join(state, 'tls', 'localhost.crt'));
    await new Promise((resolve, reject) => {
      const call = request(url, { ca, timeout: 5000 }, (response) => { response.resume(); response.once('end', () => response.statusCode === 200 ? resolve() : reject(new Error(`${name} not ready`))); });
      call.once('error', reject); call.once('timeout', () => call.destroy(new Error('Probe timeout'))); call.end();
    });
  } else {
    const response = await fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) });
    if (!response.ok) throw new Error(`${name} not ready`);
    await response.arrayBuffer();
  }
  return { service: name, ready: true, milliseconds: Math.round((performance.now() - started) * 100) / 100 };
}

async function smoke() {
  const result = await status();
  if (!result.running || result.ready !== true) throw new Error('Development supervisor is not ready');
  const evidence = [];
  // PostgreSQL readiness is the API's real pool check, not a schema mutation.
  for (const [name, url, tls] of [
    ['gitea', `http://127.0.0.1:${ports.gitea}/api/healthz`],
    ['openfga', `http://127.0.0.1:${ports.openfga}/healthz`],
    ['nats', `http://127.0.0.1:${ports.natsMonitor}/healthz`],
    ['stead-api', `http://127.0.0.1:${ports.api}/health/ready`],
    ['stead-worker', `http://127.0.0.1:${ports.worker}/health/ready`],
    ['stead-web', `https://localhost:${ports.web}/`, true],
    ['browser-to-bff', `https://localhost:${ports.web}/health/ready`, true],
  ]) evidence.push(await httpProbe(name, url, tls));
  console.log(JSON.stringify({ scope: 'local-stack-health-not-golden-product-journey', services: serviceNames, probes: evidence }));
}

async function run(intakeOnly = false) {
  if (!intakeOnly) requireApproval();
  const secret = await secretState();
  const roots = JSON.parse(await readPrivate('roots.json'));
  const children = [];
  let stopping = false;
  const running = { repository, pid: process.pid, startTime: await processIdentity(process.pid), ready: false, services: serviceNames };
  await privateFile('running.json', JSON.stringify(running));
  const stop = async () => {
    if (stopping) return;
    stopping = true;
    for (const child of [...children].reverse()) {
      if (child.exitCode !== null) continue;
      try { process.kill(child.innerPid ?? child.pid, 'SIGTERM'); } catch {}
      const exited = await Promise.race([new Promise((resolve) => child.once('exit', () => resolve(true))), delay(15_000).then(() => false)]);
      if (!exited) { child.kill('SIGKILL'); console.error('Service exceeded graceful shutdown deadline'); }
    }
    await privateFile('running.json', JSON.stringify({ ...running, ready: false, stopped: true }));
  };
  process.on('SIGTERM', () => { void stop().then(() => process.exit(0)); });
  process.on('SIGINT', () => { void stop().then(() => process.exit(0)); });
  function start(name, command, args, environment, isSandbox = false) {
    const log = createWriteStream(path.join(state, `${name}.log`), { flags: 'a', mode: 0o600 });
    const actualArgs = isSandbox ? ['--json-status-fd', '3', ...args] : args;
    const child = spawn(command, actualArgs, { cwd: repository, env: { ...baseEnvironment, ...environment }, stdio: ['ignore', 'pipe', 'pipe', ...(isSandbox ? ['pipe'] : [])] });
    child.stdout.pipe(log, { end: false }); child.stderr.pipe(log, { end: false });
    if (isSandbox) {
      let text = '';
      child.stdio[3].on('data', (chunk) => {
        text += chunk;
        const lines = text.split('\n'); text = lines.pop();
        for (const line of lines) { try { const event = JSON.parse(line); if (event['child-pid']) child.innerPid = event['child-pid']; } catch {} }
      });
    }
    children.push(child);
    child.once('error', () => { console.error(`${name} failed to start`); void stop().then(() => process.exit(1)); });
    child.once('exit', () => { log.end(); if (!stopping) { console.error(`${name} stopped unexpectedly; inspect private log`); void stop().then(() => process.exit(1)); } });
    return child;
  }
  const waitHTTP = async (name, url, tls) => {
    for (let attempt = 0; attempt < 120; attempt++) {
      if (stopping) throw new Error('Development startup stopped');
      try { await httpProbe(name, url, tls); return; } catch { await delay(500); }
    }
    throw new Error(`${name} readiness deadline exceeded; inspect its private log`);
  };
  try {
    for (const directory of ['postgres', 'postgres-socket', 'gitea', 'gitea-config', 'nats', 'tls', 'policy']) await privateDirectory(path.join(state, directory));
    await privateFile('gitea-config/app.ini', giteaConfig(secret));
    await privateFile('nats.conf', natsConfig(secret));
    await privateFile('openfga-key', secret.openfgaKey);
    await privateFile('database-admin-url', postgresURL('stead_bootstrap', secret.adminPassword, 'stead'));
    await privateFile('database-password', secret.apiPassword);
    await privateFile('nats-publisher.json', JSON.stringify({ url: `nats://127.0.0.1:${ports.nats}`, username: 'publisher', password: secret.natsPublisher }));
    await privateFile('nats-consumer.json', JSON.stringify({ url: `nats://127.0.0.1:${ports.nats}`, username: 'consumer', password: secret.natsConsumer }));
    await privateFile('nats-maintenance.json', JSON.stringify({ url: `nats://127.0.0.1:${ports.nats}`, username: 'maintenance', password: secret.natsMaintenance }));
    const pgEnvironment = { PATH: '/usr/bin:/bin:/usr/libexec/postgresql18', LANG: 'en_US.UTF-8', PGDATA: '/var/lib/postgresql/data', PG_MAJOR: '18', POSTGRES_USER: 'stead_bootstrap', POSTGRES_DB: 'stead', POSTGRES_PASSWORD: secret.adminPassword, POSTGRES_INITDB_ARGS: '--auth-local=scram-sha-256 --auth-host=scram-sha-256', POSTGRES_HOST_AUTH_METHOD: 'scram-sha-256' };
    const pgBinds = [[path.join(state, 'postgres'), '/var/lib/postgresql', true], [path.join(state, 'postgres-socket'), '/var/run/postgresql', true]];
    start('postgres', '/usr/bin/bwrap', sandbox(roots.postgres, 70, '/usr/bin/docker-entrypoint.sh', ['postgres', '-c', 'listen_addresses=127.0.0.1', '-c', `port=${ports.postgres}`, '-c', 'log_min_error_statement=panic'], pgBinds), pgEnvironment, true);
    for (let attempt = 0; ; attempt++) {
      const probe = spawnSync('/usr/bin/bwrap', sandbox(roots.postgres, 70, '/usr/bin/pg_isready', ['-q', '-h', '127.0.0.1', '-p', String(ports.postgres), '-U', 'stead_bootstrap', '-d', 'stead']), { env: pgEnvironment, stdio: 'ignore' });
      if (probe.status === 0) break;
      if (attempt >= 120 || stopping) throw new Error('PostgreSQL readiness deadline exceeded');
      await delay(500);
    }
    // Only the administrative init connection sees these three database roles.
    // Values are generated hex, never user input or shell-expanded SQL.
    const sql = String.raw`SELECT format('CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT PASSWORD %L', name, password) FROM (VALUES ('gitea','${secret.giteaPassword}'),('openfga','${secret.openfgaPassword}')) AS roles(name,password) WHERE NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname=name) \gexec
SELECT format('CREATE DATABASE %I OWNER %I', name, name) FROM (VALUES ('gitea'),('openfga')) AS databases(name) WHERE NOT EXISTS(SELECT 1 FROM pg_database WHERE datname=name) \gexec
REVOKE CONNECT ON DATABASE stead, gitea, openfga FROM PUBLIC;
REVOKE CONNECT ON DATABASE postgres, template1 FROM PUBLIC;
GRANT CONNECT ON DATABASE gitea TO gitea;
GRANT CONNECT ON DATABASE openfga TO openfga;
`;
    checkedCommand('/usr/bin/bwrap', sandbox(roots.postgres, 70, '/usr/bin/psql', ['--no-psqlrc', '-v', 'ON_ERROR_STOP=1', '-h', '127.0.0.1', '-p', String(ports.postgres), '-U', 'stead_bootstrap', '-d', 'stead']), { input: sql, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'], env: { ...pgEnvironment, PGPASSWORD: secret.adminPassword } });
    const fgaEnvironment = openfgaEnvironment(secret);
    const fgaArgs = sandbox(roots.postgres, 65532, '/openfga', ['migrate'], [[path.join(state, 'openfga'), '/openfga', false]]);
    checkedCommand('/usr/bin/bwrap', fgaArgs, { env: { ...baseEnvironment, ...fgaEnvironment }, stdio: 'pipe' });
    start('openfga', '/usr/bin/bwrap', sandbox(roots.postgres, 65532, '/openfga', ['run'], [[path.join(state, 'openfga'), '/openfga', false]]), fgaEnvironment, true);
    start('nats', '/usr/bin/bwrap', sandbox(roots.nats, 65532, '/nats-server', ['--config', '/nats.conf'], [[path.join(state, 'nats'), '/data', true], [path.join(state, 'nats.conf'), '/nats.conf', false]]), {}, true);
    start('gitea', '/usr/bin/bwrap', sandbox(roots.gitea, 1000, '/usr/bin/dumb-init', ['--', '/usr/local/bin/docker-entrypoint.sh'], [[path.join(state, 'gitea'), '/var/lib/gitea', true], [path.join(state, 'gitea-config'), '/etc/gitea', true]]), { PATH: '/usr/local/bin:/usr/bin:/bin', GITEA_WORK_DIR: '/var/lib/gitea', GITEA_CUSTOM: '/var/lib/gitea/custom', GITEA_TEMP: '/tmp/gitea', TMPDIR: '/tmp/gitea', GITEA_APP_INI: '/etc/gitea/app.ini', HOME: '/var/lib/gitea/git', GIT_SSH_COMMAND: '/bin/false', GIT_ALLOW_PROTOCOL: 'http:https:file' }, true);
    await waitHTTP('OpenFGA', `http://127.0.0.1:${ports.openfga}/healthz`);
    await waitHTTP('NATS', `http://127.0.0.1:${ports.natsMonitor}/healthz`);
    await waitHTTP('Gitea', `http://127.0.0.1:${ports.gitea}/api/healthz`);
    if (intakeOnly) {
      const unauthenticated = await fetch(`http://127.0.0.1:${ports.openfga}/stores`, { signal: AbortSignal.timeout(5000) });
      if (unauthenticated.status !== 401) throw new Error('OpenFGA must deny missing service credentials');
      const authenticated = await fetch(`http://127.0.0.1:${ports.openfga}/stores`, { headers: { Authorization: `Bearer ${secret.openfgaKey}` }, signal: AbortSignal.timeout(5000) });
      if (authenticated.status !== 200) throw new Error('OpenFGA must accept scoped development service credentials');
      await privateFile('intake-result.json', JSON.stringify({ scope: 'non-distributed-infrastructure-candidate-proof-not-approval', postgres: 'real SCRAM readiness', gitea: 'stock provider health', openfga: 'real PostgreSQL datastore; missing credential denied; private service credential accepted', nats: 'real JetStream health', rootless: true, listeners: '127.0.0.1 only', data: 'synthetic private fixture' }));
      console.log(`Infrastructure candidate proof passed; evidence retained at ${state}`);
      const hold = process.argv.find((value) => value.startsWith('--hold-seconds='));
      if (hold) {
        const seconds = Number(hold.split('=')[1]);
        if (!Number.isSafeInteger(seconds) || seconds < 1 || seconds > 300) throw new Error('Intake hold must be between1 and300 seconds');
        console.log(`Holding isolated synthetic candidate fixture for ${seconds} seconds for live protocol checks`);
        await delay(seconds * 1000);
      }
      await stop();
      return;
    }
    const environment = { STEAD_PUBLIC_ORIGIN: `https://localhost:${ports.web}`, STEAD_INSTANCE_ID: secret.instanceID, STEAD_SECURITY_DOMAIN: secret.securityDomain, STEAD_BOOTSTRAP_STATE_DIR: state, STEAD_DATABASE_URL_FILE: path.join(state, 'database-url'), STEAD_OPENFGA_URL: `http://127.0.0.1:${ports.openfga}`, STEAD_OPENFGA_TOKEN_FILE: path.join(state, 'openfga-key'), STEAD_POLICY_DIR: path.join(state, 'policy'), STEAD_TLS_CERT_FILE: path.join(state, 'tls/localhost.crt'), STEAD_TLS_KEY_FILE: path.join(state, 'tls/localhost.key') };
    checkedCommand(path.join(state, 'stead-api'), ['dev-bootstrap'], { env: { ...baseEnvironment, ...environment, STEAD_DATABASE_ADMIN_URL_FILE: path.join(state, 'database-admin-url'), STEAD_DATABASE_PASSWORD_FILE: path.join(state, 'database-password'), STEAD_INSTANCE_ID: secret.instanceID, STEAD_SECURITY_DOMAIN: secret.securityDomain, STEAD_BOOTSTRAP_STATE_DIR: state, STEAD_NATS_MAINTENANCE_FILE: path.join(state, 'nats-maintenance.json') }, stdio: 'pipe' });
    const auth = JSON.parse(await readPrivate('bootstrap.json'));
    environment.STEAD_OPENFGA_STORE_ID = auth.openfga_store_id;
    environment.STEAD_OPENFGA_MODEL_ID = auth.openfga_model_id;
    start('stead-api', path.join(state, 'stead-api'), [], { ...environment, STEAD_LISTEN: `127.0.0.1:${ports.api}` });
    start('stead-worker', path.join(state, 'stead-worker'), [], { STEAD_NATS_PUBLISHER_FILE: path.join(state, 'nats-publisher.json'), STEAD_WORKER_LISTEN: `127.0.0.1:${ports.worker}` });
    await waitHTTP('Stead API', `http://127.0.0.1:${ports.api}/health/ready`);
    await waitHTTP('Stead worker', `http://127.0.0.1:${ports.worker}/health/ready`);
    start('stead-web', path.join(state, 'stead-api'), ['dev-web', '--listen', `127.0.0.1:${ports.web}`, '--origin', `https://localhost:${ports.web}`, '--upstream', `http://127.0.0.1:${ports.api}`, '--assets', path.join(repository, 'apps/web/dist'), '--tls-cert', environment.STEAD_TLS_CERT_FILE, '--tls-key', environment.STEAD_TLS_KEY_FILE], {});
    await waitHTTP('Stead web', `https://localhost:${ports.web}/health/ready`, true);
    running.ready = true;
    await privateFile('running.json', JSON.stringify(running));
  } catch (error) { console.error(error.message); await stop(); process.exitCode = 1; }
}

async function main() {
  const command = process.argv[2];
  if (command === 'probe-infrastructure') {
    // Explicit intake execution never grants approval or uses the persistent dev
    // project. A new fixture and fresh credentials are mandatory on every run.
    await mkdir(path.join(repository, '.cache'), { recursive: true, mode: 0o700 });
    state = await mkdtemp(path.join(repository, '.cache/stead-intake-'));
    for (const port of Object.values(ports)) await portAvailable(port);
    await prepare(true);
    return run(true);
  }
  if (command === '__run') return run();
  if (command === 'status') { console.log(JSON.stringify(await status())); return; }
  if (command === 'smoke') return smoke();
  if (command === 'down') {
    const current = await status();
    if (!current.running) { console.log('Stead local stack is stopped; data preserved'); return; }
    process.kill(current.pid, 'SIGTERM');
    for (let attempt = 0; attempt < 120; attempt++) { if (!(await status()).running) { console.log('Stead local stack stopped; data preserved'); return; } await delay(500); }
    throw new Error('Graceful shutdown still in progress; no data was deleted');
  }
  if (command !== 'up' && command !== 'prepare') throw new Error('Usage: dev_stack.mjs up|down|status|smoke|prepare');
  if (process.platform !== 'linux' || process.arch !== 'x64') throw new Error('Reviewed rootless dev stack supports Linux amd64 only');
  requireApproval();
  if ((await status()).running) { console.log('Stead local stack already running'); return; }
  for (const port of Object.values(ports)) await portAvailable(port);
  await prepare();
  if (command === 'prepare') return;
  const log = await import('node:fs').then((fs) => fs.openSync(path.join(state, 'supervisor.log'), 'a', 0o600));
  const child = spawn(process.execPath, [fileURLToPath(import.meta.url), '__run'], { cwd: repository, env: baseEnvironment, detached: true, stdio: ['ignore', log, log] });
  child.unref();
  for (let attempt = 0; attempt < 360; attempt++) {
    const current = await status();
    if (current.running && current.ready) {
      console.log(`Stead local development: https://localhost:${ports.web} (trust this checkout's private development certificate deliberately; no system trust was changed)`);
      console.log(`One-time login token and logs are private files under ${state}; no credentials are printed.`);
      return;
    }
    if (attempt > 10 && !current.running) throw new Error('Stack startup failed; inspect the private supervisor log');
    await delay(500);
  }
  throw new Error('Stack startup deadline exceeded; inspect status/private logs, then make dev-down');
}

main().catch((error) => { console.error(error.message); process.exitCode = 1; });
