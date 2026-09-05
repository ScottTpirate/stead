// SPDX-License-Identifier: Apache-2.0
import test from 'node:test';
import assert from 'node:assert/strict';
import { parseImage, validateArchiveNames } from './dev_image.mjs';
import { serviceNames, servicePorts, postgresURL, giteaConfig, natsConfig, openfgaEnvironment } from './dev_stack_config.mjs';

const secrets = Object.fromEntries(['giteaPassword', 'giteaSecret', 'giteaInternalToken', 'natsPublisher', 'natsConsumer', 'natsMaintenance', 'openfgaKey', 'openfgaPassword'].map((key, index) => [key, String(index).repeat(64)]));

test('OCI acquisition accepts immutable platform digests only from reviewed registries', () => {
  const pin = `cgr.dev/chainguard/postgres@sha256:${'a'.repeat(64)}`;
  assert.equal(parseImage(pin).repository, 'chainguard/postgres');
  for (const invalid of ['postgres:latest', 'docker.io/postgres:18', pin.replace('cgr.dev', 'evil.invalid'), pin.replace('/postgres', '/../postgres'), pin + '/extra']) assert.throws(() => parseImage(invalid));
});

test('image extraction rejects traversal, control characters and unsupported whiteouts', () => {
  validateArchiveNames('usr/bin/postgres\n./etc/passwd\nvar/lib/\n');
  for (const invalid of ['/etc/passwd', '../etc/passwd', 'usr/../etc/passwd', 'etc/.wh.passwd', 'etc/name\rvalue', 'etc\\passwd']) assert.throws(() => validateArchiveNames(invalid));
});

test('fixed seven services have distinct loopback ports', () => {
  assert.deepEqual(serviceNames, ['postgres', 'gitea', 'openfga', 'nats', 'stead-api', 'stead-worker', 'stead-web']);
  assert.equal(new Set(Object.values(servicePorts)).size, Object.values(servicePorts).length);
  assert.ok(Object.values(servicePorts).every((port) => Number.isInteger(port) && port > 1024 && port < 65536));
});

test('PostgreSQL URI encodes credential syntax and remains bounded to the explicit service', () => {
  const url = new URL(postgresURL('role', 'p@ss:/?#', 'stead'));
  assert.equal(url.hostname, '127.0.0.1');
  assert.equal(url.pathname, '/stead');
  assert.equal(decodeURIComponent(url.password), 'p@ss:/?#');
  assert.equal(url.searchParams.get('connect_timeout'), '5');
});

test('local Gitea disables reachable SSH, imports and untrusted extension/upload surfaces', () => {
  const config = giteaConfig(secrets);
  for (const setting of ['HTTP_ADDR = 127.0.0.1', 'DISABLE_SSH = true', 'START_SSH_SERVER = false', 'OFFLINE_MODE = true', 'DISABLE_MIGRATIONS = true', 'DISABLE_REGISTRATION = true', 'REQUIRE_SIGNIN_VIEW = true', 'DISABLE_GRAVATAR = true']) assert.ok(config.includes(setting));
  for (const section of ['actions', 'packages', 'attachment', 'repository.upload', 'mirror', 'mailer']) assert.ok(config.includes(`[${section}]\nENABLED = false`));
  assert.ok(config.includes('NAME = gitea\nUSER = gitea'));
});

test('NATS has one account, scoped distinct infrastructure roles and no global publish wildcard', () => {
  const config = natsConfig(secrets);
  assert.equal((config.match(/accounts \{/g) ?? []).length, 1);
  for (const role of ['publisher', 'consumer', 'maintenance']) assert.ok(config.includes(`user: ${role}`));
  assert.ok(!config.includes('publish: [">"'));
  assert.ok(!config.includes('stead.>'));
  assert.ok(config.includes('listen: 127.0.0.1:14222'));
  assert.ok(config.includes('max_file_store: 1073741824'));
});

test('OpenFGA requires real PostgreSQL and service authentication with authorization caches off', () => {
  const env = openfgaEnvironment(secrets);
  assert.equal(env.OPENFGA_DATASTORE_ENGINE, 'postgres');
  assert.equal(new URL(env.OPENFGA_DATASTORE_URI).pathname, '/openfga');
  assert.equal(env.OPENFGA_AUTHN_METHOD, 'preshared');
  assert.equal(env.OPENFGA_AUTHN_PRESHARED_KEYS, secrets.openfgaKey);
  for (const key of ['OPENFGA_CHECK_QUERY_CACHE_ENABLED', 'OPENFGA_CHECK_ITERATOR_CACHE_ENABLED', 'OPENFGA_LIST_OBJECTS_ITERATOR_CACHE_ENABLED', 'OPENFGA_PLAYGROUND_ENABLED', 'OPENFGA_METRICS_ENABLED', 'OPENFGA_TRACE_ENABLED']) assert.equal(env[key], 'false');
});
