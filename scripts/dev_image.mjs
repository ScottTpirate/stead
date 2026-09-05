// SPDX-License-Identifier: Apache-2.0
// Explicit, digest-only OCI acquisition for the non-distributed Linux dev stack.
import { createHash } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { mkdir, readFile, writeFile, rename, lstat } from 'node:fs/promises';
import path from 'node:path';

export const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digestPattern = /^sha256:[a-f0-9]{64}$/;

export function parseImage(reference) {
  const match = /^(cgr\.dev|docker\.gitea\.com|registry-1\.docker\.io)\/([a-z0-9_./-]+)@(sha256:[a-f0-9]{64})$/.exec(reference);
  if (!match || match[2].split('/').some((part) => !part || part === '..')) {
    throw new Error('A supported registry and immutable image digest are required');
  }
  return { registry: match[1], repository: match[2], digest: match[3] };
}

export function validateArchiveNames(names) {
  for (const name of names.split('\n').filter(Boolean)) {
    if (name.startsWith('/') || name.split('/').includes('..') || name.includes('\\') || /[\x00-\x1f\x7f]/.test(name)) {
      throw new Error('Unsafe path in pinned image archive');
    }
    if (name.split('/').some((part) => part.startsWith('.wh.'))) {
      throw new Error('This bounded image extractor does not support OCI whiteouts');
    }
  }
}

async function fetchRegistry(image, resource) {
  const url = `https://${image.registry}/v2/${image.repository}/${resource}`;
  const headers = { Accept: 'application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.index.v1+json' };
  let response = await fetch(url, { headers, signal: AbortSignal.timeout(120_000) });
  if (response.status === 401) {
    const challenge = response.headers.get('www-authenticate') ?? '';
    const realm = /realm="([^"]+)"/.exec(challenge)?.[1];
    const service = /service="([^"]+)"/.exec(challenge)?.[1];
    if (!challenge.startsWith('Bearer ') || !realm) throw new Error('Unsupported registry authentication');
    const authURL = new URL(realm);
    const allowedHost = { 'cgr.dev': 'cgr.dev', 'docker.gitea.com': 'docker.gitea.com', 'registry-1.docker.io': 'auth.docker.io' }[image.registry];
    if (authURL.protocol !== 'https:' || authURL.hostname !== allowedHost || authURL.username || authURL.password) {
      throw new Error('Unexpected registry authentication origin');
    }
    if (service) authURL.searchParams.set('service', service);
    authURL.searchParams.set('scope', `repository:${image.repository}:pull`);
    const authResponse = await fetch(authURL, { signal: AbortSignal.timeout(30_000) });
    if (!authResponse.ok) throw new Error(`Anonymous image authentication failed (${authResponse.status})`);
    const auth = await authResponse.json();
    const token = auth.token ?? auth.access_token;
    if (typeof token !== 'string' || !token) throw new Error('Registry did not return a pull token');
    response = await fetch(url, { headers: { ...headers, Authorization: `Bearer ${token}` }, signal: AbortSignal.timeout(120_000) });
  }
  if (!response.ok) throw new Error(`Image acquisition failed (${response.status})`);
  return Buffer.from(await response.arrayBuffer());
}

async function blob(image, digest, destination, manifest = false) {
  if (!digestPattern.test(digest)) throw new Error('Invalid OCI digest');
  let bytes;
  try {
    if (!(await lstat(destination)).isFile()) throw new Error('Image cache entry is not a regular file');
    bytes = await readFile(destination);
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
    bytes = await fetchRegistry(image, `${manifest ? 'manifests' : 'blobs'}/${digest}`);
    if (`sha256:${sha256(bytes)}` !== digest) throw new Error('Image download checksum mismatch');
    await writeFile(destination, bytes, { flag: 'wx', mode: 0o600 });
  }
  if (`sha256:${sha256(bytes)}` !== digest) throw new Error('Image cache checksum mismatch');
  return bytes;
}

export async function acquireImage(reference, cacheRoot) {
  const image = parseImage(reference);
  const directory = path.join(cacheRoot, image.digest.slice(7));
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const manifest = JSON.parse(await blob(image, image.digest, path.join(directory, 'manifest.json'), true));
  if (manifest.schemaVersion !== 2 || !Array.isArray(manifest.layers) || !manifest.config) {
    throw new Error('Pin a platform manifest, not a multi-platform index');
  }
  const config = JSON.parse(await blob(image, manifest.config.digest, path.join(directory, 'config.json')));
  if (config.os !== 'linux' || config.architecture !== 'amd64') throw new Error('Only reviewed Linux amd64 images are supported');
  for (const layer of manifest.layers) {
    await blob(image, layer.digest, path.join(directory, `${layer.digest.slice(7)}.tar.gz`));
  }
  const rootfs = path.join(directory, 'rootfs');
  try {
    if ((await readFile(path.join(directory, 'complete'), 'utf8')) === reference) return { rootfs, config };
    throw new Error('Image cache completion identity mismatch');
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  // The fixed approved images are trusted input, not an arbitrary archive service.
  // Extract into a fresh private directory. GNU tar also rejects traversal through
  // earlier archive symlinks; do not add --absolute-names or --keep-directory-symlink.
  const temporary = path.join(directory, `rootfs-${process.pid}`);
  await mkdir(temporary, { mode: 0o700 });
  for (const layer of manifest.layers) {
    const archive = path.join(directory, `${layer.digest.slice(7)}.tar.gz`);
    const listing = spawnSync('tar', ['--list', '--gzip', '--file', archive], { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
    if (listing.status !== 0) throw new Error('Image layer listing failed');
    validateArchiveNames(listing.stdout);
    const extraction = spawnSync('tar', ['--extract', '--gzip', '--file', archive, '--directory', temporary, '--no-same-owner', '--no-same-permissions', '--exclude=dev/*', '--exclude=./dev/*'], { encoding: 'utf8' });
    if (extraction.status !== 0) throw new Error('Image layer extraction failed');
  }
  await rename(temporary, rootfs);
  await writeFile(path.join(directory, 'complete'), reference, { flag: 'wx', mode: 0o600 });
  return { rootfs, config };
}
