// Closed, credential-free TLS diagnostic protocol. Importing is inert.
import { openSync, closeSync, writeSync, fsyncSync, constants } from 'node:fs';
import path from 'node:path';
import { check, keys, validateAdmission, SOURCE_FILES, TLS_SOURCE_FILES, hash,
  privateDirectory, ORIGIN } from './checkpoint_a_browser_boundary.mjs';

export const TLS_SCOPE = 'one-credential-free-real-origin-tls-diagnostic';
export const WRONG_ORIGIN = 'https://stead-wrong-host.invalid:18443';
export const WRONG_HOST_RULE = 'MAP stead-wrong-host.invalid 127.0.0.1';
export const TLS_PROFILES = Object.freeze(['untrusted', 'ca', 'peer', 'wrong_name']);
export const TLS_ERRORS = Object.freeze(['none', 'certificate_authority', 'certificate_name',
  'certificate_date', 'certificate_other', 'tls', 'connection', 'timeout', 'other']);
export const TLS_PHASES = Object.freeze(['preflight', 'identity', 'attempt', 'staging',
  'namespace', 'trust', 'browser', 'navigation', 'cleanup', 'complete']);
export function validateTLSAdmission(value, now = Date.now()) {
  keys(value, ['format', 'status', 'scope', 'expiresAt', 'harness', 'source', 'instance', 'files', 'reviews']);
  check(value.format === 'stead-checkpoint-a-tls-admission-v1' && value.scope === TLS_SCOPE);
  keys(value.files, TLS_SOURCE_FILES);
  Object.values(value.files).forEach((digest) => check(hash(digest)));
  // Reuse the closed identity/reviewer schema, not its executable scope. The
  // real browser validator rejects this original diagnostic admission outright.
  validateAdmission({ ...value, format: 'stead-checkpoint-a-browser-admission-v1',
    scope: 'one-fresh-real-checkpoint-a-browser-run',
    files: Object.fromEntries(SOURCE_FILES.map((file) => [file, value.files[file]])) }, now);
  return value;
}
export function claimTLSDiagnostic(admissionPath, record) {
  const directory = path.dirname(admissionPath); privateDirectory(directory);
  // Separate from application state and its spent one-shot browser marker.
  const file = admissionPath + '.tls-attempt.json';
  const descriptor = openSync(file, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(descriptor, JSON.stringify(record) + '\n'); fsyncSync(descriptor); }
  finally { closeSync(descriptor); }
  const parent = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(parent); } finally { closeSync(parent); }
  return file;
}
export function classifyTLSError(error) {
  const message = typeof error === 'string' ? error : typeof error?.message === 'string' ? error.message : '';
  if (message.length > 8192) return 'other';
  if (/\bERR_CERT_AUTHORITY_INVALID\b/.test(message)) return 'certificate_authority';
  if (/\bERR_CERT_COMMON_NAME_INVALID\b/.test(message)) return 'certificate_name';
  if (/\bERR_CERT_DATE_INVALID\b/.test(message)) return 'certificate_date';
  if (/\bERR_CERT_[A-Z_]+\b/.test(message)) return 'certificate_other';
  if (/\bERR_(?:SSL|TLS)_[A-Z_]+\b/.test(message)) return 'tls';
  if (/\bERR_(?:CONNECTION_[A-Z_]+|ADDRESS_UNREACHABLE|NAME_NOT_RESOLVED)\b/.test(message)) return 'connection';
  if (/\bERR_TIMED_OUT\b|\bTimeout\b|\bTimeoutError\b/.test(message)) return 'timeout';
  return 'other';
}
export function tlsNavigationAllowed(profile, method, url, resourceType, navigation) {
  // Initial requests only: pinned Playwright does not route every redirect hop.
  // Admission requires the exact application's nonredirecting static / handler.
  check(TLS_PROFILES.includes(profile));
  return method === 'GET' && resourceType === 'document' && navigation === true &&
    url === (profile === 'wrong_name' ? WRONG_ORIGIN : ORIGIN) + '/';
}
export function trialPass(value) {
  if (value.sent !== 1 || value.overflow) return false;
  const accepted = value.status === 200 && value.error === 'none' &&
    value.responses === 1 && value.failed === 0 && value.csp && value.sandbox;
  if (value.profile === 'peer') return accepted;
  // CA mode is a comparison, not a forced confirmation of the diagnosis. Its
  // actual accept/reject outcome is retained even if it contradicts expectation.
  if (value.profile === 'ca') return accepted || (value.status === null && value.responses === 0 &&
    value.failed === 1 && ['certificate_authority', 'certificate_other'].includes(value.error));
  return value.status === null && value.responses === 0 && value.failed === 1 &&
    value.error === (value.profile === 'wrong_name' ? 'certificate_name' : 'certificate_authority');
}
export function validateTLSProof(value) {
  keys(value, ['format', 'passed', 'phase', 'networkIsolated', 'browserCleanup', 'trials']);
  check(value.format === 'stead-checkpoint-a-tls-proof-v1' && typeof value.passed === 'boolean' &&
    TLS_PHASES.includes(value.phase) && typeof value.networkIsolated === 'boolean' && typeof value.browserCleanup === 'boolean');
  check(Array.isArray(value.trials) && value.trials.length <= TLS_PROFILES.length);
  value.trials.forEach((trial, index) => {
    keys(trial, ['profile', 'status', 'error', 'sent', 'responses', 'failed', 'blocked', 'overflow', 'csp', 'sandbox']);
    check(trial.profile === TLS_PROFILES[index] && TLS_ERRORS.includes(trial.error));
    check(trial.status === null || (Number.isInteger(trial.status) && trial.status >= 100 && trial.status <= 599));
    for (const field of ['sent', 'responses', 'failed', 'blocked']) check(Number.isSafeInteger(trial[field]) && trial[field] >= 0 && trial[field] <= 64);
    check(typeof trial.overflow === 'boolean' && typeof trial.csp === 'boolean' && typeof trial.sandbox === 'boolean');
  });
  if (value.passed) check(value.phase === 'complete' && value.networkIsolated && value.browserCleanup &&
    value.trials.length === 4 && value.trials.every(trialPass));
  return value;
}
