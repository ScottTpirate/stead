// Test-only closed keyboard scope. No execution on import and no credential schema.
import { openSync, closeSync, writeSync, fsyncSync, constants } from 'node:fs';
import path from 'node:path';
import { check, keys, hash, validateAdmission, SOURCE_FILES, KEYBOARD_SOURCE_FILES,
  privateDirectory, ORIGIN } from './checkpoint_a_browser_boundary.mjs';

export const KEYBOARD_SCOPE = 'one-credential-free-real-shell-keyboard-diagnostic';
export const KEYBOARD_STEPS = Object.freeze(['login_shell', 'trigger_focus', 'first_open', 'search_focus',
  'audit', 'escape', 'hidden', 'return_focus', 'second_open', 'filter', 'tab', 'enter', 'route', 'skip']);
export function validateKeyboardAdmission(value, now = Date.now()) {
  keys(value, ['format', 'status', 'scope', 'expiresAt', 'harness', 'source', 'instance', 'files', 'reviews']);
  check(value.format === 'stead-checkpoint-a-keyboard-admission-v1' && value.scope === KEYBOARD_SCOPE);
  keys(value.files, KEYBOARD_SOURCE_FILES); Object.values(value.files).forEach((digest) => check(hash(digest)));
  validateAdmission({ ...value, format: 'stead-checkpoint-a-browser-admission-v1', scope: 'one-fresh-real-checkpoint-a-browser-run',
    files: Object.fromEntries(SOURCE_FILES.map((file) => [file, value.files[file]])) }, now);
  return value;
}
export function claimKeyboardDiagnostic(admissionPath, record) {
  const directory = path.dirname(admissionPath); privateDirectory(directory);
  const filename = admissionPath + '.keyboard-attempt.json';
  const fd = openSync(filename, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW, 0o600);
  try { writeSync(fd, JSON.stringify(record) + '\n'); fsyncSync(fd); } finally { closeSync(fd); }
  const parent = openSync(directory, constants.O_RDONLY | constants.O_DIRECTORY);
  try { fsyncSync(parent); } finally { closeSync(parent); }
  return filename;
}
export function keyboardAssets(evidence) {
  check(Array.isArray(evidence?.distribution_artifacts) && evidence.distribution_artifacts.length <= 32);
  const assets = evidence.distribution_artifacts.filter((entry) => /^assets\/[A-Za-z0-9_-]+\.(js|css)$/.test(entry.file));
  check(assets.length > 0 && assets.every((entry) => hash(entry.sha256)));
  check(new Set(assets.map((entry) => entry.file)).size === assets.length);
  return assets.map((entry) => '/' + entry.file);
}
export function keyboardRequestAllowed(method, url, type, navigation, headers, assets) {
  if (method !== 'GET' || !headers || Object.keys(headers).some((key) => /^(cookie|authorization|proxy-authorization)$/i.test(key))) return false;
  if (url === ORIGIN + '/') return type === 'document' && navigation;
  if (navigation) return false;
  if (url === ORIGIN + '/api/v1/session') return ['fetch', 'xhr'].includes(type);
  return assets.some((asset) => url === ORIGIN + asset && type === (asset.endsWith('.css') ? 'stylesheet' : 'script'));
}
export function keyboardResponseAllowed(url, status, headers, assets) {
  if (Object.keys(headers).some((key) => /^(set-cookie|location)$/i.test(key))) return false;
  return url === ORIGIN + '/api/v1/session' ? status === 401 :
    (url === ORIGIN + '/' || assets.some((asset) => url === ORIGIN + asset)) && status === 200;
}
export function validateFocus(value) {
  keys(value, ['dialogOpen', 'documentFocused', 'visible', 'triggerFocused', 'searchFocused', 'teamsFocused', 'mainFocused']);
  check(Object.values(value).every((entry) => typeof entry === 'boolean')); return value;
}
export function validateKeyboardProof(value) {
  keys(value, ['format', 'passed', 'phase', 'networkIsolated', 'rendererSandbox', 'csp', 'browserCleanup',
    'steps', 'failedStep', 'lastState', 'sent', 'responses', 'blocked', 'sessions', 'axeObserved']);
  check(value.format === 'stead-checkpoint-a-keyboard-proof-v1' &&
    ['namespace', 'trust', 'browser', 'keyboard', 'cleanup', 'complete'].includes(value.phase));
  for (const key of ['passed', 'networkIsolated', 'rendererSandbox', 'csp', 'browserCleanup', 'axeObserved']) check(typeof value[key] === 'boolean');
  for (const key of ['sent', 'responses', 'blocked', 'sessions']) check(Number.isSafeInteger(value[key]) && value[key] >= 0 && value[key] <= 64);
  check(Array.isArray(value.steps) && value.steps.length <= KEYBOARD_STEPS.length);
  value.steps.forEach((entry, index) => {
    keys(entry, ['step', 'state']); check(entry.step === KEYBOARD_STEPS[index]); validateFocus(entry.state);
  });
  check(value.failedStep === null || value.failedStep === KEYBOARD_STEPS[value.steps.length]);
  if (value.lastState !== null) validateFocus(value.lastState);
  if (value.passed) check(value.phase === 'complete' && value.networkIsolated && value.rendererSandbox && value.csp && value.browserCleanup &&
    value.axeObserved && value.steps.length === KEYBOARD_STEPS.length && value.failedStep === null && value.blocked === 0 && value.sessions === 1 && value.sent === value.responses);
  return value;
}
