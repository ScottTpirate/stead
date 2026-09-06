// One credential-free keyboard diagnostic. No login/session/key reads or retries.
import { readFileSync, writeFileSync, mkdtempSync, chmodSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { X509Certificate } from 'node:crypto';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { check, readBounded, sha256, INPUTS_SHA256 } from './checkpoint_a_browser_boundary.mjs';
import { validateKeyboardAdmission, claimKeyboardDiagnostic, validateKeyboardProof, KEYBOARD_SCOPE } from './checkpoint_a_keyboard_boundary.mjs';
import { verifyInputs, verifyHarness, verifyIdentity, stage, relay } from './checkpoint_a_browser.mjs';

// Closed stdin, no inherited environment, no native output. Retain actual exit,
// not a boolean inferred from a proof file that could precede a child failure.
export async function executeKeyboard(args, spawnImplementation = spawn) {
  return new Promise((resolve) => {
    let timedOut = false, spawnError = false;
    const child = spawnImplementation('/usr/bin/bwrap', args, { detached: true, stdio: ['ignore', 'ignore', 'ignore'],
      env: { PATH: '/usr/bin', HOME: '/home/controller', LANG: 'C.UTF-8', TZ: 'UTC', FONTCONFIG_FILE: '/fixture/fonts.conf' } });
    const timer = setTimeout(() => { timedOut = true; try { process.kill(-child.pid, 'SIGKILL'); } catch {} }, 120_000);
    child.once('error', () => { spawnError = true; });
    child.once('close', (code, signal) => {
      clearTimeout(timer);
      resolve({ code, signal: signal === null ? null : ['SIGKILL', 'SIGTERM'].includes(signal) ? signal : 'other', timedOut, spawnError });
    });
  });
}
export async function main(argv = process.argv.slice(2)) {
  let admission, admissionBytes, inputs, identity, directory, staged, transport, attempt, attemptHash, inner = null, child = null;
  let phase = 'preflight', passed = false, inputsUnchanged = false;
  try {
    check(argv.length === 2 && argv[0] === '--review');
    check(!Object.keys(process.env).some((name) => !['PATH', 'LANG', 'TZ'].includes(name)));
    check(/^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$/m.test(readFileSync('/proc/self/limits', 'utf8')));
    admissionBytes = readBounded(argv[1], 32768, { privateMode: true });
    admission = validateKeyboardAdmission(JSON.parse(admissionBytes));
    for (const review of admission.reviews) check(sha256(readBounded(review.path, 1 << 20)) === review.sha256);
    inputs = verifyInputs(); verifyHarness(admission);
    phase = 'identity'; identity = verifyIdentity(admission);
    const certificate = new X509Certificate(identity.certificate);
    check(!certificate.ca && certificate.issuer === certificate.subject && certificate.verify(certificate.publicKey));
    check(certificate.checkHost('localhost') === 'localhost' && certificate.checkHost('stead-wrong-host.invalid') === undefined);
    check(Date.parse(certificate.validFrom) <= Date.now() && Date.parse(certificate.validTo) > Date.now());
    phase = 'attempt';
    attempt = claimKeyboardDiagnostic(argv[1], { scope: KEYBOARD_SCOPE, admissionSHA256: sha256(admissionBytes),
      instanceID: admission.instance.instanceID, sourceRevision: admission.source.head, startedAt: new Date().toISOString() });
    attemptHash = sha256(readBounded(attempt, 4096, { privateMode: true }));
    directory = mkdtempSync('/home/skilgore/stead-checkpoint-a-keyboard-run.'); chmodSync(directory, 0o700);
    phase = 'staging'; staged = stage(inputs, directory, admission, identity.certificate, undefined, 'keyboard');
    transport = await relay(path.join(directory, 'relay.sock'));
    phase = 'namespace'; child = await executeKeyboard(staged.args);
    inner = validateKeyboardProof(JSON.parse(readBounded(path.join(staged.work, 'result.json'), 16384, { privateMode: true })));
    phase = inner.phase;
    passed = child.code === 0 && child.signal === null && !child.timedOut && !child.spawnError && inner.passed && transport.good();
  } catch { passed = false; }
  finally {
    try { if (transport) await transport.close(); } catch { passed = false; }
    if (admission && inputs && staged) {
      try {
        verifyInputs(); verifyHarness(admission);
        check(sha256(readBounded(argv[1], 32768, { privateMode: true })) === sha256(admissionBytes));
        check(sha256(readBounded(attempt, 4096, { privateMode: true })) === attemptHash);
        for (const entry of staged.copies) check(sha256(readBounded(entry.path, 512 << 20)) === entry.sha256);
        const after = verifyIdentity(admission);
        check(after.certificate.equals(identity.certificate) && after.distribution === identity.distribution &&
          JSON.stringify(after.runtime) === JSON.stringify(identity.runtime));
        inputsUnchanged = true;
      } catch { passed = false; }
    }
  }
  const report = { format: 'stead-checkpoint-a-keyboard-run-v1', scope: KEYBOARD_SCOPE, passed: passed && inputsUnchanged,
    phase, inputsUnchanged, inputsSHA256: INPUTS_SHA256, child,
    admissionSHA256: admissionBytes ? sha256(admissionBytes) : null,
    sourceRevision: admission?.source.head ?? null, harnessRevision: admission?.harness.head ?? null,
    instanceID: admission?.instance.instanceID ?? null, proof: inner };
  if (directory) writeFileSync(path.join(directory, 'result.json'), JSON.stringify(report) + '\n', { mode: 0o600, flag: 'wx' });
  process.stdout.write(JSON.stringify({ passed: report.passed, phase, resultDirectory: directory ?? null }) + '\n');
  process.exitCode = report.passed ? 0 : 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.stdout.write('{"passed":false,"phase":"cleanup"}\n'); process.exitCode = 1; });
}
