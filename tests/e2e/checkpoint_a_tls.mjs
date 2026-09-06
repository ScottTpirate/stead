// Four fixed, credential-free document navigations. No journey, auth/session
// endpoint, setup/cookie/key/config file, application script or raw error output.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { check, ORIGIN, CSP, serverTrustCommands } from '../../scripts/checkpoint_a_browser_boundary.mjs';
import { TLS_PROFILES, WRONG_ORIGIN, WRONG_HOST_RULE, classifyTLSError,
  tlsNavigationAllowed, trialPass, validateTLSProof } from '../../scripts/checkpoint_a_tls_boundary.mjs';
import { fixedEnvironment, deniedConnection, startTunnel, proveSandbox, cspContext } from './checkpoint_a_browser.mjs';

export function launchOptions(profile) {
  check(TLS_PROFILES.includes(profile));
  return { executablePath: '/browser/chrome-headless-shell', headless: true,
    chromiumSandbox: true, timeout: 10_000, ignoreDefaultArgs: ['--enable-unsafe-swiftshader'],
    args: ['--enable-automation', '--disable-gpu', '--disable-software-rasterizer',
      ...(profile === 'wrong_name' ? ['--host-resolver-rules=' + WRONG_HOST_RULE] : [])],
    env: fixedEnvironment(serverTrustCommands(profile).home) };
}
export async function main() {
  const proof = { format: 'stead-checkpoint-a-tls-proof-v1', passed: false,
    phase: 'namespace', networkIsolated: false, browserCleanup: false, trials: [] };
  let tunnel, browser, timer, failed = false, allClosed = true;
  try {
    check(process.getuid() === 1000 && process.argv.length === 2);
    check(/^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$/m.test(await readFile('/proc/self/limits', 'utf8')));
    const routes = await readFile('/proc/net/route', 'utf8');
    check(!routes.split('\n').slice(1).some((line) => line.trim().split(/\s+/)[1] === '00000000'));
    check(await deniedConnection('192.0.2.1', 443));
    check((await Promise.all([15432, 13000, 18080, 18081, 14222, 18222, 18000, 18001, 18443]
      .map((port) => deniedConnection('127.0.0.1', port)))).every(Boolean));
    proof.networkIsolated = true;
    timer = setTimeout(() => process.exit(1), 110_000);
    tunnel = await startTunnel();
    const { chromium } = await import('/tools/playwright-core/index.mjs');
    for (const profile of TLS_PROFILES) {
      const trial = { profile, status: null, error: 'none', sent: 0, responses: 0,
        failed: 0, blocked: 0, overflow: false, csp: false, sandbox: false };
      proof.trials.push(trial);
      try {
        proof.phase = 'trust';
        const { home, database, commands } = serverTrustCommands(profile);
        await mkdir(database, { recursive: true, mode: 0o700 });
        for (const args of commands) {
          const result = spawnSync('/usr/bin/certutil', args, { env: fixedEnvironment(home), timeout: 3000, stdio: 'ignore' });
          check(result.status === 0 && !result.signal && !result.error);
        }
        proof.phase = 'browser'; browser = await chromium.launch(launchOptions(profile));
        check(browser.version() === '152.0.7977.82');
        const context = await browser.newContext({ viewport: { width: 1280, height: 900 },
          locale: 'en-US', timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false });
        const page = await context.newPage();
        const target = (profile === 'wrong_name' ? WRONG_ORIGIN : ORIGIN) + '/';
        await context.route(() => true, async (route) => {
          const request = route.request();
          if (trial.sent === 0 && request.frame() === page.mainFrame() &&
              tlsNavigationAllowed(profile, request.method(), request.url(), request.resourceType(), request.isNavigationRequest())) {
            trial.sent++; await route.continue();
          } else {
            if (trial.blocked === 64) { trial.overflow = true; failed = true; }
            else trial.blocked++;
            await route.abort('blockedbyclient');
          }
        });
        page.on('requestfailed', (request) => {
          if (request.resourceType() === 'document' && request.url() === target) {
            trial.failed++; if (trial.error === 'none') trial.error = classifyTLSError(request.failure()?.errorText);
          }
        });
        page.on('response', (response) => {
          if (response.request().resourceType() === 'document') trial.responses++;
        });
        page.on('websocket', () => { failed = true; });
        page.on('download', (download) => { failed = true; void download.cancel().catch(() => {}); });
        proof.phase = 'navigation';
        try {
          const response = await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 12_000 });
          // Detects a changed final URL after navigation, not a network-level
          // redirect block. The admitted application's / must not redirect.
          check(response && response.url() === target);
          trial.status = response.status();
          if (trial.status === 200) {
            check(response.headers()['content-security-policy'] === CSP);
            await proveSandbox(browser); trial.sandbox = true;
            const session = await context.newCDPSession(page);
            try { await cspContext(session); trial.csp = true; }
            finally { await session.detach(); }
          }
        } catch (error) {
          if (trial.error === 'none') trial.error = classifyTLSError(error);
        }
      } catch (error) {
        if (trial.error === 'none') trial.error = classifyTLSError(error);
      } finally {
        proof.phase = 'cleanup';
        try {
          if (browser) await Promise.race([browser.close(), new Promise((_, reject) => setTimeout(() => reject(new Error('close')), 5000).unref())]);
        } catch { allClosed = false; failed = true; }
        browser = undefined;
      }
    }
    check(proof.trials.every(trialPass) && tunnel.good());
  } catch { failed = true; }
  finally {
    clearTimeout(timer);
    try { if (tunnel) await tunnel.close(); } catch { failed = true; }
    proof.browserCleanup = allClosed;
  }
  if (!failed) { proof.passed = true; proof.phase = 'complete'; }
  await writeFile('/work/result.json', JSON.stringify(validateTLSProof(proof)) + '\n', { mode: 0o600, flag: 'wx' });
  process.exitCode = proof.passed ? 0 : 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.exitCode = 1; });
}
