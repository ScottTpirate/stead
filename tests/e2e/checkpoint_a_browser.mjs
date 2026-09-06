// Namespace entry point, never imported by normal CI. Only the reviewed outer
// controller dispatches this exact file with the admitted private tool closure.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { createServer, connect } from 'node:net';
import { pathToFileURL } from 'node:url';
import { check, ORIGIN, CSP, byteBudget, allowedRequest, sha256, validateAxe,
  validateJourney, validateInnerProof } from '../../scripts/checkpoint_a_browser_boundary.mjs';
import { runCheckpointAJourney } from './checkpoint_a_browser_journey.mjs';

const fixedEnvironment = (home) => ({ PATH: '/usr/bin', HOME: home, LANG: 'C.UTF-8', TZ: 'UTC',
  XDG_CONFIG_HOME: `${home}/.config`, XDG_CACHE_HOME: `${home}/.cache`,
  XDG_DATA_HOME: `${home}/.local/share`, FONTCONFIG_FILE: '/fixture/fonts.conf' });
async function deniedConnection(host, port) {
  return new Promise((resolve) => {
    const socket = connect({ host, port });
    const finish = (denied) => { socket.destroy(); resolve(denied); };
    socket.setTimeout(500, () => finish(true));
    socket.once('connect', () => finish(false)); socket.once('error', () => finish(true));
  });
}
async function ingress() {
  const chunks = []; let length = 0;
  const timer = setTimeout(() => process.stdin.destroy(new Error('ingress_timeout')), 5000);
  try {
    for await (const chunk of process.stdin) {
      length += chunk.length; check(length <= 256); chunks.push(chunk);
    }
    const bytes = Buffer.concat(chunks);
    try {
      const value = JSON.parse(bytes.toString('utf8'));
      check(Object.keys(value).sort().join(',') === 'denied,primary');
      check(/^[A-Za-z0-9_-]{43}$/.test(value.primary) && /^[A-Za-z0-9_-]{43}$/.test(value.denied) && value.primary !== value.denied);
      return value;
    } finally { bytes.fill(0); }
  } finally { clearTimeout(timer); chunks.forEach((chunk) => chunk.fill(0)); }
}
async function startTunnel() {
  const sockets = new Set(), budget = byteBudget(); let count = 0, failed = false;
  const server = createServer((incoming) => {
    if (++count > 256 || sockets.size >= 64) { failed = true; incoming.destroy(); return; }
    const outgoing = connect('/relay.sock');
    for (const socket of [incoming, outgoing]) {
      sockets.add(socket); socket.setTimeout(30_000, () => socket.destroy());
      socket.once('close', () => sockets.delete(socket));
      socket.on('error', () => { incoming.destroy(); outgoing.destroy(); });
      socket.on('data', (chunk) => {
        if (!budget.add(chunk.length)) { failed = true; incoming.destroy(); outgoing.destroy(); }
      });
    }
    incoming.pipe(outgoing); outgoing.pipe(incoming);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(18443, '127.0.0.1', resolve); });
  server.on('error', () => { failed = true; });
  return { good: () => !failed && !budget.exceeded,
    close: async () => { sockets.forEach((socket) => socket.destroy()); await new Promise((resolve) => server.close(resolve)); } };
}
async function proveSandbox(browser) {
  const session = await browser.newBrowserCDPSession();
  try {
    const { arguments: args } = await session.send('Browser.getBrowserCommandLine');
    check(Array.isArray(args) && args.includes('--remote-debugging-pipe'));
    check(!args.some((arg) => /^(--no-sandbox|--disable-setuid-sandbox|--disable-seccomp-filter-sandbox|--disable-namespace-sandbox|--disable-web-security|--ignore-certificate-errors|--allow-insecure-localhost|--remote-debugging-port|--proxy-server|--enable-unsafe-swiftshader)(=|$)/.test(arg)));
    const { processInfo } = await session.send('SystemInfo.getProcessInfo');
    const renderers = processInfo.filter((item) => item.type === 'renderer');
    check(renderers.length > 0 && renderers.length <= 8);
    for (const renderer of renderers) {
      check(Number.isSafeInteger(renderer.id) && renderer.id > 1);
      const status = await readFile(`/proc/${renderer.id}/status`, 'utf8'); check(status.length < 32768);
      check(/^Seccomp:\s+2$/m.test(status) && /^NoNewPrivs:\s+1$/m.test(status));
      check(/^Uid:\s+1000\s+1000\s+1000\s+1000$/m.test(status));
      check((/^NSpid:\s+([\d\t ]+)$/m.exec(status)?.[1].trim().split(/\s+/).length ?? 0) >= 2);
    }
  } finally { await session.detach(); }
}
// Static sanitizer expression: no DOM, selectors, help URLs, raw axe errors,
// protocol descriptions or node contents cross out of the isolated world.
const AXE_RESULT = ` (async () => {
  if (globalThis.axe?.version !== '4.13.0') return null;
  try {
    const raw = await globalThis.axe.run(document);
    const filter = (items) => {
      if (!Array.isArray(items) || items.length > 64) return null;
      const output = [];
      for (const item of items) {
        if (!/^[a-z0-9-]{1,80}$/.test(item.id) || ![null,'minor','moderate','serious','critical'].includes(item.impact) ||
            !Array.isArray(item.nodes) || item.nodes.length > 2048) return null;
        output.push({rule:item.id,impact:item.impact,affectedNodes:item.nodes.length});
      }
      return output;
    };
    const violations=filter(raw.violations), incomplete=filter(raw.incomplete);
    if (!violations || !incomplete || !Array.isArray(raw.passes) || raw.passes.length > 256) return null;
    return {violations,incomplete,passedRules:raw.passes.length};
  } catch { return null; }
})() `;
async function auditSurface(page, surface, axeSource) {
  const session = await page.context().newCDPSession(page);
  try {
    const { frameTree } = await session.send('Page.getFrameTree');
    // Chrome's protocol defaults would clear isolated-world CSP and permit
    // unsafe eval. Explicitly preserve both, with no universal world access.
    const { executionContextId } = await session.send('Page.createIsolatedWorld', {
      frameId: frameTree.frame.id, worldName: 'stead-fixed-axe-audit',
      grantUniveralAccess: false, contentSecurityPolicy: CSP,
    });
    const parameters = { contextId: executionContextId, silent: true, generatePreview: false,
      includeCommandLineAPI: false, allowUnsafeEvalBlockedByCSP: false, timeout: 10_000 };
    const loaded = await session.send('Runtime.evaluate', { ...parameters, expression: axeSource, returnByValue: false });
    check(!loaded.exceptionDetails);
    const evaluated = await session.send('Runtime.evaluate', { ...parameters, expression: AXE_RESULT, returnByValue: true, awaitPromise: true });
    check(!evaluated.exceptionDetails && evaluated.result?.value);
    return validateAxe({ surface, ...evaluated.result.value }, surface);
  } finally { await session.detach(); }
}
export async function main() {
  const proof = { format: 'stead-checkpoint-a-browser-proof-v1', passed: false, phase: 'namespace',
    networkIsolated: false, rendererSandbox: false, cspPreserved: false, browserCleanup: false, journey: null };
  let browser, tunnel, credentials, timer;
  let failed = false, violations = 0, seenDocuments = 0;
  try {
    check(process.getuid() === 1000 && process.argv.length === 2);
    check(/^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$/m.test(await readFile('/proc/self/limits', 'utf8')));
    const routes = await readFile('/proc/net/route', 'utf8');
    check(!routes.split('\n').slice(1).some((line) => line.trim().split(/\s+/)[1] === '00000000'));
    check(await deniedConnection('192.0.2.1', 443));
    check((await Promise.all([15432, 13000, 18080, 18081, 14222, 18222, 18000, 18001, 18443]
      .map((port) => deniedConnection('127.0.0.1', port)))).every(Boolean));
    proof.networkIsolated = true;
    credentials = await ingress();
    timer = setTimeout(() => process.exit(1), 290_000);
    tunnel = await startTunnel();
    proof.phase = 'trust';
    const home = '/home/trusted', nss = `${home}/.local/share/pki/nssdb`;
    await mkdir(nss, { recursive: true, mode: 0o700 });
    for (const args of [
      ['-N', '--empty-password', '-d', `sql:${nss}`],
      ['-A', '-d', `sql:${nss}`, '-n', 'stead-fresh-local-instance', '-t', 'C,,', '-i', '/fixture/localhost.crt'],
    ]) {
      const run = spawnSync('/usr/bin/certutil', args, { env: fixedEnvironment(home), timeout: 3000, stdio: 'ignore' });
      check(run.status === 0 && !run.signal && !run.error);
    }
    const axeBytes = await readFile('/tools/axe-core/axe.min.js');
    const expected = JSON.parse(await readFile('/fixture/axe-pin.json', 'utf8'));
    check(sha256(axeBytes) === expected.sha256);
    const axeSource = axeBytes.toString('utf8');
    const { chromium } = await import('/tools/playwright-core/index.mjs');
    proof.phase = 'browser';
    browser = await chromium.launch({ executablePath: '/browser/chrome-headless-shell', headless: true,
      chromiumSandbox: true, timeout: 10_000, ignoreDefaultArgs: ['--enable-unsafe-swiftshader'],
      args: ['--enable-automation', '--disable-gpu', '--disable-software-rasterizer'], env: fixedEnvironment(home) });
    check(browser.version() === '152.0.7977.82');
    const contexts = [];
    for (let i = 0; i < 2; i++) {
      const context = await browser.newContext({ viewport: { width: 1280, height: 900 },
        locale: 'en-US', timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false });
      await context.route(() => true, async (route) => {
        if (!allowedRequest(route.request().method(), route.request().url())) {
          violations++; await route.abort('blockedbyclient');
        } else await route.continue();
      });
      context.on('response', (response) => {
        if (response.request().resourceType() === 'document') {
          seenDocuments++;
          if (response.headers()['content-security-policy'] !== CSP) violations++;
        }
      });
      context.on('page', (page) => {
        page.on('websocket', () => { violations++; });
        page.on('download', (download) => { violations++; void download.cancel().catch(() => {}); });
      });
      contexts.push(context);
    }
    proof.phase = 'journey';
    proof.journey = validateJourney(await runCheckpointAJourney({ primaryContext: contexts[0], deniedContext: contexts[1],
      primaryCredential: credentials.primary, deniedCredential: credentials.denied,
      auditSurface: async (page, surface) => {
        check(violations === 0 && seenDocuments > 0);
        await proveSandbox(browser); proof.rendererSandbox = true;
        return auditSurface(page, surface, axeSource);
      } }));
    credentials.primary = ''; credentials.denied = '';
    proof.cspPreserved = violations === 0 && seenDocuments >= 3;
    check(proof.journey.status === 'completed' && proof.cspPreserved && tunnel.good());
    proof.phase = 'cleanup';
  } catch { failed = true; } // Never serialize native, Playwright or protocol errors.
  finally {
    if (credentials) { credentials.primary = ''; credentials.denied = ''; }
    try {
      if (browser) await Promise.race([browser.close(), new Promise((_, reject) => setTimeout(() => reject(new Error('close')), 5000).unref())]);
      proof.browserCleanup = true;
    } catch { failed = true; }
    try { if (tunnel) await tunnel.close(); } catch { failed = true; }
    clearTimeout(timer);
  }
  if (!failed) { proof.passed = true; proof.phase = 'complete'; }
  await writeFile('/work/result.json', JSON.stringify(validateInnerProof(proof)) + '\n', { mode: 0o600, flag: 'wx' });
  process.exitCode = proof.passed ? 0 : 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.exitCode = 1; });
}
