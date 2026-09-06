// Anonymous real shell only. No ingress, session access, login or product writes.
import { readFile, writeFile, mkdir } from 'node:fs/promises';
import { spawnSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { check, ORIGIN, CSP, serverTrustCommands, sha256 } from '../../scripts/checkpoint_a_browser_boundary.mjs';
import { KEYBOARD_STEPS, keyboardAssets, keyboardRequestAllowed, keyboardResponseAllowed,
  validateFocus, validateKeyboardProof } from '../../scripts/checkpoint_a_keyboard_boundary.mjs';
import { fixedEnvironment, deniedConnection, startTunnel, proveSandbox, auditSurface } from './checkpoint_a_browser.mjs';
import { launchOptions } from './checkpoint_a_tls.mjs';

// Only finite booleans leave the actual document. No outerHTML, labels, selectors,
// exception text or active-element contents are serialized.
export async function focusState(page) {
  return validateFocus(await page.evaluate(() => {
    const active = document.activeElement;
    return { dialogOpen: document.querySelector('dialog.command-dialog')?.open === true,
      documentFocused: document.hasFocus(), visible: document.visibilityState === 'visible',
      triggerFocused: active?.matches('button.command-trigger') === true,
      searchFocused: active?.matches('dialog.command-dialog input') === true,
      teamsFocused: active?.matches('button.command-result') === true && active.textContent.replace(/\s+/g, '') === 'Teams↵',
      mainFocused: active?.id === 'main-content' };
  }));
}
// Owned unit callbacks can exercise the exact sequence without Playwright/HTTP.
export async function keyboardSequence(actions, observe, report) {
  for (const step of KEYBOARD_STEPS) {
    report.failedStep = step;
    try {
      await actions[step]();
      report.steps.push({ step, state: await observe() });
    } catch {
      try { report.lastState = await observe(); } catch { /* unavailable stays null, never false evidence */ }
      return false;
    }
  }
  report.failedStep = null; return true;
}
export function keyboardActions(page, audit) {
  const trigger = page.getByRole('button', { name: /Search or jump/ });
  const dialog = page.getByRole('dialog', { name: 'Search or jump', exact: true });
  const search = dialog.getByLabel('Search commands', { exact: true });
  return {
    login_shell: async () => {
      const response = await page.goto(ORIGIN + '/', { waitUntil: 'domcontentloaded' });
      check(response?.status() === 200 && response.url() === ORIGIN + '/');
      await page.locator('.product-workspace[aria-busy="false"]').waitFor();
      await page.getByRole('heading', { name: 'Open your workspace', exact: true }).waitFor();
      check(await page.getByRole('button', { name: 'Sign out', exact: true }).count() === 0);
    },
    trigger_focus: () => trigger.focus(),
    first_open: async () => { await page.keyboard.press('Control+k'); await dialog.waitFor(); },
    search_focus: async () => { check(await search.evaluate((element) => element === document.activeElement)); },
    audit,
    escape: () => page.keyboard.press('Escape'),
    hidden: () => dialog.waitFor({ state: 'hidden' }),
    return_focus: () => page.waitForFunction(() => document.activeElement?.matches('button.command-trigger')),
    second_open: async () => { await page.keyboard.press('Control+k'); await dialog.waitFor(); },
    filter: () => search.fill('Teams'),
    tab: async () => {
      await search.press('Tab');
      check(await dialog.getByRole('button', { name: 'Teams', exact: true }).evaluate((element) => element === document.activeElement));
    },
    enter: () => page.keyboard.press('Enter'),
    route: async () => { await page.waitForURL(ORIGIN + '/teams'); await dialog.waitFor({ state: 'hidden' }); },
    skip: async () => {
      const skip = page.getByRole('link', { name: 'Skip to content', exact: true });
      await skip.focus(); await skip.press('Enter');
      await page.waitForFunction(() => document.activeElement?.id === 'main-content');
    },
  };
}
export async function main() {
  const proof = { format: 'stead-checkpoint-a-keyboard-proof-v1', passed: false, phase: 'namespace',
    networkIsolated: false, rendererSandbox: false, csp: false, browserCleanup: false,
    steps: [], failedStep: null, lastState: null, sent: 0, responses: 0, blocked: 0, sessions: 0, axeObserved: false };
  let browser, tunnel, timer, failed = false;
  const pending = new Set();
  try {
    check(process.getuid() === 1000 && process.argv.length === 2);
    check(/^Max core file size[ \t]+0[ \t]+0[ \t]+bytes[ \t]*$/m.test(await readFile('/proc/self/limits', 'utf8')));
    const routes = await readFile('/proc/net/route', 'utf8');
    check(!routes.split('\n').slice(1).some((line) => line.trim().split(/\s+/)[1] === '00000000'));
    check(await deniedConnection('192.0.2.1', 443));
    check((await Promise.all([15432, 13000, 18080, 18081, 14222, 18222, 18000, 18001, 18443]
      .map((port) => deniedConnection('127.0.0.1', port)))).every(Boolean));
    proof.networkIsolated = true; timer = setTimeout(() => process.exit(1), 110_000);
    tunnel = await startTunnel(); proof.phase = 'trust';
    const { home, database, commands } = serverTrustCommands('peer');
    await mkdir(database, { recursive: true, mode: 0o700 });
    for (const args of commands) {
      const result = spawnSync('/usr/bin/certutil', args, { env: fixedEnvironment(home), timeout: 3000, stdio: 'ignore' });
      check(result.status === 0 && !result.signal && !result.error);
    }
    const assets = keyboardAssets(JSON.parse(await readFile('/fixture/keyboard-assets.json', 'utf8')));
    const axe = await readFile('/tools/axe-core/axe.min.js');
    check(sha256(axe) === JSON.parse(await readFile('/fixture/axe-pin.json', 'utf8')).sha256);
    const { chromium } = await import('/tools/playwright-core/index.mjs');
    proof.phase = 'browser'; browser = await chromium.launch(launchOptions('peer'));
    check(browser.version() === '152.0.7977.82');
    const contexts = [], pages = [], dispatched = new Set();
    for (let i = 0; i < 2; i++) contexts.push(await browser.newContext({ viewport: { width: 1280, height: 900 },
      locale: 'en-US', timezoneId: 'UTC', serviceWorkers: 'block', acceptDownloads: false }));
    // Match original creation order: both contexts exist, then primary page,
    // then unused second page. No bringToFront, sleep, focus patch or login.
    for (const context of contexts) {
      await context.route(() => true, async (route) => {
        try {
          const req = route.request(), url = req.url();
          check(context === contexts[0] && keyboardRequestAllowed(req.method(), url, req.resourceType(), req.isNavigationRequest(), await req.allHeaders(), assets));
          check(!dispatched.has(url) && proof.sent < 32); dispatched.add(url); proof.sent++;
          await route.continue();
        } catch { proof.blocked = Math.min(64, proof.blocked + 1); failed = true; await route.abort('blockedbyclient').catch(() => {}); }
      });
      context.on('response', (response) => {
        const job = (async () => {
          const headers = await response.allHeaders();
          check(proof.responses < 32 && keyboardResponseAllowed(response.url(), response.status(), headers, assets));
          proof.responses++;
          if (response.url() === ORIGIN + '/api/v1/session') proof.sessions++;
          if (response.request().resourceType() === 'document') { check(headers['content-security-policy'] === CSP); proof.csp = true; }
        })().catch(() => { failed = true; });
        pending.add(job); void job.finally(() => pending.delete(job));
      });
      context.on('page', (page) => {
        page.setDefaultTimeout(10_000); page.setDefaultNavigationTimeout(10_000);
        page.on('websocket', () => { failed = true; });
        page.on('download', (download) => { failed = true; void download.cancel().catch(() => {}); });
      });
      pages.push(await context.newPage());
    }
    proof.phase = 'keyboard';
    const complete = await keyboardSequence(keyboardActions(pages[0], async () => {
      await proveSandbox(browser); proof.rendererSandbox = true;
      await auditSurface(pages[0], 'command_palette', axe.toString('utf8')); proof.axeObserved = true;
    }), () => focusState(pages[0]), proof);
    await Promise.all([...pending]);
    check(complete && !failed && proof.sessions === 1 && proof.sent === proof.responses && proof.csp && tunnel.good());
    check(contexts.every((context) => context.pages().length === 1));
  } catch { failed = true; }
  finally {
    // Keep the first phase/substep on failure; cleanup never hides it.
    try {
      if (browser) await Promise.race([browser.close(), new Promise((_, reject) => setTimeout(() => reject(new Error('close')), 5000).unref())]);
      proof.browserCleanup = true;
    } catch { failed = true; }
    try { if (tunnel) await tunnel.close(); } catch { failed = true; }
    await Promise.all([...pending]); clearTimeout(timer);
  }
  if (!failed) { proof.passed = true; proof.phase = 'complete'; }
  await writeFile('/work/result.json', JSON.stringify(validateKeyboardProof(proof)) + '\n', { mode: 0o600, flag: 'wx' });
  process.exitCode = proof.passed ? 0 : 1;
}
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(() => { process.exitCode = 1; });
}
