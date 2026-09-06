// Original Stead Checkpoint A journey. Importing this file does not execute it.
// The reviewed controller supplies two NEW, empty, isolated contexts, validated
// private TLS, disabled tracing/video/log capture, and fresh one-use credentials.
// It owns acquisition, activation, network confinement, deadlines and cleanup.
// Never retry this function after a possibly dispatched login or mutation.
// Contexts/pages remain with the controller on success AND failure: no logout,
// screenshots, traces, response bodies or credential file reads. A reviewed
// controller may preserve only the established session via afterLogin.

import { JOURNEY_KEYBOARD_SUBSTEPS } from '../../scripts/checkpoint_a_browser_boundary.mjs';

const ORIGIN = "https://localhost:18443";
const TIMEOUT = 10_000;
const LIMIT = 256;
const usedContexts = new WeakSet();
const SYNTHETIC = Object.freeze({
  organization: { key: "BJA7ORG", title: "Browser Journey A7 Organization" },
  parent: { key: "BJA7PAR", title: "Browser Journey A7 Parent Team" },
  child: { key: "BJA7CHD", title: "Browser Journey A7 Child Team" },
  project: {
    key: "BJA7PRJ", title: "Browser Journey A7 General Project",
    purpose: "Synthetic browser-only Checkpoint A persistence verification.",
  },
  denied: { key: "BJA7DEN", title: "Browser Journey A7 Denied Organization" },
});
const NAVIGATION = Object.freeze([
  ["Home", "/"], ["Inbox", "/inbox"], ["My Work", "/my-work"],
  ["Projects", "/projects"], ["Knowledge", "/knowledge"], ["Teams", "/teams"],
]);
const OPERATIONS = Object.freeze({
  session_get: ["GET", /^\/api\/v1\/session$/],
  session_create: ["POST", /^\/api\/v1\/session$/],
  organization_list: ["GET", /^\/api\/v1\/organizations$/],
  organization_create: ["POST", /^\/api\/v1\/organizations$/],
  organization_read: ["GET", /^\/api\/v1\/organizations\/[0-9a-f-]{36}$/],
  team_list: ["GET", /^\/api\/v1\/organizations\/[0-9a-f-]{36}\/teams$/],
  team_create: ["POST", /^\/api\/v1\/organizations\/[0-9a-f-]{36}\/teams$/],
  team_read: ["GET", /^\/api\/v1\/teams\/[0-9a-f-]{36}$/],
  project_list: ["GET", /^\/api\/v1\/organizations\/[0-9a-f-]{36}\/projects$/],
  project_create: ["POST", /^\/api\/v1\/organizations\/[0-9a-f-]{36}\/projects$/],
  project_read: ["GET", /^\/api\/v1\/projects\/[0-9a-f-]{36}$/],
});
const GENERIC_DENIAL = "The request could not be completed. Please refresh or try again.";

function requireCondition(condition) {
  if (!condition) throw new Error("journey_check_failed");
}

// Native SELECT labels contain option text in Playwright's label-text engine.
// Match the control's semantic accessible name, not its label's descendants.
export function workspaceSelect(page, name) {
  requireCondition(["Organization", "Parent Team", "Owning Team"].includes(name));
  return page.getByRole("combobox", { name, exact: true });
}

function matches(request, operation) {
  const url = new URL(request.url());
  const [method, path] = OPERATIONS[operation];
  return url.origin === ORIGIN && !url.username && !url.password &&
    request.method() === method && path.test(url.pathname);
}

// Counters only; do not retain URLs, requests, responses or their secret fields.
function observe(page) {
  const counts = Object.fromEntries(Object.keys(OPERATIONS).map((key) => [key, 0]));
  const stats = { requests: 0, responses: 0, failed: 0, forbidden: 0, unknownAPI: 0, overflow: false };
  const increment = (object, key) => {
    if (object[key] >= LIMIT) stats.overflow = true;
    else object[key] += 1;
  };
  const request = (value) => {
    try {
      increment(stats, "requests");
      const url = new URL(value.url());
      if (url.origin !== ORIGIN || url.username || url.password) increment(stats, "forbidden");
      if (url.pathname.startsWith("/api/")) {
        const key = Object.keys(OPERATIONS).find((candidate) => matches(value, candidate));
        if (key) increment(counts, key);
        else increment(stats, "unknownAPI");
      }
    } catch { stats.overflow = true; }
  };
  const response = () => { increment(stats, "responses"); };
  const failed = () => { increment(stats, "failed"); };
  const websocket = () => { increment(stats, "forbidden"); };
  page.on("request", request);
  page.on("response", response);
  page.on("requestfailed", failed);
  page.on("websocket", websocket);
  return {
    counts, stats,
    stop() {
      page.off("request", request); page.off("response", response);
      page.off("requestfailed", failed); page.off("websocket", websocket);
    },
  };
}

async function settled(page) {
  await page.locator('.product-workspace[aria-busy="false"]').waitFor();
  requireCondition(new URL(page.url()).origin === ORIGIN);
  requireCondition(await page.getByRole("alert").count() === 0);
}

async function actionWithResponses(page, expectations, action) {
  // Install all observers BEFORE the one UI action; no API dispatch here.
  await Promise.all([
    ...expectations.map(async ([operation, status]) => {
      const response = await page.waitForResponse((value) => matches(value.request(), operation), { timeout: TIMEOUT });
      requireCondition(response.status() === status);
    }),
    action(),
  ]);
}

function resource(page, title) {
  return page.locator(".resource-list").getByRole("button").filter({
    has: page.getByText(title, { exact: true }),
  });
}

async function navigate(page, label, keyboard = false) {
  const entry = NAVIGATION.find(([name]) => name === label);
  requireCondition(Boolean(entry));
  const link = page.getByRole("navigation", { name: "Primary navigation" })
    .getByRole("link", { name: label, exact: true });
  if (keyboard) { await link.focus(); await link.press("Enter"); }
  else await link.click();
  await page.waitForURL(ORIGIN + entry[1]);
  await page.getByRole("heading", { name: label, level: 1, exact: true }).waitFor();
  await settled(page);
}

async function readDetails(page, item, kind) {
  await resource(page, item.title).waitFor();
  await actionWithResponses(page, [[`${kind}_read`, 200]], () => resource(page, item.title).click());
  await settled(page);
  const details = page.getByRole("region", { name: "Resource details" });
  await details.getByRole("heading", { name: item.title, level: 2, exact: true }).waitFor();
  requireCondition(await details.locator("p").first().evaluate((element) =>
    Boolean(element.textContent?.trim()) && element.textContent.length <= 1024));
  if (kind === "project") {
    await details.getByText(item.purpose, { exact: true }).waitFor();
    await details.getByText("Capabilities: work, docs", { exact: true }).waitFor();
  } else {
    await details.getByText(new RegExp(`^${kind} · version [1-9][0-9]*$`)).waitFor();
  }
  await details.getByText("Read from Stead after central authorization.", { exact: true }).waitFor();
}

async function emptyOrganization(page) {
  await settled(page);
  const organization = workspaceSelect(page, "Organization");
  requireCondition(await organization.isDisabled());
  requireCondition(await organization.locator("option").count() === 1);
  requireCondition(await organization.inputValue() === "");
  requireCondition(await organization.locator("option").textContent() === "Create your first Organization");
  requireCondition(await page.locator(".resource-list button").count() === 0);
  requireCondition(await page.getByRole("region", { name: "Resource details" }).count() === 0);
}

// The controller owns exact-source CDP instrumentation in a CSP-preserving
// isolated world. Never add script tags, bypass CSP or return protected DOM.
async function axeSurface(page, auditSurface, surface) {
  if (!auditSurface) return null;
  return auditSurface(page, surface);
}

// Fixed substep identifier only; no exception, locator, DOM, or secret is read.
// Preserve the first failing action without retries or changing its assertions.
export async function keyboardSubsteps(actions, evidence) {
  for (const name of JOURNEY_KEYBOARD_SUBSTEPS) {
    evidence.failedKeyboardSubstep = name;
    await actions[name]();
  }
  evidence.failedKeyboardSubstep = null;
}

/**
 * Future reviewed controller entry point; never auto-executed.
 * Credentials are used once and not saved. JS strings cannot be zeroized; the
 * controller must avoid logging arguments and must own final process disposal.
 * Output is only closed stage IDs, scalar counters/timings and bounded axe rule
 * metadata. Failure is intentionally generic; do not replace it with raw errors.
 * No result constitutes SQL/FGA proof, known/unknown denial proof, provider
 * readiness, complete accessibility, or a phase/release acceptance.
 */
export async function runCheckpointAJourney({
  primaryContext, deniedContext, primaryCredential, deniedCredential, auditSurface = null, afterLogin = null,
} = {}) {
  let stage = "preflight";
  const completed = [], accessibility = [], timings = [];
  const observations = [];
  const keyboardEvidence = { failedKeyboardSubstep: null };
  const start = Date.now();
  let status = "failed";
  async function step(name, task) {
    stage = name;
    const began = Date.now();
    await task();
    requireCondition(Date.now() - start < 240_000);
    for (const observer of observations) requireCondition(
      !observer.stats.overflow && observer.stats.forbidden === 0 && observer.stats.unknownAPI === 0);
    completed.push(name);
    timings.push({ stage: name, elapsedMs: Math.min(240_000, Math.max(0, Date.now() - began)) });
  }
  async function audit(page, surface) {
    const result = await axeSurface(page, auditSurface, surface);
    if (result) accessibility.push(result);
  }
  async function login(page, credential, beforeLogin) {
    await page.goto(ORIGIN + "/", { waitUntil: "domcontentloaded" });
    await settled(page);
    await page.getByRole("heading", { name: "Open your workspace", exact: true }).waitFor();
    requireCondition(await page.getByRole("button", { name: "Sign out", exact: true }).count() === 0);
    if (beforeLogin) await audit(page, "primary_login");
    await page.getByLabel("Setup credential", { exact: true }).fill(credential);
    credential = "";
    await actionWithResponses(page, [["organization_list", 200]], () => Promise.all([
      (async () => {
        const response = await page.waitForResponse((value) => matches(value.request(), "session_create"), { timeout: TIMEOUT });
        requireCondition(response.status() === 200);
        requireCondition(await response.finished() === null);
        if (afterLogin) await afterLogin(page.context(), beforeLogin ? "primary" : "denied");
      })(),
      page.getByRole("button", { name: "Sign in", exact: true }).click(),
    ]));
    await page.getByRole("button", { name: "Sign out", exact: true }).waitFor();
    await emptyOrganization(page);
    requireCondition(await page.getByLabel("Setup credential", { exact: true }).count() === 0);
  }
  try {
    requireCondition(primaryContext && deniedContext && primaryContext !== deniedContext);
    requireCondition(primaryContext.browser() && primaryContext.browser() === deniedContext.browser());
    requireCondition(primaryContext.pages().length === 0 && deniedContext.pages().length === 0);
    requireCondition(!usedContexts.has(primaryContext) && !usedContexts.has(deniedContext));
    requireCondition(typeof primaryCredential === "string" && /^[A-Za-z0-9_-]{43}$/.test(primaryCredential));
    requireCondition(typeof deniedCredential === "string" && /^[A-Za-z0-9_-]{43}$/.test(deniedCredential));
    requireCondition(primaryCredential !== deniedCredential);
    requireCondition(auditSurface === null || typeof auditSurface === "function");
    requireCondition(afterLogin === null || typeof afterLogin === "function");
    usedContexts.add(primaryContext); usedContexts.add(deniedContext);
    const primary = await primaryContext.newPage(), denied = await deniedContext.newPage();
    for (const page of [primary, denied]) {
      page.setDefaultTimeout(TIMEOUT); page.setDefaultNavigationTimeout(15_000);
      observations.push(observe(page));
    }
    await step("primary_login", async () => { await login(primary, primaryCredential, true); primaryCredential = ""; });
    await step("organization_create_read", async () => {
      await primary.getByLabel("Key", { exact: true }).fill(SYNTHETIC.organization.key);
      await primary.getByLabel("Name", { exact: true }).fill(SYNTHETIC.organization.title);
      await actionWithResponses(primary, [["organization_create", 201], ["team_list", 200], ["project_list", 200]],
        () => primary.getByRole("button", { name: "Create Organization", exact: true }).click());
      await settled(primary);
      requireCondition(await workspaceSelect(primary, "Organization").locator("option").count() === 1);
      await readDetails(primary, SYNTHETIC.organization, "organization");
      await audit(primary, "organization_detail");
    });
    await step("parent_team_create_read", async () => {
      await navigate(primary, "Teams", true);
      await primary.getByLabel("Key", { exact: true }).fill(SYNTHETIC.parent.key);
      await primary.getByLabel("Name", { exact: true }).fill(SYNTHETIC.parent.title);
      await workspaceSelect(primary, "Parent Team").selectOption({ label: "No parent" });
      await actionWithResponses(primary, [["team_create", 201], ["team_list", 200]],
        () => primary.getByRole("button", { name: "Create Team", exact: true }).click());
      await readDetails(primary, SYNTHETIC.parent, "team");
    });
    await step("child_team_create_read", async () => {
      await primary.getByLabel("Key", { exact: true }).fill(SYNTHETIC.child.key);
      await primary.getByLabel("Name", { exact: true }).fill(SYNTHETIC.child.title);
      await workspaceSelect(primary, "Parent Team").selectOption({ label: SYNTHETIC.parent.title });
      await actionWithResponses(primary, [["team_create", 201], ["team_list", 200]],
        () => primary.getByRole("button", { name: "Create Team", exact: true }).click());
      await resource(primary, SYNTHETIC.child.title).getByText("Child Team · access granted separately", { exact: true }).waitFor();
      await readDetails(primary, SYNTHETIC.child, "team");
      await audit(primary, "child_team_detail");
    });
    await step("general_project_create_read", async () => {
      await navigate(primary, "Projects", true);
      await primary.getByLabel("Key", { exact: true }).fill(SYNTHETIC.project.key);
      await primary.getByLabel("Title", { exact: true }).fill(SYNTHETIC.project.title);
      await primary.getByLabel("Purpose", { exact: true }).fill(SYNTHETIC.project.purpose);
      await workspaceSelect(primary, "Owning Team").selectOption({ label: SYNTHETIC.child.title });
      await actionWithResponses(primary, [["project_create", 201], ["project_list", 200]],
        () => primary.getByRole("button", { name: "Create Project", exact: true }).click());
      await readDetails(primary, SYNTHETIC.project, "project");
      const nav = primary.getByRole("navigation", { name: "Primary navigation" });
      requireCondition(await nav.getByRole("link").count() === NAVIGATION.length);
      for (const [name] of NAVIGATION) requireCondition(await nav.getByRole("link", { name, exact: true }).count() === 1);
      requireCondition(await nav.getByRole("link", { name: /^(Code|Delivery)$/ }).count() === 0);
      await audit(primary, "general_project_detail");
    });
    await step("reload_refresh_read", async () => {
      await actionWithResponses(primary, [["session_get", 200], ["organization_list", 200], ["team_list", 200], ["project_list", 200]],
        () => primary.reload({ waitUntil: "domcontentloaded" }));
      await settled(primary);
      await readDetails(primary, SYNTHETIC.project, "project");
      await actionWithResponses(primary, [["organization_list", 200], ["team_list", 200], ["project_list", 200]],
        () => primary.getByRole("button", { name: "Refresh", exact: true }).click());
      await settled(primary);
      await workspaceSelect(primary, "Owning Team").selectOption({ label: SYNTHETIC.child.title });
      await readDetails(primary, SYNTHETIC.project, "project");
    });
    await step("keyboard_palette_focus", async () => {
      const trigger = primary.getByRole("button", { name: /Search or jump/ });
      const dialog = primary.getByRole("dialog", { name: "Search or jump", exact: true });
      const search = dialog.getByLabel("Search commands", { exact: true });
      const skip = primary.getByRole("link", { name: "Skip to content", exact: true });
      await keyboardSubsteps({
        trigger_focus: () => trigger.focus(),
        first_open_key: () => primary.keyboard.press("Control+k"),
        first_dialog_visible: () => dialog.waitFor(),
        search_focus: async () => requireCondition(await search.evaluate((element) => element === document.activeElement)),
        audit: () => audit(primary, "command_palette"),
        escape_key: () => primary.keyboard.press("Escape"),
        dialog_hidden: () => dialog.waitFor({ state: "hidden" }),
        return_focus: () => primary.waitForFunction(() => document.activeElement?.matches("button.command-trigger")),
        second_open_key: () => primary.keyboard.press("Control+k"),
        second_dialog_visible: () => dialog.waitFor(),
        filter: () => search.fill("Teams"),
        tab_key: () => search.press("Tab"),
        teams_focus: async () => requireCondition(await dialog.getByRole("button", { name: "Teams", exact: true })
          .evaluate((element) => element === document.activeElement)),
        enter_key: () => primary.keyboard.press("Enter"),
        teams_route: () => primary.waitForURL(ORIGIN + "/teams"),
        second_dialog_hidden: () => dialog.waitFor({ state: "hidden" }),
        child_read: () => readDetails(primary, SYNTHETIC.child, "team"),
        skip_focus: () => skip.focus(),
        skip_enter: () => skip.press("Enter"),
        main_focus: () => primary.waitForFunction(() => document.activeElement?.id === "main-content"),
        projects_navigation: () => navigate(primary, "Projects", true),
        project_read: () => readDetails(primary, SYNTHETIC.project, "project"),
      }, keyboardEvidence);
    });
    await step("denied_login_empty_views", async () => {
      await login(denied, deniedCredential, false); deniedCredential = "";
      await denied.getByText("No authorized Organizations to show yet.", { exact: true }).waitFor();
      for (const [name, empty, create] of [
        ["Teams", "No authorized teams to show yet.", "Create Team"],
        ["Projects", "No authorized projects to show yet.", "Create Project"],
      ]) {
        await navigate(denied, name); await emptyOrganization(denied);
        await denied.getByText(empty, { exact: true }).waitFor();
        requireCondition(await denied.getByRole("button", { name: create, exact: true }).count() === 0);
      }
      await audit(denied, "denied_projects_empty");
    });
    await step("denied_organization_mutation", async () => {
      await navigate(denied, "Home");
      await denied.getByLabel("Key", { exact: true }).fill(SYNTHETIC.denied.key);
      await denied.getByLabel("Name", { exact: true }).fill(SYNTHETIC.denied.title);
      await actionWithResponses(denied, [["organization_create", 404]],
        () => denied.getByRole("button", { name: "Create Organization", exact: true }).click());
      await denied.locator('.product-workspace[aria-busy="false"]').waitFor();
      const alert = denied.getByRole("alert");
      await alert.waitFor();
      requireCondition(await alert.count() === 1 && await alert.textContent() === GENERIC_DENIAL);
      requireCondition(await denied.locator(".resource-list button").count() === 0);
      requireCondition(await denied.getByRole("region", { name: "Resource details" }).count() === 0);
      requireCondition(await workspaceSelect(denied, "Organization").isDisabled());
      await audit(denied, "denied_organization_alert");
    });
    await step("one_shot_counts", async () => {
      const [primary, denied] = observations.map((value) => value.counts);
      requireCondition(primary.session_create === 1 && denied.session_create === 1);
      requireCondition(primary.organization_create === 1 && primary.team_create === 2 && primary.project_create === 1);
      requireCondition(denied.organization_create === 1 && denied.team_create === 0 && denied.project_create === 0);
      requireCondition(denied.team_list === 0 && denied.project_list === 0);
      requireCondition(denied.organization_read === 0 && denied.team_read === 0 && denied.project_read === 0);
      requireCondition(primaryContext.pages().length === 1 && deniedContext.pages().length === 1);
    });
    status = "completed";
  } catch {
    // Deliberately do not inspect, print, stringify or return a Playwright error:
    // action diagnostics could contain credential values or protected DOM text.
  } finally {
    primaryCredential = ""; deniedCredential = "";
    for (const observer of observations) observer.stop();
  }
  return {
    format: "stead-checkpoint-a-browser-journey-v2", status,
    failedStage: status === "failed" ? stage : null,
    failedKeyboardSubstep: keyboardEvidence.failedKeyboardSubstep,
    completed, timings,
    elapsedMs: Math.min(240_000, Math.max(0, Date.now() - start)),
    network: observations.map(({ counts, stats }, index) => ({ principal: index === 0 ? "primary" : "denied", counts, ...stats })),
    accessibility: { status: auditSurface ? "collected_if_reached" : "not_requested", surfaces: accessibility },
    denialEvidence: "ui_only_sql_fga_and_known_unknown_checks_are_separate",
    contextsPreserved: true,
  };
}
