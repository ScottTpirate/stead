import { act, cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, beforeEach, expect, it, vi } from "vitest";

import { PlatformApiError, type PlatformResponse, type PlatformRequestOptions } from "../../../packages/api-client/src/index";
import { Foundation } from "./Foundation";
import { type FrontendMetric, startBrowserPerformanceInstrumentation } from "./performance";
import { platformClient } from "./platform";

// Deterministic UI readiness tests only, not browser/golden latency evidence.
const session = {
  principal: { type: "user", id: "fixture-user" }, instance_id: "fixture-instance",
  expires_at: new Date(Date.now() + 3_600_000).toISOString(), session_revision: 1,
};
const organization = {
  id: "fixture-org", kind: "organization", title: "Authorized Organization", key: "ORG",
  version: 1, security_presentation: { markings: [] },
};
const team = { ...organization, kind: "team", id: "fixture-team", title: "Authorized Team" };
const project = { ...organization, kind: "project", id: "fixture-project", title: "Authorized Project" };

function deferred() {
  let resolve!: (value: PlatformResponse<unknown>) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<PlatformResponse<unknown>>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}

let requests: Map<string, ReturnType<typeof deferred>>;
let metrics: FrontendMetric[];
let frames: Map<number, FrameRequestCallback>;
let nextFrame: number;
let now: number;
let stop: () => void;
const record = (event: CustomEvent<FrontendMetric>) => { metrics.push(event.detail); };
const samples = (name: FrontendMetric["name"]) => metrics.filter((metric) => metric.name === name).map((metric) => metric.value);
const workspaceBusy = () => document.querySelector(".product-workspace")?.getAttribute("aria-busy");

beforeEach(() => {
  requests = new Map(["getSession", "listOrganizations", "listTeams", "listProjects", "createTeam", "deleteSession"].map((operation) => [operation, deferred()]));
  metrics = []; frames = new Map(); nextFrame = 0; now = 10;
  vi.spyOn(performance, "now").mockImplementation(() => now);
  vi.spyOn(window, "requestAnimationFrame").mockImplementation((callback) => {
    frames.set(++nextFrame, callback); return nextFrame;
  });
  vi.spyOn(window, "cancelAnimationFrame").mockImplementation((id) => { frames.delete(id); });
  vi.stubGlobal("PerformanceObserver", class { static supportedEntryTypes: string[] = []; });
  vi.spyOn(platformClient, "request").mockImplementation(async <T,>(operation: string) => {
    const request = requests.get(operation);
    if (!request) throw new Error("unexpected fixture operation");
    return await request.promise as PlatformResponse<T>;
  });
  window.addEventListener("stead:performance", record);
  stop = startBrowserPerformanceInstrumentation();
});

afterEach(() => {
  cleanup(); stop();
  window.removeEventListener("stead:performance", record);
  vi.restoreAllMocks(); vi.unstubAllGlobals();
  window.history.replaceState(null, "", "/");
});

async function resolve(operation: string, data: unknown, at: number) {
  now = at;
  await act(async () => { requests.get(operation)!.resolve({ data, status: 200, responseBytes: 0 }); });
}

async function reject(operation: string, status: number, at: number) {
  now = at;
  await act(async () => { requests.get(operation)!.reject(new PlatformApiError(status)); });
}

function frame(at: number) {
  now = at;
  act(() => {
    const callbacks = [...frames.values()]; frames.clear();
    for (const callback of callbacks) callback(at);
  });
}

function open(path = "/projects") {
  window.history.replaceState(null, "", path);
  render(<Foundation />);
}

function navigate(name: string, at: number) {
  now = at;
  fireEvent.click(within(screen.getByRole("navigation", { name: "Primary navigation" })).getByRole("link", { name }));
}

async function authorizedOrganization() {
  await resolve("getSession", session, 20);
  await resolve("listOrganizations", { items: [organization] }, 30);
}

it("acknowledges the shell before delayed data, then separates useful content from usable controls", async () => {
  open();
  expect(samples("cold-shell-acknowledgement")).toEqual([10]);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
  await authorizedOrganization();
  expect(workspaceBusy()).toBe("true");
  // Pending presentation does not disable controls that remain usable.
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(false);
  expect((screen.getByLabelText("Organization") as HTMLSelectElement).disabled).toBe(false);
  frame(40); frame(50);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
  await resolve("listTeams", { items: [team] }, 60);
  expect(workspaceBusy()).toBe("true");
  expect(samples("cold-useful-content")).toEqual([]);
  await resolve("listProjects", { items: [project] }, 70);
  expect(workspaceBusy()).toBe("false");
  expect(screen.getByRole("button", { name: "ORG Authorized Project" })).toBeDefined();
  expect(samples("cold-useful-content")).toEqual([70]);
  expect(samples("cold-interactive")).toEqual([]);
  frame(80);
  expect(samples("cold-interactive")).toEqual([]);
  frame(90);
  expect(samples("cold-interactive")).toEqual([90]);
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(false);
});

it("counts an authoritative empty Organization result without making unauthorized downstream calls", async () => {
  open();
  await resolve("getSession", session, 20);
  frame(30); frame(40);
  expect(samples("cold-useful-content")).toEqual([]);
  await resolve("listOrganizations", { items: [] }, 50);
  expect(workspaceBusy()).toBe("false");
  expect(screen.getByText("No authorized projects to show yet.")).toBeDefined();
  expect(samples("cold-useful-content")).toEqual([50]);
  expect(vi.mocked(platformClient.request).mock.calls.map(([operation]) => operation)).toEqual(["getSession", "listOrganizations"]);
  frame(60); frame(70);
  expect(samples("cold-interactive")).toEqual([70]);
});

it.each(["teams", "projects"])("does not confuse pending %s with an authoritative empty collection", async (area) => {
  open(`/${area}`); await authorizedOrganization();
  expect(screen.getByText(`No authorized ${area} to show yet.`)).toBeDefined();
  expect(workspaceBusy()).toBe("true");
  expect(samples("cold-useful-content")).toEqual([]);
  await resolve("listTeams", { items: [] }, 40);
  expect(workspaceBusy()).toBe("true");
  await resolve("listProjects", { items: [] }, 50);
  expect(workspaceBusy()).toBe("false");
  expect(samples("cold-useful-content")).toEqual([50]);
  frame(60); frame(70);
  expect(samples("cold-interactive")).toEqual([70]);
});

it.each(["getSession", "listOrganizations", "listTeams", "listProjects"])("never records loading/error UI as successful content or interactivity when %s fails", async (operation) => {
  open();
  if (operation !== "getSession") await resolve("getSession", session, 20);
  if (operation === "listTeams" || operation === "listProjects") {
    await resolve("listOrganizations", { items: [organization] }, 30);
    // Keep the sibling request pending: a failed logical collection load must
    // still expose its error announcement outside an aria-busy region.
  }
  await reject(operation, 503, 50);
  expect(screen.getByRole("alert")).toBeDefined();
  expect(workspaceBusy()).toBe("false");
  frame(60); frame(70);
  expect(samples("cold-shell-acknowledgement")).toEqual([10]);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
});

it("measures a cached shell navigation independently of delayed useful Project content", async () => {
  open("/"); await authorizedOrganization();
  // Home's primary Organization content must not wait for secondary collections.
  expect(workspaceBusy()).toBe("false");
  expect(samples("cold-useful-content")).toEqual([30]);
  frame(40); frame(50);
  navigate("Projects", 60);
  expect(workspaceBusy()).toBe("true");
  expect(samples("route-shell-acknowledgement")).toEqual([0]);
  expect(samples("route-useful-content")).toEqual([]);
  frame(70); frame(80);
  expect(samples("route-interactive")).toEqual([]);
  await resolve("listTeams", { items: [team] }, 90);
  await resolve("listProjects", { items: [project] }, 100);
  expect(workspaceBusy()).toBe("false");
  expect(samples("route-useful-content")).toEqual([40]);
  frame(110); frame(120);
  expect(samples("route-interactive")).toEqual([60]);
});

it("does not mark an undisplayed collection as pending on Home or a placeholder route", async () => {
  open("/"); await authorizedOrganization();
  expect(workspaceBusy()).toBe("false");
  navigate("Teams", 40);
  expect(workspaceBusy()).toBe("true");
  navigate("Knowledge", 50);
  expect(workspaceBusy()).toBe("false");
  navigate("Home", 60);
  expect(workspaceBusy()).toBe("false");
  expect(samples("cold-useful-content")).toEqual([30]);
  expect(samples("route-useful-content")).toEqual([0]);
});

it.each(["teams", "projects"])("keeps Refresh busy through delayed displayed %s without disabling usable controls", async (area) => {
  open(`/${area}`); await authorizedOrganization();
  await resolve("listTeams", { items: [team] }, 40);
  await resolve("listProjects", { items: [project] }, 50);
  frame(60); frame(70);
  expect(workspaceBusy()).toBe("false");
  for (const operation of ["listOrganizations", "listTeams", "listProjects"]) requests.set(operation, deferred());
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  expect(workspaceBusy()).toBe("true");
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(true);
  await resolve("listOrganizations", { items: [organization] }, 80);
  expect(workspaceBusy()).toBe("true");
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(false);
  await resolve("listProjects", { items: [] }, 90);
  expect(workspaceBusy()).toBe("true");
  await resolve("listTeams", { items: [] }, 100);
  expect(workspaceBusy()).toBe("false");
  expect(screen.getByText(`No authorized ${area} to show yet.`)).toBeDefined();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(vi.mocked(platformClient.request).mock.calls.filter(([operation]) => operation === "listTeams")).toHaveLength(2);
  expect(vi.mocked(platformClient.request).mock.calls.filter(([operation]) => operation === "listProjects")).toHaveLength(2);
  frame(110); frame(120);
  expect(samples("cold-useful-content")).toEqual([50]);
  expect(samples("cold-interactive")).toEqual([70]);
  expect(samples("route-useful-content")).toEqual([]);
  expect(samples("route-interactive")).toEqual([]);
});

it("keeps a settled collection failure non-busy after another action clears its alert", async () => {
  open("/teams"); await authorizedOrganization();
  await resolve("listTeams", { items: [team] }, 40);
  await reject("listProjects", 503, 50);
  expect(workspaceBusy()).toBe("false");
  expect(screen.getByRole("alert")).toBeDefined();
  fireEvent.change(screen.getByLabelText("Key"), { target: { value: "NEW" } });
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New Team" } });
  fireEvent.submit(screen.getByRole("button", { name: "Create Team" }).closest("form")!);
  expect(screen.queryByRole("alert")).toBeNull();
  expect(workspaceBusy()).toBe("true");
  await resolve("createTeam", team, 60);
  expect(workspaceBusy()).toBe("false");
  frame(70); frame(80);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
});

it("cancels a superseded ready render before its interactivity sample and does not count placeholders", async () => {
  open("/"); await authorizedOrganization();
  await resolve("listTeams", { items: [team] }, 40);
  await resolve("listProjects", { items: [project] }, 50);
  frame(60); frame(70);
  navigate("Projects", 80);
  expect(samples("route-useful-content")).toEqual([0]);
  frame(90);
  navigate("Knowledge", 100);
  frame(110); frame(120);
  expect(samples("route-shell-acknowledgement")).toEqual([0, 0]);
  expect(samples("route-useful-content")).toEqual([0]);
  expect(samples("route-interactive")).toEqual([]);
});

it("counts a resolved sign-in surface as interactive, never as authorized content", async () => {
  open();
  await reject("getSession", 401, 20);
  expect(screen.getByRole("button", { name: "Sign in" })).toBeDefined();
  expect(samples("cold-useful-content")).toEqual([]);
  frame(30); frame(40);
  expect(samples("cold-interactive")).toEqual([40]);
});

it.each([true, false])("cancels unmatched-route cold spans before a later rendered sign-in form (session resolves while unmatched: %s)", async (resolveWhileUnmatched) => {
  open("/unavailable-route");
  expect(screen.getByText("This view is unavailable")).toBeDefined();
  expect(screen.queryByRole("button", { name: "Sign in" })).toBeNull();
  if (resolveWhileUnmatched) await reject("getSession", 401, 20);
  frame(30); frame(40);
  expect(samples("cold-shell-acknowledgement")).toEqual([10]);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
  navigate("Home", 50);
  if (!resolveWhileUnmatched) await reject("getSession", 401, 60);
  expect(screen.getByRole("button", { name: "Sign in" })).toBeDefined();
  frame(70); frame(80);
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
  expect(samples("route-shell-acknowledgement")).toEqual([0]);
  expect(samples("route-useful-content")).toEqual([]);
  expect(samples("route-interactive")).toEqual([30]);
});

it("does not finish an authorized-view timing after logout replaces that view", async () => {
  open("/"); await authorizedOrganization();
  frame(40);
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }));
  await resolve("deleteSession", {}, 50);
  expect(screen.getByRole("button", { name: "Sign in" })).toBeDefined();
  frame(60); frame(70);
  expect(samples("cold-useful-content")).toEqual([30]);
  expect(samples("cold-interactive")).toEqual([]);
});

it("starts route markers for history navigation, not a duplicate popstate on the same pathname", async () => {
  open("/"); await authorizedOrganization();
  await resolve("listTeams", { items: [team] }, 40);
  await resolve("listProjects", { items: [project] }, 50);
  frame(60); frame(70);
  now = 80;
  act(() => {
    window.history.replaceState(null, "", "/projects");
    window.dispatchEvent(new PopStateEvent("popstate"));
  });
  expect(samples("route-navigation-count")).toHaveLength(1);
  const firstCount = samples("route-navigation-count")[0];
  expect(samples("route-shell-acknowledgement")).toEqual([0]);
  expect(samples("route-useful-content")).toEqual([0]);
  act(() => { window.dispatchEvent(new PopStateEvent("popstate")); });
  frame(90); frame(100);
  expect(samples("route-navigation-count")).toEqual([firstCount]);
  expect(samples("route-interactive")).toEqual([20]);
});

it.each(["resolve", "reject"])("ignores late collections that %s from a prior Organization and waits for the newly selected scope", async (outcome) => {
  const otherOrganization = { ...organization, id: "fixture-other-org", title: "Other Organization" };
  const otherTeams = deferred(), otherProjects = deferred();
  vi.mocked(platformClient.request).mockImplementation(async <T,>(operation: string, options?: PlatformRequestOptions) => {
    const request = options?.path?.organization_id === otherOrganization.id
      ? operation === "listTeams" ? otherTeams : otherProjects
      : requests.get(operation)!;
    return await request.promise as PlatformResponse<T>;
  });
  open();
  await resolve("getSession", session, 20);
  await resolve("listOrganizations", { items: [organization, otherOrganization] }, 30);
  fireEvent.change(screen.getByLabelText("Organization"), { target: { value: otherOrganization.id } });
  expect(workspaceBusy()).toBe("true");
  if (outcome === "resolve") {
    await resolve("listTeams", { items: [team] }, 40);
    await resolve("listProjects", { items: [project] }, 50);
  } else await reject("listProjects", 503, 50);
  frame(60); frame(70);
  expect(screen.queryByRole("button", { name: "ORG Authorized Project" })).toBeNull();
  expect(screen.queryByRole("alert")).toBeNull();
  expect(samples("cold-useful-content")).toEqual([]);
  expect(samples("cold-interactive")).toEqual([]);
  expect(workspaceBusy()).toBe("true");
  now = 80;
  await act(async () => {
    otherTeams.resolve({ data: { items: [] }, status: 200, responseBytes: 0 });
    otherProjects.resolve({ data: { items: [] }, status: 200, responseBytes: 0 });
  });
  expect(samples("cold-useful-content")).toEqual([80]);
  expect(workspaceBusy()).toBe("false");
  frame(90); frame(100);
  expect(samples("cold-interactive")).toEqual([100]);
});

it.each(["resolve", "reject"])("ignores a superseded same-Organization batch that later %s after Refresh", async (outcome) => {
  open(); await authorizedOrganization();
  const oldTeams = requests.get("listTeams")!, oldProjects = requests.get("listProjects")!;
  requests.set("listTeams", deferred()); requests.set("listProjects", deferred());
  fireEvent.click(screen.getByRole("button", { name: "Refresh" }));
  await act(async () => {});
  expect(workspaceBusy()).toBe("true");
  await act(async () => {
    if (outcome === "resolve") {
      oldTeams.resolve({ data: { items: [team] }, status: 200, responseBytes: 0 });
      oldProjects.resolve({ data: { items: [project] }, status: 200, responseBytes: 0 });
    } else oldProjects.reject(new PlatformApiError(503));
  });
  expect(workspaceBusy()).toBe("true");
  expect(screen.queryByRole("alert")).toBeNull();
  expect(samples("cold-useful-content")).toEqual([]);
  await resolve("listTeams", { items: [] }, 40);
  await resolve("listProjects", { items: [] }, 50);
  expect(workspaceBusy()).toBe("false");
  expect(samples("cold-useful-content")).toEqual([50]);
});

it("can show authorized route content while a mutation still disables controls, but waits to mark interactivity", async () => {
  open("/teams"); await authorizedOrganization();
  await resolve("listTeams", { items: [team] }, 40);
  await resolve("listProjects", { items: [project] }, 50);
  frame(60); frame(70);
  fireEvent.change(screen.getByLabelText("Key"), { target: { value: "NEW" } });
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "New Team" } });
  fireEvent.submit(screen.getByRole("button", { name: "Create Team" }).closest("form")!);
  navigate("Projects", 80);
  expect(samples("route-useful-content")).toEqual([0]);
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(true);
  frame(90); frame(100);
  expect(samples("route-interactive")).toEqual([]);
  await resolve("createTeam", team, 110);
  frame(120); frame(130);
  expect(samples("route-interactive")).toEqual([50]);
  expect((screen.getByRole("button", { name: "Refresh" }) as HTMLButtonElement).disabled).toBe(false);
});
