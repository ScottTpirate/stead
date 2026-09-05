import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";

import { PlatformApiError, type JsonValue, type PlatformOperationId } from "../../../packages/api-client/src/index";
import { AppShell } from "./AppShell";
import { clearAuthorizedPresentationState, platformClient } from "./platform";
import type { RouteMatch } from "./routes";

interface Session {
  principal: { type: string; id: string };
  instance_id: string;
  expires_at: string;
  session_revision: number;
}

interface Resource {
  id: string;
  kind: "organization" | "team" | "project";
  title: string;
  name?: string;
  key?: string;
  version: number;
  parent_team_id?: string;
  hierarchy_depth?: number;
  purpose?: string;
  authorized_capabilities?: readonly string[];
  security_presentation: { markings: readonly { kind: string; text: string }[] };
}

type MutationForm = "organization" | "team" | "project";
interface ResourcePage { items: Resource[]; next_after?: string }

// Authorized presentation is memory-only. A generation fence prevents responses
// from a prior session or Organization from repopulating a newly cleared view.
export function Workspace({ route, navigate }: { readonly route: RouteMatch; readonly navigate: (href: string) => void }) {
  const [session, setSession] = useState<Session | null>(null);
  const [checking, setChecking] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [organizations, setOrganizations] = useState<Resource[]>([]);
  const [organizationID, setOrganizationID] = useState("");
  const [teams, setTeams] = useState<Resource[]>([]);
  const [projects, setProjects] = useState<Resource[]>([]);
  const [peek, setPeek] = useState<Resource | null>(null);
  const [continuations, setContinuations] = useState<Record<MutationForm, string>>({ organization: "", team: "", project: "" });
  const generation = useRef(0);
  const mutationKey = useRef<{ fingerprint: string; value: string } | null>(null);

  const clear = useCallback(() => {
    generation.current += 1;
    setSession(null);
    setOrganizations([]);
    setOrganizationID("");
    setTeams([]);
    setProjects([]);
    setPeek(null);
    setContinuations({ organization: "", team: "", project: "" });
    mutationKey.current = null;
    clearAuthorizedPresentationState();
  }, []);

  const failed = useCallback((cause: unknown) => {
    if (cause instanceof PlatformApiError && cause.status === 401) clear();
    setError("The request could not be completed. Please refresh or try again.");
  }, [clear]);

  const applyPage = useCallback((kind: MutationForm, page: ResourcePage, append: boolean) => {
    const update = (prior: Resource[]) => append ? [...new Map([...prior, ...page.items].map((item) => [item.id, item])).values()] : page.items;
    ({ organization: setOrganizations, team: setTeams, project: setProjects })[kind](update);
    setContinuations((prior) => ({ ...prior, [kind]: page.next_after ?? "" }));
  }, []);

  const loadOrganizations = useCallback(async (revision: number, after = "") => {
    const result = await platformClient.request<ResourcePage>("listOrganizations", { query: { page_size: 20, ...(after ? { after } : {}) } });
    if (revision !== generation.current) return;
    applyPage("organization", result.data, after !== "");
    if (!after) setOrganizationID((current) => result.data.items.some((item) => item.id === current) ? current : result.data.items[0]?.id ?? "");
  }, [applyPage]);

  useEffect(() => {
    const controller = new AbortController();
    const revision = generation.current;
    void platformClient.request<Session>("getSession", { signal: controller.signal }).then(async ({ data }) => {
      if (controller.signal.aborted || revision !== generation.current) return;
      setSession(data);
      await loadOrganizations(revision);
    }).catch((cause: unknown) => {
      if (!controller.signal.aborted && !(cause instanceof PlatformApiError && cause.status === 401)) failed(cause);
    }).finally(() => { if (!controller.signal.aborted) setChecking(false); });
    return () => { controller.abort(); };
  }, [failed, loadOrganizations]);

  useEffect(() => {
    setTeams([]);
    setProjects([]);
    setPeek(null);
    setContinuations((prior) => ({ ...prior, team: "", project: "" }));
    if (!session || !organizationID) return;
    const controller = new AbortController();
    const revision = generation.current;
    void Promise.all([
      platformClient.request<ResourcePage>("listTeams", { path: { organization_id: organizationID }, query: { page_size: 20 }, signal: controller.signal }),
      platformClient.request<ResourcePage>("listProjects", { path: { organization_id: organizationID }, query: { page_size: 20 }, signal: controller.signal }),
    ]).then(([teamList, projectList]) => {
      if (controller.signal.aborted || generation.current !== revision) return;
      applyPage("team", teamList.data, false);
      applyPage("project", projectList.data, false);
    }).catch((cause: unknown) => { if (!controller.signal.aborted) failed(cause); });
    return () => { controller.abort(); };
  }, [organizationID, session, failed, applyPage]);

  useEffect(() => {
    if (!session) return;
    const expiry = Date.parse(session.expires_at) - Date.now();
    if (expiry <= 0) { clear(); return; }
    const timer = window.setTimeout(clear, Math.min(expiry, 2_147_483_647));
    return () => { window.clearTimeout(timer); };
  }, [session, clear]);

  async function login(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const form = event.currentTarget;
    const token = String(new FormData(form).get("token") ?? "");
    form.reset();
    clear();
    const revision = generation.current;
    setBusy(true); setError("");
    try {
      const result = await platformClient.request<Session>("createSession", { body: { token } });
      if (revision !== generation.current) return;
      setSession(result.data);
      await loadOrganizations(revision);
    } catch (cause) { failed(cause); } finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true);
    try { await platformClient.request("deleteSession"); }
    catch (cause) { failed(cause); }
    finally { clear(); setBusy(false); }
  }

  async function loadMore(kind: MutationForm) {
    const after = continuations[kind];
    if (!after || busy) return;
    const revision = generation.current;
    setBusy(true); setError("");
    try {
      if (kind === "organization") await loadOrganizations(revision, after);
      else {
        const result = await platformClient.request<ResourcePage>(kind === "team" ? "listTeams" : "listProjects", { path: { organization_id: organizationID }, query: { page_size: 20, after } });
        if (revision === generation.current) applyPage(kind, result.data, true);
      }
    } catch (cause) { failed(cause); } finally { setBusy(false); }
  }

  async function create(event: FormEvent<HTMLFormElement>, kind: MutationForm) {
    event.preventDefault();
    const form = event.currentTarget;
    const values = new FormData(form);
    const body: Record<string, JsonValue> = { key: String(values.get("key")) };
    if (kind === "project") {
      body.title = String(values.get("title"));
      body.purpose = String(values.get("purpose") ?? "");
      body.owning_team_id = String(values.get("owning_team_id"));
    } else {
      body.name = String(values.get("name"));
      const parent = values.get("parent_team_id");
      if (kind === "team" && parent) body.parent_team_id = String(parent);
    }
    const operation = { organization: "createOrganization", team: "createTeam", project: "createProject" }[kind] as PlatformOperationId;
    const fingerprint = JSON.stringify([operation, organizationID, body]);
    if (mutationKey.current?.fingerprint !== fingerprint) mutationKey.current = { fingerprint, value: crypto.randomUUID() };
    const revision = generation.current;
    setBusy(true); setError(""); setPeek(null);
    try {
      const result = await platformClient.request<Resource>(operation, {
        ...(kind === "organization" ? {} : { path: { organization_id: organizationID } }),
        body, idempotencyKey: mutationKey.current.value,
      });
      if (revision !== generation.current) return;
      mutationKey.current = null;
      form.reset();
      // Display only the authorized server representation, never optimistic input.
      setPeek(result.data);
      if (kind === "organization") {
        await loadOrganizations(revision);
        if (revision === generation.current) {
          setOrganizations((prior) => prior.some((item) => item.id === result.data.id) ? prior : [...prior, result.data]);
          setOrganizationID(result.data.id);
        }
      } else {
        const list = await platformClient.request<ResourcePage>(kind === "team" ? "listTeams" : "listProjects", { path: { organization_id: organizationID }, query: { page_size: 20 } });
        if (revision === generation.current) {
          applyPage(kind, list.data, false);
          const update = kind === "team" ? setTeams : setProjects;
          update((prior) => prior.some((item) => item.id === result.data.id) ? prior : [...prior, result.data]);
        }
      }
    } catch (cause) { failed(cause); } finally { setBusy(false); }
  }

  async function inspect(item: Resource) {
    const revision = generation.current;
    setBusy(true); setError(""); setPeek(null);
    try {
      const operations = { organization: "getOrganization", team: "getTeam", project: "getProject" } as const;
      const result = await platformClient.request<Resource>(operations[item.kind], { path: { [`${item.kind}_id`]: item.id } });
      if (revision === generation.current) setPeek(result.data);
    } catch (cause) { failed(cause); } finally { setBusy(false); }
  }

  const area = route.kind === "primary" ? route.route.id : "unmatched";
  const resources = area === "teams" ? teams : area === "projects" ? projects : organizations;
  return <AppShell route={route} navigate={navigate} sessionLabel={session ? <button type="button" onClick={() => { void logout(); }} disabled={busy}>Sign out</button> : "Local development"}>
    <div className="product-workspace" aria-busy={checking || busy}>
      {error && <p className="product-error" role="alert">{error}</p>}
      {checking ? <p role="status">Checking your session…</p> : !session ? <section className="product-panel">
        <h2>Open your workspace</h2>
        <p>Use the disposable sign-in credential generated by your local Stead setup.</p>
        <form onSubmit={(event) => { event.preventDefault(); void login(event); }}>
          <label>Setup credential<input name="token" type="password" autoComplete="off" required pattern="[A-Za-z0-9_-]{43}" /></label>
          <button type="submit" disabled={busy}>Sign in</button>
        </form>
      </section> : <>
        <div className="organization-switcher">
          <label>Organization<select value={organizationID} disabled={busy || organizations.length === 0} onChange={(event) => { generation.current += 1; setOrganizationID(event.currentTarget.value); }}>
            {organizations.length === 0 && <option value="">Create your first Organization</option>}
            {organizations.map((item) => <option key={item.id} value={item.id}>{item.title}</option>)}
          </select></label>
          <button type="button" disabled={busy} onClick={() => { setError(""); void loadOrganizations(generation.current).catch(failed); }}>Refresh</button>
          {area !== "home" && continuations.organization && <button type="button" disabled={busy} onClick={() => { void loadMore("organization"); }}>Load more Organizations</button>}
        </div>
        {(area === "home" || area === "teams" || area === "projects") ? <div className="product-columns">
          <section className="product-panel">
            <h2>{area === "teams" ? "Your Teams" : area === "projects" ? "Your Projects" : "Your Organizations"}</h2>
            {resources.length === 0 ? <p>No authorized {area === "home" ? "Organizations" : area} to show yet.</p> : <ul className="resource-list">
              {resources.map((item) => <li key={item.id}><button type="button" disabled={busy} onClick={() => { void inspect(item); }}>
                <span className="resource-key">{item.key ?? "Project"}</span><strong>{item.title}</strong>
                {item.parent_team_id && <small>Child Team · access granted separately</small>}
              </button></li>)}
            </ul>}
            {continuations[area === "teams" ? "team" : area === "projects" ? "project" : "organization"] && <button type="button" disabled={busy} onClick={() => { void loadMore(area === "teams" ? "team" : area === "projects" ? "project" : "organization"); }}>Load more {area === "teams" ? "Teams" : area === "projects" ? "Projects" : "Organizations"}</button>}
          </section>
          {(area === "home" || organizationID) && <section className="product-panel">
            <h2>Create {area === "home" ? "an Organization" : area === "teams" ? "a Team" : "a general Project"}</h2>
            <form onSubmit={(event) => { event.preventDefault(); void create(event, area === "home" ? "organization" : area === "teams" ? "team" : "project"); }}>
              <label>Key<input name="key" required pattern="[A-Z][A-Z0-9]{1,9}" maxLength={10} placeholder="DESIGN" /></label>
              <label>{area === "projects" ? "Title" : "Name"}<input name={area === "projects" ? "title" : "name"} required maxLength={160} /></label>
              {area === "teams" && <label>Parent Team<select name="parent_team_id"><option value="">No parent</option>{teams.map((team) => <option key={team.id} value={team.id}>{team.title}</option>)}</select></label>}
              {area === "projects" && <><label>Purpose<textarea name="purpose" required maxLength={2000} /></label><label>Owning Team<select name="owning_team_id" required><option value="">Choose an authorized Team</option>{teams.map((team) => <option key={team.id} value={team.id}>{team.title}</option>)}</select></label>{continuations.team && <button type="button" disabled={busy} onClick={() => { void loadMore("team"); }}>Load more owning Teams</button>}<p>Work and Docs are included. Team ownership does not grant access.</p></>}
              <button type="submit" disabled={busy || (area === "projects" && teams.length === 0)}>Create {area === "home" ? "Organization" : area === "teams" ? "Team" : "Project"}</button>
            </form>
          </section>}
        </div> : <section className="product-panel"><h2>Workspace connected</h2><p>Your Organization, Teams, and Projects are available. This area will appear as its workflow is connected.</p></section>}
        {peek && <section className="product-panel resource-detail" aria-label="Resource details">
          <button type="button" className="close-detail" onClick={() => { setPeek(null); }}>Close details</button>
          <p>{peek.security_presentation.markings.map((mark) => mark.text).join(" · ")}</p>
          <h2>{peek.title}</h2><p>{peek.purpose ?? `${peek.kind} · version ${peek.version}`}</p>
          {peek.authorized_capabilities && <p>Capabilities: {peek.authorized_capabilities.join(", ")}</p>}
          <small>Read from Stead after central authorization.</small>
        </section>}
      </>}
    </div>
  </AppShell>;
}
