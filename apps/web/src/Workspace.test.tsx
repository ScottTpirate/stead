import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, expect, it, vi } from "vitest";

import { PlatformApiError, type PlatformResponse } from "../../../packages/api-client/src/client";
import { platformClient } from "./platform";
import { matchRoute } from "./routes";
import { Workspace } from "./Workspace";

const session = {
  principal: { type: "user", id: "fixture-user" }, instance_id: "fixture-instance",
  expires_at: new Date(Date.now() + 60_000).toISOString(), session_revision: 1,
};
const organization = {
  id: "fixture-org", kind: "organization", title: "Authorized server title",
  key: "OPS", version: 1, security_presentation: { markings: [] },
};
const response = <T,>(data: T): PlatformResponse<T> => ({ data, status: 200, responseBytes: 0 });

afterEach(() => { cleanup(); vi.restoreAllMocks(); });

// Isolated UI behavior tests: generated-client transport validation and live
// product acceptance are separate. No listener, browser, or DB is simulated here.
it("clears the disposable credential and creates through the generated client", async () => {
  let created = false;
  const request = vi.spyOn(platformClient, "request").mockImplementation(async <T,>(operation: string) => {
    if (operation === "getSession") throw new PlatformApiError(401);
    if (operation === "createSession") return response(session as T);
    if (operation === "createOrganization") { created = true; return response(organization as T); }
    if (operation === "listOrganizations") return response((created ? [organization] : []) as T);
    return response([] as T);
  });
  const user = userEvent.setup();
  render(<Workspace route={matchRoute("/")} navigate={() => {}} />);
  const credential = await screen.findByLabelText("Setup credential") as HTMLInputElement;
  const token = "a".repeat(43);
  await user.type(credential, token);
  await user.click(screen.getByRole("button", { name: "Sign in" }));
  await screen.findByRole("button", { name: "Sign out" });
  expect(credential.value).toBe("");
  expect(request).toHaveBeenCalledWith("createSession", { body: { token } });
  await user.type(screen.getByLabelText("Key"), "OPS");
  await user.type(screen.getByLabelText("Name"), "User input title");
  await user.click(screen.getByRole("button", { name: "Create Organization" }));
  await screen.findByRole("button", { name: "OPS Authorized server title" });
  expect(screen.queryByText("User input title")).toBeNull();
  expect(request).toHaveBeenCalledWith("createOrganization", {
    body: { key: "OPS", name: "User input title" }, idempotencyKey: expect.any(String),
  });
  expect((screen.getByLabelText("Key") as HTMLInputElement).value).toBe("");
  await user.click(screen.getByRole("button", { name: "Sign out" }));
  await screen.findByLabelText("Setup credential");
  expect(screen.queryByText("Authorized server title")).toBeNull();
  expect(request).toHaveBeenCalledWith("deleteSession");
});

it("does not render a resource from a denied mutation", async () => {
  vi.spyOn(platformClient, "request").mockImplementation(async <T,>(operation: string) => {
    if (operation === "getSession") return response(session as T);
    if (operation === "createOrganization") throw new PlatformApiError(404);
    return response([] as T);
  });
  const user = userEvent.setup();
  render(<Workspace route={matchRoute("/")} navigate={() => {}} />);
  await screen.findByRole("button", { name: "Sign out" });
  await user.type(screen.getByLabelText("Key"), "OPS");
  await user.type(screen.getByLabelText("Name"), "Denied title");
  await user.click(screen.getByRole("button", { name: "Create Organization" }));
  await screen.findByRole("alert");
  expect(screen.queryByRole("region", { name: "Resource details" })).toBeNull();
  expect(screen.queryByText("Denied title")).toBeNull();
});
