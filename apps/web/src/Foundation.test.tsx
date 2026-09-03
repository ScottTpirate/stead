import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import {
  Button,
  ErrorState,
  type ButtonProps,
} from "../../../packages/design-system/src/index";

import { Foundation } from "./Foundation";

const forbiddenCapabilityLinks = () =>
  ["Code", "Delivery"].flatMap((name) =>
    screen.queryAllByRole("link", { name }),
  );

afterEach(() => {
  cleanup();
  window.history.replaceState(null, "", "/");
});

describe("Foundation", () => {
  it("keeps the universal navigation keyboard-operable", async () => {
    const user = userEvent.setup();

    render(<Foundation />);

    expect(screen.getByRole("heading", { level: 1, name: "Home" })).toBeDefined();

    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });

    expect(
      ["Home", "Inbox", "My Work", "Projects", "Knowledge", "Teams"].map(
        (name) => within(navigation).getByRole("link", { name }).getAttribute("href"),
      ),
    ).toEqual(["/", "/inbox", "/my-work", "/projects", "/knowledge", "/teams"]);

    const inboxLink = within(navigation).getByRole("link", { name: "Inbox" });
    inboxLink.focus();
    expect(document.activeElement).toBe(inboxLink);

    await user.keyboard("{Enter}");
    expect(window.location.pathname).toBe("/inbox");
    expect(screen.getByRole("heading", { level: 1, name: "Inbox" })).toBeDefined();
  });

  it("leaves modifier clicks to the browser", () => {
    render(<Foundation />);
    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    const inboxLink = within(navigation).getByRole("link", { name: "Inbox" });
    const modifierClick = new MouseEvent("click", {
      bubbles: true,
      button: 0,
      cancelable: true,
      ctrlKey: true,
    });

    expect(inboxLink.dispatchEvent(modifierClick)).toBe(true);
    expect(modifierClick.defaultPrevented).toBe(false);
  });

  it("contains no software-capability links in the general shell fixture", () => {
    render(<Foundation />);

    expect(forbiddenCapabilityLinks()).toHaveLength(0);

    const unsafeProperties = {
      formAction: "//outside.invalid/submit",
    } as unknown as ButtonProps;
    expect(() =>
      render(<Button {...unsafeProperties}>Blocked action</Button>),
    ).toThrow(/resource-loading DOM properties are not supported/u);
  });

  it("detects duplicate forbidden-capability mutations", () => {
    render(<Foundation />);

    const navigation = screen.getByRole("navigation", { name: "Primary navigation" });
    for (let index = 0; index < 2; index += 1) {
      const link = document.createElement("a");
      link.href = "#code";
      link.textContent = "Code";
      navigation.append(link);
    }

    expect(forbiddenCapabilityLinks()).toHaveLength(2);
  });

  it("renders only safe correlation identifiers", () => {
    const { rerender } = render(
      <ErrorState correlationId="safe-correlation:0001" />,
    );
    expect(screen.getByText("safe-correlation:0001")).toBeDefined();

    rerender(<ErrorState correlationId="classified-body <secret>" />);
    expect(screen.queryByText(/classified-body|secret/u)).toBeNull();
  });
});
