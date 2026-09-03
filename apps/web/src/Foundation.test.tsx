import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import {
  Button,
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
});
