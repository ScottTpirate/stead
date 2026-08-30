import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { Foundation } from "./Foundation";

const forbiddenCapabilityLinks = () =>
  ["Code", "Delivery"].flatMap((name) =>
    screen.queryAllByRole("link", { name }),
  );

afterEach(() => {
  cleanup();
  window.location.hash = "";
});

describe("Foundation", () => {
  it("keeps the universal navigation keyboard-operable", async () => {
    const user = userEvent.setup();

    render(<Foundation />);

    expect(
      screen.getByRole("heading", { level: 1, name: "Open work, in one place." }),
    ).toBeDefined();

    const navigation = screen.getByRole("navigation", { name: "Project areas" });
    const links = within(navigation).getAllByRole("link");

    expect(links.map((link) => link.textContent)).toEqual(["Overview", "Work", "Docs"]);

    await user.tab();
    expect(document.activeElement).toBe(links[0]);

    await user.keyboard("{Enter}");
    expect(window.location.hash).toBe("#overview");
  });

  it("contains no software-capability links in the general shell fixture", () => {
    render(<Foundation />);

    expect(forbiddenCapabilityLinks()).toHaveLength(0);
  });

  it("detects duplicate forbidden-capability mutations", () => {
    render(<Foundation />);

    const navigation = screen.getByRole("navigation", { name: "Project areas" });
    for (let index = 0; index < 2; index += 1) {
      const link = document.createElement("a");
      link.href = "#code";
      link.textContent = "Code";
      navigation.append(link);
    }

    expect(forbiddenCapabilityLinks()).toHaveLength(2);
  });
});
