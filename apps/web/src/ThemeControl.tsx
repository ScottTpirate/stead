import { useEffect, useState } from "react";

type ThemePreference = "system" | "light" | "dark";

const THEME_STORAGE_KEY = "stead:theme";

function storedTheme(): ThemePreference {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return value === "light" || value === "dark" ? value : "system";
  } catch {
    return "system";
  }
}

function applyTheme(theme: ThemePreference): void {
  if (theme === "system") delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
}

export function ThemeControl() {
  const [theme, setTheme] = useState<ThemePreference>(storedTheme);

  useEffect(() => applyTheme(theme), [theme]);

  return (
    <label className="theme-control">
      <span>Theme</span>
      <select
        value={theme}
        onChange={(event) => {
          const nextTheme = event.currentTarget.value as ThemePreference;
          try {
            window.localStorage.setItem(THEME_STORAGE_KEY, nextTheme);
          } catch {
            // Private browsing or storage policy can reject preference persistence.
          }
          applyTheme(nextTheme);
          setTheme(nextTheme);
        }}
      >
        <option value="system">System</option>
        <option value="light">Light</option>
        <option value="dark">Dark</option>
      </select>
    </label>
  );
}
