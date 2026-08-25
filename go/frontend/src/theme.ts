// Minimal light/dark theme support: explicit choice persisted in
// localStorage, falling back to the OS preference when unset.
export type Theme = "light" | "dark";

const KEY = "apdns-go-theme";

export function loadTheme(): Theme {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "light" || stored === "dark") return stored;
  } catch {
    /* localStorage unavailable (private mode etc.) -- fall through */
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

export function applyTheme(theme: Theme): void {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem(KEY, theme);
  } catch {
    /* best-effort persistence only */
  }
}
