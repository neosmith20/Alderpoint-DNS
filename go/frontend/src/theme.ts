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

/** True when the current theme is an explicit stored preference (light
 * or dark), false when it's following the OS/browser's own
 * prefers-color-scheme -- General Settings' "System" option needs this
 * to know which of its three radio choices is actually active. */
export function hasExplicitTheme(): boolean {
  try {
    const stored = localStorage.getItem(KEY);
    return stored === "light" || stored === "dark";
  } catch {
    return false;
  }
}

/** Clears the stored explicit preference and re-applies whatever the
 * OS/browser reports right now -- General Settings' "System" option. */
export function useSystemTheme(): Theme {
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* best-effort */
  }
  const theme: Theme = window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  document.documentElement.setAttribute("data-theme", theme);
  return theme;
}
