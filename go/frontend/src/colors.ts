// Owner color customization: which palette swatch (see colorPalette.ts)
// drives each of three real, distinct UI roles -- Accent/Primary
// (buttons, links, active nav, focus rings, meters), Success (allowed/
// healthy status text and badges), and Danger (blocked/failed status
// text and badges). Same persistence pattern as theme.ts (explicit
// choice in localStorage, applied by overriding the same CSS custom
// properties App.svelte's own light/dark blocks already define) --
// per-viewer, not synced anywhere, exactly like the light/dark choice
// it sits alongside.
import { COLOR_PALETTE, swatchById, type ColorSwatch } from "./colorPalette";

export type ColorRole = "accent" | "success" | "danger";

export interface ColorChoices {
  accent: string; // palette id, or "" for the theme's own default
  success: string;
  danger: string;
}

const KEY = "apdns-go-colors";
const DEFAULT_CHOICES: ColorChoices = { accent: "", success: "", danger: "" };

export function loadColors(): ColorChoices {
  try {
    const raw = localStorage.getItem(KEY);
    if (raw) {
      const parsed = JSON.parse(raw);
      return {
        accent: typeof parsed.accent === "string" ? parsed.accent : "",
        success: typeof parsed.success === "string" ? parsed.success : "",
        danger: typeof parsed.danger === "string" ? parsed.danger : "",
      };
    }
  } catch {
    /* fall through to default */
  }
  return { ...DEFAULT_CHOICES };
}

export function saveColors(choices: ColorChoices): void {
  try {
    localStorage.setItem(KEY, JSON.stringify(choices));
  } catch {
    /* best-effort persistence only */
  }
}

function setVar(name: string, value: string | null): void {
  const root = document.documentElement;
  if (value) root.style.setProperty(name, value);
  else root.style.removeProperty(name); // "" / unknown id -> fall back to the theme's own default
}

export function applyColors(choices: ColorChoices): void {
  const accent = swatchById(choices.accent);
  setVar("--accent", accent?.base ?? null);
  setVar("--accent-strong", accent?.strong ?? null);
  setVar("--accent-fg", accent?.fg ?? null);
  // --btn-bg/--btn-bg-hover are a SEPARATE pair of tokens from --accent
  // (App.svelte's global `button` rule uses these, not --accent, for
  // every real filled button in the app) -- both must be overridden or
  // "Primary" only recolors links/the active nav item/meters, not the
  // buttons an owner actually clicks, which is most of what this role
  // is for.
  setVar("--btn-bg", accent?.base ?? null);
  setVar("--btn-bg-hover", accent?.strong ?? null);

  const success = swatchById(choices.success);
  setVar("--success", success?.base ?? null);
  setVar("--badge-ok-fg", success?.base ?? null);

  const danger = swatchById(choices.danger);
  setVar("--danger", danger?.base ?? null);
  setVar("--badge-danger-fg", danger?.base ?? null);
}

export { COLOR_PALETTE };
export type { ColorSwatch };
