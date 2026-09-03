// Standard/Advanced navigation profile. Purely a presentation switch: it
// changes which nav groups/items are shown and how dense the shell reads --
// it never touches backend behavior, never creates a second route for the
// same page, and never hides an active warning (System Status/health badges
// render regardless of profile; see App.svelte). An Advanced page reached by
// direct link/bookmark while Standard is selected still renders normally --
// nav.ts marks it `advanced: true` and RouteLoader/App.svelte show an
// "Advanced page" label instead of hiding or redirecting it.
//
// Persisted the same way every other per-operator UI preference in this app
// already is (theme.ts, Nav.svelte's COLLAPSED_KEY, dashboardCards.ts):
// localStorage, scoped to this browser. There is no per-administrator
// account-preferences store anywhere in the Go backend yet (auth.Admin
// carries only credentials/session fields) -- ADR: if one is ever added,
// this is the one preference that should move server-side first, since
// "which nav an operator sees" is the most identity-bound of the bunch.
export type NavProfile = "standard" | "advanced";

const KEY = "apdns-go-nav-profile";

export function loadProfile(): NavProfile {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "standard" || stored === "advanced") return stored;
  } catch {
    /* localStorage unavailable -- fall through to the default */
  }
  return "standard";
}

export function saveProfile(profile: NavProfile): void {
  try {
    localStorage.setItem(KEY, profile);
  } catch {
    /* best-effort persistence only */
  }
}
