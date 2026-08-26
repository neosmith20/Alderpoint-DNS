// The "keep multiple navigation sections open" preference: shared between
// Nav.svelte (which enforces it) and the Administration page (which owns
// the checkbox for it). Default true -- multiple groups open at once is
// the existing accepted default behavior; switching it off makes opening
// a group close the others (single-open accordion).
const KEY = "apdns-go-nav-keep-multiple-open";

export function loadKeepMultipleOpen(): boolean {
  try {
    const v = localStorage.getItem(KEY);
    if (v !== null) return v === "1";
  } catch {
    /* fall through to default */
  }
  return true;
}

export function saveKeepMultipleOpen(value: boolean): void {
  try {
    localStorage.setItem(KEY, value ? "1" : "0");
  } catch {
    /* best-effort persistence only */
  }
}
