// Shared, app-wide toast notification store -- the design-system
// unification's own real replacement for the ad hoc mix this app had
// grown across pages (a bare inline "Saved." paragraph on some,
// nothing at all on others, a native alert() on none but easily could
// have been). One queue, one host component (ToastHost.svelte, mounted
// once in App.svelte), consumed via this module's own tiny API --
// matching the same singleton-store pattern timestamp.svelte.ts/
// queryLogPrefill.svelte.ts already established, not a new paradigm.
//
// Deliberately NOT a replacement for a page's own persistent inline
// error state (a form's own validation error, a page-level degraded
// banner) -- those need to stay visible until the underlying condition
// changes, which a toast (transient, auto-dismissing) is the wrong
// shape for. Toasts are for one-off outcomes of an action just taken:
// "saved", "deleted", "a background action failed" -- exactly the
// class of feedback this app used to show (or not show at all)
// inconsistently per page.
export type ToastKind = "success" | "error" | "info";

export interface ToastEntry {
  id: number;
  kind: ToastKind;
  message: string;
}

let nextId = 1;
let entries = $state<ToastEntry[]>([]);

const AUTO_DISMISS_MS: Record<ToastKind, number> = {
  success: 4000,
  info: 4000,
  error: 7000, // errors stay a bit longer -- more likely to need actually reading
};

function push(kind: ToastKind, message: string) {
  const id = nextId++;
  entries = [...entries, { id, kind, message }];
  setTimeout(() => dismiss(id), AUTO_DISMISS_MS[kind]);
}

function dismiss(id: number) {
  entries = entries.filter((e) => e.id !== id);
}

export const toast = {
  success(message: string) {
    push("success", message);
  },
  error(message: string) {
    push("error", message);
  },
  info(message: string) {
    push("info", message);
  },
  dismiss,
  get entries() {
    return entries;
  },
};
