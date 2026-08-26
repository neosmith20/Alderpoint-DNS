// Shared timestamp-display engine: Browser Local / Appliance Time / UTC,
// matching app/v2/ui/app.js's three modes exactly (see PARITY_MATRIX.md,
// Administration page, which owns the mode picker). Reactive singleton
// (not a plain function module) so every currently-mounted page's
// timestamps reformat instantly the moment the operator changes the mode
// on Administration -- no reload, no re-fetch, matching the Python
// behavior's own "no reload, no re-fetch" requirement.
export type TimestampMode = "browser" | "appliance" | "utc";

const MODE_KEY = "apdns-go-timestamp-mode";

function loadMode(): TimestampMode {
  try {
    const stored = localStorage.getItem(MODE_KEY);
    if (stored === "browser" || stored === "appliance" || stored === "utc") return stored;
  } catch {
    /* localStorage unavailable -- fall through to default */
  }
  return "browser";
}

const fmtCache = new Map<string, Intl.DateTimeFormat>();

function formatter(timeZone: string | undefined): Intl.DateTimeFormat {
  const key = timeZone ?? "__browser__";
  let f = fmtCache.get(key);
  if (!f) {
    f = new Intl.DateTimeFormat(undefined, {
      timeZone,
      year: "numeric",
      month: "short",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
    fmtCache.set(key, f);
  }
  return f;
}

class TimestampPreference {
  mode = $state<TimestampMode>(loadMode());
  applianceTimezone = $state("UTC");

  setMode(mode: TimestampMode): void {
    this.mode = mode;
    try {
      localStorage.setItem(MODE_KEY, mode);
    } catch {
      /* best-effort persistence only */
    }
  }

  /** Format an ISO-8601 / epoch-ms timestamp per the current mode.
   * Returns "--" for null/invalid input rather than "Invalid Date". */
  format(value: string | number | null | undefined): string {
    if (value === null || value === undefined || value === "") return "--";
    const d = new Date(value);
    if (Number.isNaN(d.getTime())) return "--";
    switch (this.mode) {
      case "utc":
        return formatter("UTC").format(d) + " UTC";
      case "appliance":
        return formatter(this.applianceTimezone).format(d);
      case "browser":
      default:
        return formatter(undefined).format(d);
    }
  }
}

export const timestampPref = new TimestampPreference();

/** Epoch-ms sort key, independent of display mode -- tables must sort
 * chronologically, never by the localized display string. */
export function timestampSortKey(value: string | number | null | undefined): number {
  if (value === null || value === undefined || value === "") return -Infinity;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? -Infinity : t;
}
