// Shared timestamp-display engine: Browser Local / Appliance Time / UTC,
// matching app/v2/ui/app.js's three modes exactly (see PARITY_MATRIX.md,
// Administration page). The Administration page (which owns the mode
// picker) isn't built yet, but every other page's tables render
// timestamps, so this lives centrally now rather than being redone per
// page later.
export type TimestampMode = "browser" | "appliance" | "utc";

const KEY = "apdns-go-timestamp-mode";
let applianceTz = "UTC";

export function setApplianceTimezone(tz: string): void {
  applianceTz = tz || "UTC";
}

export function loadTimestampMode(): TimestampMode {
  try {
    const stored = localStorage.getItem(KEY);
    if (stored === "browser" || stored === "appliance" || stored === "utc") return stored;
  } catch {
    /* localStorage unavailable -- fall through to default */
  }
  return "browser";
}

export function saveTimestampMode(mode: TimestampMode): void {
  try {
    localStorage.setItem(KEY, mode);
  } catch {
    /* best-effort persistence only */
  }
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

/** Format an ISO-8601 / epoch-ms timestamp per the given mode. Returns
 * "--" for null/invalid input rather than "Invalid Date". */
export function formatTimestamp(value: string | number | null | undefined, mode: TimestampMode): string {
  if (value === null || value === undefined || value === "") return "--";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return "--";
  switch (mode) {
    case "utc":
      return formatter("UTC").format(d) + " UTC";
    case "appliance":
      return formatter(applianceTz).format(d);
    case "browser":
    default:
      return formatter(undefined).format(d);
  }
}

/** Epoch-ms sort key, independent of display mode -- tables must sort
 * chronologically, never by the localized display string. */
export function timestampSortKey(value: string | number | null | undefined): number {
  if (value === null || value === undefined || value === "") return -Infinity;
  const t = new Date(value).getTime();
  return Number.isNaN(t) ? -Infinity : t;
}
