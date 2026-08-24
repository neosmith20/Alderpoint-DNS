(function () {
  "use strict";

  function loadPerfHistory() {
    try {
      const parsed = JSON.parse(sessionStorage.getItem("apdnsPerfHistory") || "[]");
      return Array.isArray(parsed) ? parsed.slice(0, 80) : [];
    } catch (_) {
      sessionStorage.removeItem("apdnsPerfHistory");
      return [];
    }
  }

  const state = {
    csrf: "",
    user: "",
    route: "dashboard",
    theme: localStorage.getItem("apdnsTheme") || "dark",
    navCollapsed: localStorage.getItem("apdnsNavCollapsed") === "1",
    cache: {},
    busy: new Set(),
    // Dashboard chart controls (owner-reported fix: Top Domains was an
    // anonymous, non-operator-usable bar chart with no time-series view
    // at all). Session-only (not persisted) -- a reasonable default the
    // operator can change per visit, not a durable preference.
    dashboardRangeMinutes: 1440,
    dashboardTopMode: "top",
    dashboardLivePaused: false,
    dashboardLiveTimer: null,
    dashboardLiveAbort: null,
    dashboardLivePollSeq: 0,
    dashboardLiveDiagnostics: { renders: [], replacement_count: 0, stale_discards: 0, overlap_skips: 0, failures: [] },
    applianceTimezone: null,
    routeCache: new Map(),
    inFlightGets: new Map(),
    perfHistory: loadPerfHistory(),
    lastNavClickAt: 0,
    currentNavigationId: "",
  };
  const PERF_LIMIT = 80;
  const ROUTE_CACHE_TTL_MS = 30000;
  let routeLabels = {};

  function nowMs() { return performance.now(); }
  function absNow() { return new Date().toISOString(); }
  function perfSave(entry) {
    state.perfHistory.unshift(entry);
    state.perfHistory = state.perfHistory.slice(0, PERF_LIMIT);
    try { sessionStorage.setItem("apdnsPerfHistory", JSON.stringify(state.perfHistory)); } catch (_) {}
  }
  function parseServerTiming(header) {
    const out = {};
    String(header || "").split(",").forEach((part) => {
      const bits = part.trim().split(";");
      const name = bits[0] && bits[0].trim();
      const dur = bits.find((b) => b.trim().startsWith("dur="));
      if (name && dur) out[name] = Number(dur.split("=", 2)[1]) || 0;
    });
    return out;
  }
  function pageTitleFor(route) { return routeLabels[route] || route; }
  function routeSkeleton(route, note) {
    return page(pageTitleFor(route), note || "Preparing page.", "", `
      <div class="grid two" data-route-loading="1">
        <section class="panel"><div class="panel__head"><h2>Summary</h2></div><div class="panel__body"><div class="empty">Loading summary...</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Details</h2></div><div class="panel__body"><div class="empty">Loading details...</div></div></section>
      </div>`);
  }
  function nextPaint() {
    return new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  }
  function deployedVersionFromPage() {
    const text = document.body.innerText || "";
    const match = text.match(/2\.0\.0~preview[0-9a-f]+-1/);
    return match ? match[0] : "";
  }
  function performanceReportText() {
    const payload = {
      generated_at: absNow(),
      browser_timezone: browserTimezone(),
      viewport: { width: window.innerWidth, height: window.innerHeight },
      deployed_version_seen: deployedVersionFromPage(),
      measurements: state.perfHistory,
      live_render_health: state.dashboardLiveDiagnostics,
    };
    return JSON.stringify(payload, null, 2);
  }
  function clearPerformanceMeasurements() {
    state.perfHistory = [];
    sessionStorage.removeItem("apdnsPerfHistory");
  }

  if ("PerformanceObserver" in window) {
    try {
      const longTasks = new PerformanceObserver((list) => {
        for (const item of list.getEntries()) {
          perfSave({ type: "longtask", route: state.route, timestamp: absNow(), duration_ms: Math.round(item.duration) });
        }
      });
      longTasks.observe({ entryTypes: ["longtask"] });
    } catch (_) {}
  }

  // Grouping/order intentionally mirrors V1.1.1's information architecture
  // (docs/v2/... parity work, priority 1 of the beta-rescue brief) rather
  // than V2's prior ad hoc "Operations/Policy/DNS/System" split, which mixed
  // unrelated concerns (e.g. Replication and Backup living under the same
  // group as Dashboard) and gave the owner no stable mental model to
  // navigate by. Dashboard stays a standalone top-level item, matching V1.
  // IA split (a real owner-reported finding, priority 1 of the second beta-rescue
  // pass: Statistics was buried under Query Log, Administration was
  // buried inside System Status, and Encryption was mixed in with
  // Notifications under one "Notifications / HTTPS" page -- concept
  // soup, not V1.1.1's actual page architecture, which gives each of
  // these its own destination. See statistics()/encryption()/
  // notifications()/administration()/logs() below: each used to be a
  // section stapled onto analytics()/settings()/health() and is now its
  // own page with its own nav entry, matching V1.1.1's own
  // System group (statistics_settings.html, administration.html,
  // encryption.html, notifications.html, system_logs_results.html are
  // five separate V1 templates, not one).
  const pages = [
    ["DNS", "analytics", "Query Log"],
    ["DNS", "clients", "Clients"],
    ["DNS", "policies", "Clients & Access"],
    ["DNS", "localdns", "Local DNS"],
    ["DNS", "upstreams", "DNS Settings"],
    ["DNS", "cache", "Cache"],
    ["Security", "filtering", "Filters"],
    ["Security", "blocklists", "Blocklists"],
    ["Security", "encryption", "Encryption"],
    ["Operations", "importexport", "Import"],
    ["Operations", "backup", "Backup & Restore"],
    ["Operations", "replication", "Replication"],
    ["System", "statistics", "Statistics"],
    ["System", "health", "System Status"],
    ["System", "administration", "Administration"],
    ["System", "network", "Network Configuration"],
    ["System", "notifications", "Notifications"],
    ["System", "updates", "Software Updates"],
    ["System", "logs", "Logs"],
  ];
  routeLabels = Object.fromEntries([["Dashboard", "dashboard", "Dashboard"], ...pages].map((p) => [p[1], p[2]]));
  const GROUP_ORDER = ["DNS", "Security", "Operations", "System"];
  // Real defect fixed here (owner-reported: main-menu items showed an
  // arbitrary placeholder letter, which reads as unfinished/prototype
  // UI). Intentional, hand-authored inline SVG per section -- generic
  // geometric glyphs (a network globe, a shield, a sliders/controls
  // icon, a stacked-server icon), not copied from any icon library or
  // loaded from a CDN (no external dependency at all: every <path>
  // below is inline markup). `currentColor` so each icon automatically
  // follows the surrounding button's text color (muted/active/hover),
  // matching every other themed element rather than a fixed hardcoded
  // color.
  const ICON_VIEWBOX = "0 0 24 24";
  const DASHBOARD_ICON = `<svg viewBox="${ICON_VIEWBOX}" fill="currentColor" aria-hidden="true"><rect x="3" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="3" width="7.5" height="7.5" rx="1.6"/><rect x="3" y="13.5" width="7.5" height="7.5" rx="1.6"/><rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.6"/></svg>`;
  const GROUP_ICON = {
    DNS: `<svg viewBox="${ICON_VIEWBOX}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="8.5"/><path d="M3.5 12h17M12 3.5c2.8 2.3 2.8 15 0 17M12 3.5c-2.8 2.3-2.8 15 0 17"/></svg>`,
    Security: `<svg viewBox="${ICON_VIEWBOX}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round" stroke-linecap="round" aria-hidden="true"><path d="M12 3.2l7 2.8v5.6c0 4.6-3 8.3-7 9.4-4-1.1-7-4.8-7-9.4V6l7-2.8z"/><path d="M8.7 12l2.3 2.3 4.3-4.3"/></svg>`,
    Operations: `<svg viewBox="${ICON_VIEWBOX}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" aria-hidden="true"><path d="M4 7h11M18 7h2M4 12h6M9 17h11M6 17h2"/><circle cx="15" cy="7" r="2.1" fill="currentColor" stroke="none"/><circle cx="8" cy="12" r="2.1" fill="currentColor" stroke="none"/><circle cx="15" cy="17" r="2.1" fill="currentColor" stroke="none"/></svg>`,
    System: `<svg viewBox="${ICON_VIEWBOX}" fill="none" stroke="currentColor" stroke-width="1.6" aria-hidden="true"><rect x="3.5" y="4" width="17" height="6.2" rx="1.4"/><rect x="3.5" y="13.8" width="17" height="6.2" rx="1.4"/><circle cx="7" cy="7.1" r=".9" fill="currentColor" stroke="none"/><circle cx="7" cy="16.9" r=".9" fill="currentColor" stroke="none"/></svg>`,
  };

  // Real per-section expand/collapse state (a real owner-reported finding, priority
  // 1 of the beta-rescue brief: the sidebar previously rendered
  // GROUP_ORDER as plain, non-interactive `.section-label` divs above a
  // flat button list -- visually grouped but not an actual disclosure
  // widget. Matching V1.1.1's behavior: each group is its own toggle,
  // independent of the others, persisted per-section across reloads, and
  // a group containing the active route auto-expands unless the operator
  // has explicitly collapsed it.
  const NAV_SECTION_KEY_PREFIX = "apdnsNavSectionOpen:";
  function navSectionOpen(group, activeInGroup) {
    try {
      const stored = localStorage.getItem(NAV_SECTION_KEY_PREFIX + group);
      if (stored !== null) return stored === "1";
    } catch (_) {}
    return activeInGroup;
  }
  function setNavSectionOpen(group, open) {
    try { localStorage.setItem(NAV_SECTION_KEY_PREFIX + group, open ? "1" : "0"); } catch (_) {}
  }

  // Owner preference (default OFF, i.e. accordion behavior by default:
  // opening one main section closes whichever other one was open).
  // Persisted like every other nav preference; a real settings control
  // lives on the Administration page (administration()/wire()'s
  // [data-action="nav-keep-multiple-open"] handler).
  const NAV_KEEP_MULTIPLE_OPEN_KEY = "apdnsNavKeepMultipleOpen";
  function navKeepMultipleOpen() {
    try { return localStorage.getItem(NAV_KEEP_MULTIPLE_OPEN_KEY) === "1"; } catch (_) { return false; }
  }
  function setNavKeepMultipleOpen(value) {
    try { localStorage.setItem(NAV_KEEP_MULTIPLE_OPEN_KEY, value ? "1" : "0"); } catch (_) {}
  }

  // One canonical model, matching app/v2/policy_model.py's own
  // _VALID_* sets exactly -- real defect fixed here: these previously
  // showed placeholder text that didn't match any real accepted value
  // ("sinkhole" is not a real response mode; ECS's real values are
  // disabled/preserve/custom, not "off | privacy | full"; fallback's
  // real values are none/on_failure/always_parallel, not
  // "ordered | failover"). Enum-valued fields render as a real <select>
  // (4th element) so an operator can only ever submit a value the
  // backend actually accepts; id-referencing fields stay free text.
  const policyFields = [
    ["filtering_profile_id", "Filtering profile", "default"],
    ["safesearch_mode", "SafeSearch", "off | moderate | strict", ["off", "moderate", "strict"]],
    ["parental_policy_id", "Parental policy", "none | family"],
    ["security_policy_id", "Security policy", "none | standard"],
    ["service_blocking_ruleset_id", "Service ruleset", "ruleset id"],
    ["blocking_response_mode", "Response mode", "", ["nxdomain", "refused", "null_ip", "custom_ip"]],
    ["custom_ipv4", "Custom block IPv4", "only used when response mode is custom_ip"],
    ["custom_ipv6", "Custom block IPv6", "only used when response mode is custom_ip"],
    ["upstream_profile_id", "Upstream profile", "profile id"],
    ["fallback_strategy", "Fallback", "", ["none", "on_failure", "always_parallel"]],
    ["fallback_upstream_profile_id", "Fallback upstream profile", "profile id (must use the same transport as the primary)"],
    ["ecs_mode", "ECS (client subnet)", "", ["disabled", "preserve", "custom"]],
    ["domain_routing_ruleset_id", "Domain routes", "ruleset id"],
  ];

  function esc(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  }

  // Real defect fixed here (owner-reported: raw UTC ISO strings like
  // "2026-08-23T05:00:00+00:00" were the default operator-facing
  // presentation everywhere -- Dashboard, Query Log, Clients, backup/
  // update history, replication, everywhere an API field carried a
  // timestamp). UTC stays the canonical storage/API/transport format
  // (never reinterpreted here -- this only ever affects presentation,
  // and only for values that already look like a real ISO-8601
  // UTC-offset timestamp; a plain date, a bare number, or free text is
  // left completely alone). One shared formatter + one shared DOM
  // marker (`data-ts-utc`) so the display-mode preference below can
  // reformat every already-rendered timestamp on the page in place,
  // instantly, with no re-fetch and no page reload.
  //
  // Three modes, never a hardcoded geographic timezone anywhere in this
  // file (owner-reported requirement): "browser" (the operator's own
  // browser-detected IANA zone, via the standard
  // Intl.DateTimeFormat().resolvedOptions().timeZone -- the same
  // mechanism every other real-world local-time UI uses, not a guess),
  // "appliance" (this specific box's own configured zone, detected
  // server-side by webapp.py's _detect_appliance_timezone() and cached
  // here once fetched), and "utc". Default is "browser"; precedence
  // falls back browser -> appliance -> utc only when a zone is
  // genuinely undetectable/invalid, per the owner's explicit fallback
  // chain -- not a preference choice.
  const TIMESTAMP_DISPLAY_KEY = "apdnsTimestampDisplay"; // "browser" | "appliance" | "utc"
  function timestampDisplayMode() {
    try {
      const v = localStorage.getItem(TIMESTAMP_DISPLAY_KEY);
      if (v === "utc" || v === "browser" || v === "appliance") return v;
      if (v === "local") return "browser"; // migrates the earlier binary local/utc preference
    } catch (_) {}
    return "browser";
  }
  function setTimestampDisplayMode(mode) {
    try { localStorage.setItem(TIMESTAMP_DISPLAY_KEY, (mode === "utc" || mode === "appliance") ? mode : "browser"); } catch (_) {}
  }
  function browserTimezone() {
    try {
      const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
      if (tz) return tz;
    } catch (_) {}
    return null;
  }
  // Populated once /api/system/status has been fetched by any page
  // (common(), administration(), etc.) -- see timezonePreferenceSelector().
  // Never a hardcoded zone: this is exactly what the appliance itself
  // reported, or null until known/if genuinely undetectable server-side.
  function applianceTimezone() { return state.applianceTimezone || null; }
  // Requires an explicit Z or +HH:MM/-HHMM offset -- a timezone-naive
  // value is never guessed to be UTC (a real defect class this
  // deliberately avoids); every V2 API timestamp field is offset-aware
  // (Python's datetime.isoformat() on an aware UTC datetime, verified
  // against app/v2/webapp.py's own timestamp fields).
  const ISO_TIMESTAMP_RE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})$/;
  const TS_FORMAT_OPTS = { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", timeZoneName: "short" };
  // Fallback chain (owner-specified, not a silent substitution the
  // operator can't tell happened): an unavailable/invalid zone for the
  // selected mode falls through to the next one. Shared by
  // formatTimestamp() (full cell display) and the dashboard activity
  // chart's own compact axis/tooltip labels, so both always agree on
  // which real zone is actually in effect.
  function resolveDisplayTimeZone() {
    const mode = timestampDisplayMode();
    const zone = mode === "utc" ? "UTC" : mode === "appliance" ? (applianceTimezone() || browserTimezone()) : (browserTimezone() || applianceTimezone());
    return zone || "UTC";
  }
  function formatTimestamp(raw) {
    const str = String(raw ?? "");
    if (!ISO_TIMESTAMP_RE.test(str)) return null; // not recognized as a timestamp at all
    const d = new Date(str);
    if (isNaN(d.getTime())) return { display: "Unknown time", exact: str, invalid: true };
    const zone = resolveDisplayTimeZone();
    try {
      return { display: d.toLocaleString(undefined, Object.assign({ timeZone: zone }, TS_FORMAT_OPTS)), exact: str, invalid: false };
    } catch (_) {
      // An invalid/unrecognized IANA name from either detector -- fall
      // back to UTC rather than throwing and leaving the cell blank.
      return { display: d.toLocaleString(undefined, Object.assign({ timeZone: "UTC" }, TS_FORMAT_OPTS)), exact: str, invalid: false };
    }
  }
  // Returns null (not html) when ``raw`` doesn't look like a timestamp at
  // all, so every call site can fall through to its own plain-text
  // rendering for non-timestamp values.
  function timestampHtml(raw) {
    const f = formatTimestamp(raw);
    if (f === null) return null;
    // data-sort-value: the real epoch millisecond value -- see
    // data-grid.js's cellSortText(), which prefers this over the
    // formatted display text for exactly this cell so chronological
    // sort/filter is never fooled by locale-formatted text.
    const epoch = Date.parse(f.exact);
    const sortAttr = Number.isNaN(epoch) ? "" : ` data-sort-value="${epoch}"`;
    return `<span class="ts-value${f.invalid ? " muted" : ""}" data-ts-utc="${esc(f.exact)}"${sortAttr} title="${esc(f.exact)}">${esc(f.display)}</span>`;
  }
  // Reformats every already-rendered timestamp in the current page in
  // place -- no re-fetch, no navigation -- when the Local/UTC
  // preference changes (wired in wire()'s change-delegation listener).
  // Convenience wrapper for call sites rendering a single named
  // timestamp field directly (rather than through the generic
  // tableFromRows()/pretty() path): real timestamp -> formatted local/
  // UTC html; anything else (e.g. the literal fallback text "never") ->
  // plain escaped text, unchanged.
  function ts(value, fallbackText) {
    return timestampHtml(value) || esc(fallbackText !== undefined ? fallbackText : value);
  }

  function bytes(value) {
    const n = Number(value || 0);
    if (!Number.isFinite(n) || n <= 0) return "0 bytes";
    const units = ["bytes", "KiB", "MiB", "GiB", "TiB"];
    let size = n;
    let unit = 0;
    while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
    return unit === 0 ? `${n} bytes` : `${size.toFixed(size >= 100 ? 0 : size >= 10 ? 1 : 2)} ${units[unit]}`;
  }

  function backupFormatLabel(format, sourceVersion) {
    if (format === "v1.1.1-tar.gz") return "V1.1.1 (.tar.gz)";
    if (format === "apdns-v2-full") return "V2 native (.apdnsbak)";
    if (format && sourceVersion && sourceVersion !== "unknown") return `${format} (${sourceVersion})`;
    return format || "Unknown";
  }

  function reformatVisibleTimestamps() {
    document.querySelectorAll("[data-ts-utc]").forEach((el) => {
      const f = formatTimestamp(el.getAttribute("data-ts-utc"));
      if (f && !f.invalid) el.textContent = f.display;
    });
  }

  function pretty(value) {
    const ts = typeof value === "string" ? timestampHtml(value) : null;
    if (ts !== null) return ts;
    if (value === null || value === undefined || value === "") return '<span class="badge inherit">inherit</span>';
    if (typeof value === "boolean") return value ? '<span class="badge ok">enabled</span>' : '<span class="badge warn">disabled</span>';
    // Real defect fixed here (owner-beta visual pass): a plain
    // String(value) on a row field that is an array of objects (e.g. an
    // upstream profile's `endpoints`) stringifies each element via its
    // default Object.prototype.toString(), rendering literally
    // "[object Object],[object Object]" in the Dashboard/Upstreams
    // tables. Render each endpoint's own address when present, and fall
    // back to real JSON for any other object shape, rather than JS's
    // default (and useless) object-to-string coercion.
    if (Array.isArray(value)) {
      if (!value.length) return '<span class="badge inherit">inherit</span>';
      return esc(value.map((v) => (v && typeof v === "object" ? (v.address ?? JSON.stringify(v)) : v)).join(", "));
    }
    if (typeof value === "object") return esc(JSON.stringify(value));
    return esc(value);
  }

  function tone(status) {
    const s = String(status || "").toLowerCase();
    if (["ok", "active", "created", "promoted", "saved"].includes(s)) return "ok";
    if (["degraded", "warning", "self-signed"].includes(s)) return "warn";
    if (["failed", "error", "unavailable", "inactive"].includes(s)) return "bad";
    return "info";
  }

  function setTheme(theme) {
    state.theme = theme === "light" ? "light" : "dark";
    localStorage.setItem("apdnsTheme", state.theme);
    document.documentElement.dataset.theme = state.theme;
  }

  // After a real Software Update apply, the packaged postinst restarts
  // alderpointdns-v2-web -- the very process serving this request. The
  // apply-request call above already returned (the privileged helper
  // runs asynchronously via the .path/.service unit), so this polls
  // /api/session until the appliance is reachable again rather than
  // leaving the operator on a page that silently stopped updating.
  async function waitForReconnectAfterUpdate() {
    await waitForReconnect("updates", "Update in progress -- the appliance may become briefly unreachable while it restarts");
  }

  async function waitForReconnect(forRoute, inProgressMessage) {
    toast(inProgressMessage, "info");
    await sleep(1500);
    for (let attempt = 0; attempt < 60; attempt++) {
      try {
        await api("/api/session");
        toast("Reconnected", "ok");
        // Real defect fixed here (found via the browser harness, beta-
        // rescue priority 5/8): this polling loop runs in the
        // background while the caller's click handler has already
        // returned, so the operator is free to navigate elsewhere while
        // it's still waiting to reconnect. Reloading unconditionally
        // here would silently yank them back to a page they may have
        // long since left -- and would also race/clobber whatever they
        // navigated to next (loadPage's own stale-token guard doesn't
        // help: this call is simply issued *late*, not stale, so it
        // would legitimately "win" and overwrite the current, correct
        // page). Only refresh if the operator is still actually on the
        // page this reconnect was for.
        if (state.route === forRoute) await loadPage(forRoute);
        return;
      } catch (_) {
        await sleep(2000);
      }
    }
    toast("Still waiting to reconnect -- refresh the page manually if this persists", "warn");
  }

  function sleep(ms) {
    return new Promise((resolve) => setTimeout(resolve, ms));
  }

  function toast(message, kind) {
    let host = document.querySelector(".toast-host");
    if (!host) {
      host = document.createElement("div");
      host.className = "toast-host";
      document.body.appendChild(host);
    }
    const node = document.createElement("div");
    node.className = `toast ${kind || "info"}`;
    node.textContent = message;
    host.appendChild(node);
    setTimeout(() => node.remove(), 5200);
  }

  // Real defect fixed here (owner-reported: 10+ rapid Light/Dark clicks
  // leave the page stuck on "Loading"). Every loadPage() call (a route
  // change, a theme toggle, a collapse toggle -- all of them re-render
  // and re-fetch the current route) previously left its own GET requests
  // running to completion even after a newer loadPage() superseded it;
  // `token` already stopped a stale response from being *rendered*, but
  // did nothing to stop it from still executing. A rapid-click storm
  // therefore piled up N abandoned page-load fetches all still competing
  // for the browser's connection pool and the backend's own request
  // capacity, which could starve the one response that actually mattered
  // indefinitely -- exactly "stuck on Loading" with no error, no
  // eventual recovery. `pageLoadController` is aborted and replaced at
  // the top of every loadPage() call so only the most recent page-load's
  // GETs are ever still in flight; mutations (POST/PUT/DELETE, e.g. form
  // submits, promote/sync/backup actions) are never auto-aborted this
  // way since aborting a write client-side does not undo it server-side.
  let pageLoadController = null;

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options || {});
    const perfOptions = { background: !!opts.background, navigationId: opts.navigationId || state.currentNavigationId || "" };
    delete opts.background;
    delete opts.navigationId;
    opts.headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
    if (opts.body && !(opts.body instanceof FormData)) opts.headers["Content-Type"] = "application/json";
    const method = (opts.method || "GET").toUpperCase();
    const requestId = Math.random().toString(16).slice(2, 14);
    opts.headers["X-Request-ID"] = requestId;
    if (!/^(GET|HEAD)$/.test(method)) opts.headers["X-CSRF-Token"] = state.csrf;
    else if (!opts.signal && pageLoadController) opts.signal = pageLoadController.signal;
    const cacheKey = method === "GET" ? `${method} ${path}` : "";
    if (cacheKey && state.inFlightGets.has(cacheKey)) return state.inFlightGets.get(cacheKey);
    const started = nowMs();
    const requestEntry = { type: "api", route: state.route, path: path.split("?", 1)[0], method, request_id: requestId, timestamp: absNow(), navigation_id: perfOptions.navigationId, background: perfOptions.background };
    const promise = (async () => {
      const res = await fetch(path, opts);
      const ttfb = nowMs();
      let body = null;
      const text = await res.text();
      const complete = nowMs();
      try { body = text ? JSON.parse(text) : null; } catch (_) { body = { error: "invalid_json", detail: text.slice(0, 240) }; }
      const parsed = nowMs();
      perfSave(Object.assign(requestEntry, {
        status: res.status,
        ttfb_ms: Math.round(ttfb - started),
        download_ms: Math.round(complete - ttfb),
        parse_ms: Math.round(parsed - complete),
        total_ms: Math.round(parsed - started),
        server_timing: parseServerTiming(res.headers.get("Server-Timing")),
        response_request_id: res.headers.get("X-Request-ID") || "",
      }));
      if (!res.ok) {
        const detail = body && (body.detail || body.error) ? `${body.error || "error"}: ${body.detail || ""}` : `HTTP ${res.status}`;
        const err = new Error(detail);
        err.status = res.status;
        err.body = body;
        throw err;
      }
      return body || {};
    })();
    if (cacheKey) state.inFlightGets.set(cacheKey, promise.finally(() => state.inFlightGets.delete(cacheKey)));
    if (!/^(GET|HEAD)$/.test(method)) state.routeCache.clear();
    return promise;
  }

  async function waitBlocklistJob(jobId) {
    if (!jobId) return null;
    for (let i = 0; i < 60; i += 1) {
      const job = await api(`/api/blocklists/jobs/${encodeURIComponent(jobId)}`);
      if (job.status && job.status !== "running") return job;
      await new Promise((resolve) => setTimeout(resolve, Math.min(1000 + i * 100, 2500)));
    }
    return { status: "running", job_id: jobId, error: "update is still running" };
  }

  function jsonForm(form) {
    const data = new FormData(form);
    const body = {};
    for (const [key, value] of data.entries()) {
      if (value === "" && form.elements[key]?.dataset?.omitEmpty === "1") continue;
      if (form.elements[key]?.dataset?.number === "1") body[key] = Number(value);
      else if (form.elements[key]?.dataset?.bool === "1") body[key] = value === "true";
      else body[key] = value;
    }
    return body;
  }

  function idFrom(input) {
    return String(input || "").trim().toLowerCase().replace(/[^a-z0-9_.:-]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 64);
  }

  // Real defect fixed here (found while wiring the Import preview panel,
  // priority 2 of the beta-rescue brief): every handleForm branch that
  // renders its own inline result -- explain, the query-log filter form,
  // migration detection, and now import preview -- returned early after
  // writing directly into a results <div>, but submitOnce still
  // unconditionally toasted "Operation completed" and called
  // loadPage(state.route) afterward. Since state.route had not changed,
  // that reload re-fetched and re-rendered the entire page, silently
  // wiping the inline result the handler had just written a moment
  // earlier (the existing Chromium harness masked this for Explain by
  // accepting either the real result OR the untouched placeholder text).
  // handleForm now returns "skip-reload" from those branches so
  // submitOnce knows the handler already rendered its own outcome and
  // must not blow it away with a full page reload.
  async function submitOnce(form, handler) {
    if (form.dataset.busy === "1") return;
    form.dataset.busy = "1";
    const buttons = form.querySelectorAll("button");
    buttons.forEach((b) => b.disabled = true);
    try {
      const outcome = await handler(form);
      if (outcome !== "skip-reload") {
        // Real defect fixed here (root-caused via the browser harness,
        // priority 10 of the beta-rescue brief): the toast previously
        // fired BEFORE awaiting loadPage(), so "Operation completed"
        // could be visible while the page was still mid-reload (still
        // showing the "Loading..." placeholder, or about to replace a
        // form the operator/a test was about to interact with next).
        // The toast is now the reload's own completion signal, not a
        // separate, earlier one.
        await loadPage(state.route);
        toast("Operation completed", "ok");
      }
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      form.dataset.busy = "0";
      buttons.forEach((b) => b.disabled = false);
    }
  }

  function shell() {
    const grouped = pages.reduce((acc, p) => ((acc[p[0]] = acc[p[0]] || []).push(p), acc), {});
    // Dashboard is a standalone top-level entry above every group, matching
    // V1.1.1 -- it is never itself inside a collapsible section, so it is
    // always exactly one click away regardless of nav-collapse state.
    const dashboardBtn = `<button data-route="dashboard" class="nav-top ${state.route === "dashboard" ? "active" : ""}"><span class="nav-icon">${DASHBOARD_ICON}</span><span class="nav-top__label">Dashboard</span></button>`;
    return `
      <div class="layout">
        <aside class="sidebar">
          <div class="brand">
            <div class="mark">A</div>
            <span><strong>Alderpoint DNS</strong><small>V2 management console</small></span>
            <button class="collapse-toggle" data-action="collapse" aria-pressed="${state.navCollapsed}" title="${state.navCollapsed ? "Expand" : "Collapse"} navigation">${state.navCollapsed ? "»" : "«"}</button>
          </div>
          <nav class="nav" aria-label="Main navigation">
            ${dashboardBtn}
            ${GROUP_ORDER.filter((g) => grouped[g]).map((group) => {
              const items = grouped[group];
              const activeInGroup = items.some(([, id]) => state.route === id);
              const open = navSectionOpen(group, activeInGroup);
              const panelId = `nav-panel-${group.toLowerCase()}`;
              return `
              <section class="nav-section${activeInGroup ? " is-active" : ""}" data-nav-section="${group}">
                <button type="button" class="nav-section__toggle" data-nav-section-toggle aria-expanded="${open}" aria-controls="${panelId}" aria-label="${esc(group)}" title="${esc(group)}" ${activeInGroup ? 'aria-current="true"' : ""}>
                  <span class="nav-icon">${GROUP_ICON[group] || ""}</span>
                  <span class="nav-section__label">${esc(group)}</span>
                  <span class="nav-section__chevron" aria-hidden="true">${open ? "▾" : "▸"}</span>
                </button>
                <div class="nav-section__panel" id="${panelId}" ${open ? "" : "hidden"}>
                  ${items.map(([, id, label]) => `<button data-route="${id}" class="nav-subitem${state.route === id ? " active" : ""}" title="${esc(label)}" ${state.route === id ? 'aria-current="page"' : ""}><span>${esc(label)}</span></button>`).join("")}
                </div>
              </section>`;
            }).join("")}
          </nav>
          <div class="side-footer">
            <button data-action="theme" title="${state.theme === "dark" ? "Light theme" : "Dark theme"}"><span class="glyph">${state.theme === "dark" ? "☀" : "☽"}</span><span>${state.theme === "dark" ? "Light theme" : "Dark theme"}</span></button>
            <button data-action="logout" class="danger" title="Log out"><span class="glyph">→</span><span>Log out</span></button>
          </div>
        </aside>
        <main class="main">
          <div class="topbar"><button data-action="menu">Menu</button><strong>Alderpoint DNS</strong><button data-action="theme">${state.theme === "dark" ? "Light" : "Dark"}</button></div>
          <section id="page"></section>
        </main>
      </div>`;
  }

  // Single choke point for (re)rendering the shell so the nav-collapsed
  // state (a CSS class, not a JS reflow of geometry) is always reapplied
  // consistently -- theme toggling and collapse toggling both replace
  // #app's innerHTML, and previously only one of the two paths remembered
  // to keep the collapsed class in sync.
  function renderShell() {
    const app = document.getElementById("app");
    app.innerHTML = shell();
    app.classList.toggle("nav-collapsed", state.navCollapsed);
  }

  function page(title, intro, actions, body) {
    return `
      <header class="page-head">
        <div class="page-head__row">
          <div><h1>${esc(title)}</h1><p>${esc(intro || "")}</p></div>
          <div class="page-actions">${actions || ""}</div>
        </div>
      </header>
      <div class="content">${body}</div>`;
  }

  async function common() {
    const requests = [
      api("/api/health").catch((e) => ({ status: "unavailable", error: e.message, components: {} })),
      api("/api/system/status").catch(() => ({})),
      api("/api/replication/health").catch(() => ({ peers: [] })),
      api("/api/discovery/status").catch(() => ({})),
    ];
    const [health, system, replication, discovery] = await Promise.all(requests);
    if (system.timezone) state.applianceTimezone = system.timezone;
    return { health, system, replication, discovery };
  }

  // Fetches and caches the appliance's real detected timezone (see
  // webapp.py's _detect_appliance_timezone()) exactly once per session
  // -- every page that needs it (the timestamp display-mode selector,
  // any page not already calling common()) shares the same cached
  // value instead of re-fetching. Never a hardcoded zone: null until
  // genuinely known.
  let applianceTimezoneFetch = null;
  async function ensureApplianceTimezone() {
    if (state.applianceTimezone) return state.applianceTimezone;
    if (!applianceTimezoneFetch) {
      applianceTimezoneFetch = api("/api/system/status")
        .then((s) => { state.applianceTimezone = s.timezone || null; return state.applianceTimezone; })
        .catch(() => null);
    }
    return applianceTimezoneFetch;
  }

  // granularity is derived from the selected range, not independently
  // chosen -- 1h buckets by minute, 24h/7d by hour, keeping the point
  // count sane for both the SVG chart and its table fallback (7d @
  // hourly = 168 points; @ minute would be >10,000).
  function dashboardGranularity(minutes) {
    if (minutes === "live") return "minute";
    if (minutes <= 120) return "minute";
    return "hour";
  }

  // Real performance fix (owner-reported: route navigation must not
  // block on the slowest panel). Dashboard's two analytics panels (the
  // activity time-series and the domain ranking) are backed by the
  // heaviest real queries on the page -- a DuckDB/Parquet scan and a
  // SQLite aggregate rollup -- while every other panel here is a small,
  // fast lookup (system/health status, replication, discovery counts,
  // managed clients, upstream profiles). Fetching everything through one
  // Promise.all and rendering only once ALL of it resolves means the
  // slowest of those seven real network calls gates the entire page,
  // even though six of them are typically fast. This renders the fast
  // group immediately with real placeholder panels for the two slow
  // ones, then fetches and injects each slow panel independently as
  // soon as it resolves -- one genuinely slow panel (e.g. a large real
  // query-log history under load) no longer blocks the metrics strip,
  // clients, or upstreams from appearing.
  async function dashboard() {
    const isLive = state.dashboardRangeMinutes === "live";
    const rangeMinutes = isLive ? 60 : Number(state.dashboardRangeMinutes);
    const granularity = dashboardGranularity(rangeMinutes);
    const topMode = state.dashboardTopMode;
    const [c, recent, clients, observed, upstreams] = await Promise.all([
      common(),
      api("/api/analytics/recent?minutes=60").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
      api("/api/clients").catch(() => ({ clients: [] })),
      // Owner-reported finding, priority 3 of the second beta-rescue pass: a
      // real client was actively querying Alderpoint, but Dashboard
      // showed no clients at all -- because this panel only ever asked
      // for MANAGED clients (an explicit, operator-created record), even
      // though the "Observed clients" count just above it already came
      // from the real, asynchronous discovery pipeline (never the DNS
      // hot path) and was genuinely non-zero. A fresh appliance must
      // show devices actually using it before the operator has
      // configured anything.
      api("/api/discovery/observed-clients?limit=8").catch(() => ({ items: [] })),
      api("/api/upstreams").catch(() => ({ upstreams: [] })),
    ]);
    const rows = recent.rows || [];
    // Real defect fixed here: this previously counted "blocked" by
    // searching each row's serialized JSON text for the substring
    // "block" -- a false-positive-prone heuristic (matches domain names,
    // cache-status/block_reason text, etc. regardless of the row's real
    // `blocked` value) instead of reading the canonical typed boolean
    // field the backend already returns. All dashboard/query-log metrics
    // must use typed fields, not string heuristics.
    const blockedIdx = (recent.columns || []).indexOf("blocked");
    const blocked = blockedIdx === -1 ? 0 : rows.filter((r) => r[blockedIdx] === true).length;
    loadSlowDashboardPanels(isLive ? "live" : rangeMinutes, granularity, topMode);
    return page("Dashboard", "Operational state from the real V2 HTTPS APIs.", `<button data-refresh>Refresh</button>`, `
      <div class="strip">
        <div class="metric"><strong>${esc(c.health.status || "unknown")}</strong><span>Management / runtime status</span></div>
        <div class="metric"><strong>${rows.length}</strong><span>Recent query rows</span></div>
        <div class="metric"><strong>${blocked}</strong><span>Blocked signals in recent rows</span></div>
        <div class="metric"><strong>${esc(c.discovery.observed_count ?? 0)}</strong><span>Observed clients</span></div>
        <div class="metric"><strong>${esc((c.replication.peers || []).length)}</strong><span>Replication peers</span></div>
      </div>
      ${recent.degraded ? `<div class="alert warn">Analytics degraded: ${esc(recent.degraded_reason || "query data unavailable")}. DNS status is reported separately.</div>` : ""}
      <section class="panel"><div class="panel__head"><h2>DNS Activity</h2>${rangeSelector()}</div><div class="panel__body" id="dashboard-activity-panel"><div class="empty">Loading activity...</div></div></section>
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>${topMode === "blocked" ? "Top Blocked Domains" : "Top Domains"}</h2>${topModeSelector()}</div><div class="panel__body" id="dashboard-topdomains-panel"><div class="empty">Loading...</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Runtime Components</h2></div><div class="panel__body">${componentList(c.health.components || {})}</div></section>
        <section class="panel"><div class="panel__head"><h2>Clients</h2><button class="link" data-route="clients">Manage</button></div><div class="panel__body">${clientMini(clients.clients || [], observed.items || observed.observed_clients || observed.clients || [])}</div></section>
        <section class="panel"><div class="panel__head"><h2>Upstreams</h2></div><div class="panel__body">${upstreams.upstreams?.length ? tableFromRows(upstreams.upstreams, 5, undefined, "dashboard-upstreams") : `<div class="empty">No upstream profiles configured.</div>`}</div></section>
      </div>`);
  }

  // Fetches and injects the two slow Dashboard panels independently of
  // the fast-render path above. Guarded by the current loadToken (the
  // same staleness guard loadPage() itself uses) so a slow response
  // that finally resolves after the operator has already navigated
  // elsewhere never overwrites a different, now-current page.
  function loadSlowDashboardPanels(rangeMinutes, granularity, topMode) {
    const token = loadToken;
    if (rangeMinutes === "live") {
      setTimeout(() => {
        if (token !== loadToken || state.route !== "dashboard") return;
        const el = document.getElementById("dashboard-activity-panel");
        if (!el) return;
        el.innerHTML = liveActivityShell();
        startLiveActivity(token, topMode);
      }, 0);
      refreshDashboardTopDomains(token, 60, topMode);
      return;
    }
    api(`/api/analytics/timeseries?minutes=${rangeMinutes}&granularity=${granularity}`)
      .catch((e) => ({ buckets: [], degraded: true, degraded_reason: e.message }))
      .then((timeseries) => {
        if (token !== loadToken) return;
        const el = document.getElementById("dashboard-activity-panel");
        if (el) el.innerHTML = activityChart(timeseries);
      });
    refreshDashboardTopDomains(token, rangeMinutes, topMode);
  }

  function refreshDashboardTopDomains(token, rangeMinutes, topMode) {
    api(`/api/analytics/${topMode === "blocked" ? "top-blocked-domains" : "top-domains"}?minutes=${rangeMinutes}&limit=15`)
      .catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message }))
      .then((topResult) => {
        if (token !== loadToken) return;
        const el = document.getElementById("dashboard-topdomains-panel");
        if (el) el.innerHTML = topDomainsTable(topResult);
      });
  }

  function rangeSelector() {
    const options = [["live", "Live"], [60, "Last hour"], [1440, "Last 24 hours"], [10080, "Last 7 days"]];
    return `<select data-action="dashboard-range" aria-label="DNS activity time range">${options.map(([v, l]) => `<option value="${v}" ${state.dashboardRangeMinutes === v ? "selected" : ""}>${esc(l)}</option>`).join("")}</select>`;
  }

  function liveActivityShell() {
    return `<div class="live-toolbar">
      <span class="badge info" data-live-status>Connecting</span>
      <span class="metric-inline">Queries this second: <strong data-live-current>0</strong></span>
      <span class="metric-inline">QPS (10s avg): <strong data-live-qps>0</strong></span>
      <span class="metric-inline">Blocked (10s): <strong data-live-blocked>0%</strong></span>
      <button type="button" data-action="dashboard-live-pause">${state.dashboardLivePaused ? "Resume" : "Pause"}</button>
    </div>
    <div id="dashboard-live-chart">
      <div class="ts-legend">
        <span class="ts-legend-item"><span class="ts-swatch ts-swatch-total"></span>DNS Queries</span>
        <span class="ts-legend-item"><span class="ts-swatch ts-swatch-blocked"></span>Blocked by Filters</span>
      </div>
      <div class="ts-wrap"><div class="ts-svg-host" id="dashboard-live-svg-host" data-live-chart-host><div class="empty">Loading activity...</div></div></div>
    </div>`;
  }

  function cleanupDashboardLive() {
    if (state.dashboardLiveTimer) {
      clearInterval(state.dashboardLiveTimer);
      state.dashboardLiveTimer = null;
    }
    if (state.dashboardLiveAbort) {
      state.dashboardLiveAbort.abort();
      state.dashboardLiveAbort = null;
    }
    document.querySelectorAll(".ts-svg-host").forEach((host) => {
      if (host.__apdnsRO) host.__apdnsRO.disconnect();
    });
  }

  function startLiveActivity(token, topMode) {
    cleanupDashboardLive();
    const pollMs = 1000;
    let topRefresh = 0;
    let inFlight = false;
    let lastAppliedSeq = 0;
    async function poll() {
      if (token !== loadToken || state.route !== "dashboard") return cleanupDashboardLive();
      const status = document.querySelector("[data-live-status]");
      if (state.dashboardLivePaused) {
        if (status) status.textContent = "Paused";
        return;
      }
      if (inFlight) {
        state.dashboardLiveDiagnostics.overlap_skips += 1;
        return;
      }
      inFlight = true;
      const seq = ++state.dashboardLivePollSeq;
      const controller = new AbortController();
      state.dashboardLiveAbort = controller;
      try {
        if (status && lastAppliedSeq === 0) status.textContent = "Connecting";
        const data = await api("/api/analytics/live-activity?seconds=300&bucket_seconds=1", { signal: controller.signal, background: true, navigationId: `live-${token}` });
        if (token !== loadToken || state.route !== "dashboard") return;
        if (seq < lastAppliedSeq) {
          state.dashboardLiveDiagnostics.stale_discards += 1;
          return;
        }
        lastAppliedSeq = seq;
        if (data.degraded) {
          if (status) status.textContent = "Degraded";
          const chart = document.getElementById("dashboard-live-chart");
          if (chart) chart.innerHTML = `<div class="alert warn">${esc(data.degraded_reason || "Live analytics unavailable")}</div>`;
          return;
        }
        document.querySelector("[data-live-current]").textContent = formatCompactNumber(data.current_bucket_count || 0);
        document.querySelector("[data-live-qps]").textContent = formatCompactNumber(data.rolling_10s_qps || 0);
        document.querySelector("[data-live-blocked]").textContent = `${formatCompactNumber(data.rolling_10s_blocked_percent || 0)}%`;
        const buckets = data.buckets || [];
        const total = buckets.reduce((s, b) => s + (Number(b.total_queries) || 0), 0);
        if (status) status.textContent = total > 0 ? "Connected" : "Connected - no recent activity";
        const renderStart = nowMs();
        requestAnimationFrame(() => {
          const host = document.getElementById("dashboard-live-svg-host");
          if (host && token === loadToken && state.route === "dashboard") updateActivityChartHost(host, { buckets, granularity: "second" });
          state.dashboardLiveDiagnostics.renders.unshift({ at: absNow(), duration_ms: Math.round(nowMs() - renderStart), navigation_id: `live-${token}`, buckets: buckets.length });
          state.dashboardLiveDiagnostics.renders = state.dashboardLiveDiagnostics.renders.slice(0, 30);
        });
        const now = Date.now();
        if (now - topRefresh > 30000) {
          topRefresh = now;
          refreshDashboardTopDomains(token, 60, topMode);
        }
      } catch (err) {
        if (token !== loadToken || state.route !== "dashboard") return;
        if (status) status.textContent = "Reconnecting";
        state.dashboardLiveDiagnostics.failures.unshift({ at: absNow(), message: String(err.message || err).slice(0, 160) });
        state.dashboardLiveDiagnostics.failures = state.dashboardLiveDiagnostics.failures.slice(0, 10);
      } finally {
        if (state.dashboardLiveAbort === controller) state.dashboardLiveAbort = null;
        inFlight = false;
      }
    }
    poll();
    state.dashboardLiveTimer = setInterval(poll, pollMs);
  }

  function topModeSelector() {
    return `<select data-action="dashboard-top-mode" aria-label="Domain ranking">
      <option value="top" ${state.dashboardTopMode === "top" ? "selected" : ""}>All domains</option>
      <option value="blocked" ${state.dashboardTopMode === "blocked" ? "selected" : ""}>Blocked domains only</option>
    </select>`;
  }

  function formatCompactNumber(value) {
    const n = Number(value) || 0;
    return n.toFixed(2).replace(/\.?0+$/, "");
  }

  // Real defect fixed here (owner-reported: the prior "chart" was a row
  // of anonymous <div class="bar"> elements with the only value anyone
  // could see stuffed into a `title` attribute -- invisible until
  // hover, unreachable by keyboard, and not a real time-series at all,
  // just the ranked top-domains dataset reused as bar heights). This is
  // a real SVG time-series over app/v2/aggregates_db.py's own bucketed
  // totals (via /api/analytics/timeseries) -- two series (DNS Queries,
  // Blocked by Filters), a real legend, local-time axis labels, exact
  // values in both a native <title> tooltip AND a keyboard-reachable,
  // always-visible table fallback (never hover-only). Truthful
  // loading/empty/degraded states: this function is only ever called
  // with an already-resolved result (loading is the page shell's own
  // "Loading..." state), so it only needs to distinguish degraded from
  // genuinely-empty from populated.
  // Real defect fixed here (owner-reported: the chart rendered at a
  // fixed 760px viewBox width with no CSS width rule, so it never
  // filled its card and felt like a static image rather than a
  // responsive dashboard chart). The SVG's viewBox width is now
  // regenerated to match the container's REAL measured pixel width
  // (via ResizeObserver, see mountActivityChart below) -- one viewBox
  // unit equals one real CSS pixel, so stroke widths/font sizes never
  // stretch or shrink independent of the actual rendered size the way
  // they would if a fixed-760 viewBox were merely scaled by CSS
  // width:100%. Tick label density is recomputed for the real width
  // each time, never overlapping regardless of how narrow the card is.
  let activityChartHostSeq = 0;
  function activityChart(result) {
    if (result.degraded) return `<div class="alert warn">Analytics degraded: ${esc(result.degraded_reason || "time-series data unavailable")}. DNS status is reported separately.</div>`;
    const buckets = result.buckets || [];
    const legend = `<div class="ts-legend">
      <span class="ts-legend-item"><span class="ts-swatch ts-swatch-total"></span>DNS Queries</span>
      <span class="ts-legend-item"><span class="ts-swatch ts-swatch-blocked"></span>Blocked by Filters</span>
    </div>`;
    if (!buckets.length) return `${legend}<div class="empty">No query activity in this window.</div>`;
    const hostId = `ts-svg-host-${++activityChartHostSeq}`;
    const totalSum = buckets.reduce((s, b) => s + (b.total_queries || 0), 0);
    const blockedSum = buckets.reduce((s, b) => s + (b.blocked_queries || 0), 0);
    const chartZone = resolveDisplayTimeZone();
    const n = buckets.length;
    const fmt = (iso) => new Date(iso).toLocaleString(undefined, Object.assign({ timeZone: chartZone }, n <= 24 && result.granularity === "hour" ? { hour: "numeric", minute: "2-digit" } : result.granularity === "minute" ? { hour: "numeric", minute: "2-digit" } : { month: "short", day: "numeric" }));
    const tableRows = buckets.map((b) => ({ time: fmt(b.bucket_start_iso), exact_time_utc: b.bucket_start_iso, dns_queries: b.total_queries || 0, blocked_by_filters: b.blocked_queries || 0 }));
    // Scheduled for right after this html string is actually inserted
    // into the DOM by the caller (mountActivityChart measures the real
    // element, which doesn't exist yet at string-build time here).
    setTimeout(() => mountActivityChart(hostId, result), 0);
    return `${legend}
      <div class="ts-wrap"><div class="ts-svg-host" id="${hostId}"><div class="empty">Rendering chart...</div></div></div>
      <div class="strip" style="margin-top:10px"><div class="metric"><strong>${totalSum}</strong><span>Total queries</span></div><div class="metric"><strong>${blockedSum}</strong><span>Blocked by filters</span></div></div>
      <details class="ts-table-fallback"><summary>View exact values as a table</summary>${tableFromRows(tableRows, 500, undefined, "dashboard-activity")}</details>`;
  }

  // Measures the real host element and (re)renders the SVG at that
  // exact pixel width, then keeps it correct as the container resizes
  // (viewport resize, sidebar collapse/expand, orientation change).
  function mountActivityChart(hostId, result) {
    const host = document.getElementById(hostId);
    if (!host) return; // navigated away before this ever mounted
    updateActivityChartHost(host, result);
  }

  function updateActivityChartHost(host, result) {
    host.__apdnsResult = result;
    function redraw() {
      if (!document.body.contains(host)) { if (host.__apdnsRO) host.__apdnsRO.disconnect(); return; }
      const width = Math.max(280, Math.round(host.clientWidth) || 600);
      const before = host.querySelector("svg.ts-chart");
      host.innerHTML = renderActivitySvgMarkup(host.__apdnsResult || result, width);
      if (before) state.dashboardLiveDiagnostics.replacement_count += 1;
    }
    host.__apdnsRedraw = redraw;
    if (!host.__apdnsRO && typeof ResizeObserver !== "undefined") {
      const ro = new ResizeObserver(() => redraw());
      ro.observe(host);
      host.__apdnsRO = ro;
    } else if (!host.__apdnsRO) {
      window.addEventListener("resize", redraw);
    }
    redraw();
  }

  // Pure(ish) markup builder: given real bucket data and a real target
  // pixel width, returns the SVG at exactly that width -- viewBox width
  // === widthPx, so every stroke-width/font-size CSS rule applies at
  // its real, undistorted size no matter how the card is sized.
  function renderActivitySvgMarkup(result, widthPx) {
    const buckets = result.buckets || [];
    const w = widthPx, h = 220;
    const padL = 46, padB = 30, padT = 12, padR = 12;
    const plotW = w - padL - padR, plotH = h - padT - padB;
    const maxTotal = Math.max(1, ...buckets.map((b) => b.total_queries || 0));
    const n = buckets.length;
    const x = (i) => padL + (n === 1 ? plotW / 2 : (i / (n - 1)) * plotW);
    const y = (v) => padT + plotH - (v / maxTotal) * plotH;
    const path = (key) => buckets.map((b, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)},${y(b[key] || 0).toFixed(1)}`).join(" ");
    // Tick labels are selected using real measured label widths below;
    // never force first/last labels if the browser's actual locale/time
    // formatting would make them collide.
    const chartZone = resolveDisplayTimeZone();
    const fmt = (iso) => new Date(iso).toLocaleString(undefined, Object.assign({ timeZone: chartZone }, result.granularity === "second" ? { hour: "numeric", minute: "2-digit", second: "2-digit" } : n <= 24 && result.granularity === "hour" ? { hour: "numeric", minute: "2-digit" } : result.granularity === "minute" ? { hour: "numeric", minute: "2-digit" } : { month: "short", day: "numeric" }));
    const labelWidth = (text) => measureSvgAxisLabel(text);
    const tickIndexes = chooseXAxisTicks(buckets, fmt, x, plotW, labelWidth);
    const gridlines = [0, 0.25, 0.5, 0.75, 1].map((f) => `<line x1="${padL}" x2="${w - padR}" y1="${(padT + plotH * f).toFixed(1)}" y2="${(padT + plotH * f).toFixed(1)}" class="ts-grid"/>`).join("");
    const yLabels = [0, 0.5, 1].map((f) => `<text x="${padL - 6}" y="${(padT + plotH * (1 - f) + 4).toFixed(1)}" class="ts-axis" text-anchor="end">${Math.round(maxTotal * f)}</text>`).join("");
    const xLabels = tickIndexes.map((i) => `<text x="${x(i).toFixed(1)}" y="${h - 8}" class="ts-axis" text-anchor="middle">${esc(fmt(buckets[i].bucket_start_iso))}</text>`).join("");
    // Purely visual SVG markers -- <title> stays as a harmless native
    // fallback, but real interaction lives on the real HTML <button>
    // hit-targets below, not here. Real defect found live via the
    // Chromium harness (not source inspection): a focusable SVG
    // <circle> (tabindex + real .focus()) correctly became
    // document.activeElement but never dispatched an observable
    // focus/focusin event in this browser -- keyboard-driven tooltip
    // reveal was silently unreachable despite activeElement looking
    // correct. A real <button> element's focus behavior has no such
    // ambiguity in any browser, so the actual interactive target is a
    // real button, positioned exactly over its SVG marker.
    const dot = (b, i, key, cls) => `<circle cx="${x(i).toFixed(1)}" cy="${y(b[key] || 0).toFixed(1)}" r="4" class="${cls}"><title>${esc(fmt(b.bucket_start_iso))}: ${esc(b[key] || 0)}</title></circle>`;
    const dots = (key, cls) => buckets.map((b, i) => dot(b, i, key, cls)).join("");
    // Real interactive tooltip target (owner-reported: a native <title>
    // alone is not an adequate tooltip system). One real, focusable
    // <button> per point per series, absolutely positioned over its
    // SVG marker (the wrapping .ts-chart-overlay is position:relative;
    // 1 SVG user unit === 1 real CSS px by construction here, so the
    // same x()/y() coordinates used for the SVG marker place the button
    // exactly on top of it) -- carries the full data as data-* so
    // wire()'s delegated mouseover/focus/click handlers (see
    // [data-tp-time]) can build and position a shared floating
    // tooltip, working identically for mouse hover, real keyboard
    // focus, and touch/click.
    const hit = (b, i, key, cls, label) => {
      const value = b[key] || 0;
      const total = b.total_queries || 0;
      const blocked = b.blocked_queries || 0;
      const pct = total > 0 ? Math.round((blocked / total) * 100) : 0;
      const timeLabel = fmt(b.bucket_start_iso);
      const a11y = `${timeLabel}: ${value} ${label}${key === "total_queries" ? `, ${blocked} blocked (${pct}%)` : ""}`;
      const cx = x(i), cy = y(value);
      return `<button type="button" class="ts-point-hit ${cls}" style="left:${cx.toFixed(1)}px;top:${cy.toFixed(1)}px" aria-label="${esc(a11y)}" data-tp-time="${esc(timeLabel)}" data-tp-total="${esc(total)}" data-tp-blocked="${esc(blocked)}" data-tp-pct="${esc(pct)}"></button>`;
    };
    const hits = (key, cls, label) => buckets.map((b, i) => hit(b, i, key, cls, label)).join("");
    return `<div class="ts-chart-overlay" style="width:${w}px;height:${h}px">
      <svg viewBox="0 0 ${w} ${h}" width="${w}" height="${h}" class="ts-chart" role="img" aria-label="DNS queries and blocked queries over time">
        ${gridlines}${yLabels}${xLabels}
        <path d="${path("total_queries")}" class="ts-line ts-line-total"/>
        <path d="${path("blocked_queries")}" class="ts-line ts-line-blocked"/>
        ${dots("total_queries", "ts-point-total")}
        ${dots("blocked_queries", "ts-point-blocked")}
      </svg>
      ${hits("total_queries", "ts-point-total", "queries")}
      ${hits("blocked_queries", "ts-point-blocked", "blocked")}
    </div>`;
  }

  let axisMeasureCanvas = null;
  function measureSvgAxisLabel(text) {
    try {
      axisMeasureCanvas = axisMeasureCanvas || document.createElement("canvas");
      const ctx = axisMeasureCanvas.getContext("2d");
      const family = getComputedStyle(document.documentElement).getPropertyValue("--font") || "system-ui, sans-serif";
      ctx.font = `10px ${family}`;
      return ctx.measureText(String(text)).width;
    } catch (_) {
      return String(text).length * 6;
    }
  }

  function chooseXAxisTicks(buckets, fmt, x, plotW, labelWidth) {
    const n = buckets.length;
    if (!n) return [];
    const minGap = 14;
    const target = plotW >= 900 ? 7 : plotW >= 650 ? 6 : plotW >= 420 ? 4 : 3;
    const candidates = [];
    if (target <= 1 || n === 1) candidates.push(0);
    else {
      for (let j = 0; j < target; j += 1) {
        const idx = Math.round((j * (n - 1)) / (target - 1));
        if (!candidates.includes(idx)) candidates.push(idx);
      }
    }
    const accepted = [];
    for (const idx of candidates) {
      const text = fmt(buckets[idx].bucket_start_iso);
      const half = labelWidth(text) / 2;
      const left = x(idx) - half;
      const right = x(idx) + half;
      const collides = accepted.some((item) => left < item.right + minGap && right > item.left - minGap);
      if (!collides) accepted.push({ idx, left, right });
    }
    return accepted.map((item) => item.idx);
  }

  // Real domain names, real counts, real percentage of total -- a real
  // sortable table (the shared data-grid, per "sortable means sortable
  // product-wide"), not bars with hidden values.
  function topDomainsTable(result) {
    if (result.degraded) return `<div class="alert warn">Analytics degraded: ${esc(result.degraded_reason || "domain ranking unavailable")}. DNS status is reported separately.</div>`;
    const rows = result.rows || [];
    if (!rows.length) return `<div class="empty">No domain activity in this window.</div>`;
    const cols = result.columns || [];
    const domainIdx = cols.indexOf("domain");
    const countIdx = cols.indexOf("count");
    const total = rows.reduce((s, r) => s + (Number(countIdx === -1 ? r[1] : r[countIdx]) || 0), 0) || 1;
    const shaped = rows.map((r) => {
      const count = Number(countIdx === -1 ? r[1] : r[countIdx]) || 0;
      return { domain: domainIdx === -1 ? r[0] : r[domainIdx], queries: count, percent_of_total: `${((count / total) * 100).toFixed(1)}%` };
    });
    return tableFromRows(shaped, 50, undefined, state.dashboardTopMode === "blocked" ? "dashboard-blocked-domains" : "dashboard-top-domains");
  }

  function componentList(components) {
    return `<div class="grid">${Object.entries(components).map(([k, v]) => `<div class="field-row"><span class="mono">${esc(k)}</span><span class="badge ${tone(v.status || (v.present === false ? "warn" : "ok"))}">${esc(v.status || (v.present === false ? "missing" : "ok"))}</span><span class="muted">${esc(v.detail || "")}</span></div>`).join("") || `<div class="empty">No component data.</div>`}</div>`;
  }

  // ``columns``, when given, is the API's own explicit named-column list
  // for a POSITIONAL row source (app/v2/analytics_query.py's
  // QueryResult) -- real defect fixed here: this previously always
  // derived column headers via Object.keys(row), which is correct for a
  // list of real objects but silently produces "0", "1", "2", ... against
  // a list of plain arrays, exactly what a positional analytics row is.
  // Named analytics rows are zipped into real objects here, once, rather
  // than asking every caller to guess the row shape.
  // ``gridId`` opts this table into the shared sortable/resizable grid
  // (data-grid.js) with a stable per-page identity so column widths and
  // sort choice persist across navigation/reload -- see docs/v2/v2-roadmap.md
  // "Data-grid requirements". Callers that render genuinely non-tabular
  // 1-row status blobs (a single TLS/node-identity object, etc.) omit it.
  // ``hideColumns`` drops raw internal-id fields from prominent table
  // presentation when a friendlier column (e.g. "name") already appears
  // in the same row -- see docs/v2/v2-roadmap.md Object Identity
  // requirements. Only pass a key here when the row still carries a
  // genuinely friendly identity elsewhere; a key with no friendlier
  // sibling (e.g. domain-routing rows, which carry an upstream_profile_id
  // with no companion upstream name in the same payload) must stay
  // visible rather than becoming unidentifiable.
  function tableFromRows(rows, limit, columns, gridId, hideColumns) {
    let list = rows.slice(0, limit || 50);
    if (columns && columns.length) {
      list = list.map((r) => Object.fromEntries(columns.map((c, i) => [c, r[i]])));
    }
    if (!list.length) return `<div class="empty">No records.</div>`;
    let cols = Object.keys(list[0]).slice(0, 8 + (hideColumns || []).length);
    if (hideColumns && hideColumns.length) cols = cols.filter((c) => !hideColumns.includes(c));
    cols = cols.slice(0, 8);
    const gridAttrs = gridId ? ` data-grid data-grid-id="${esc(gridId)}"` : "";
    return `<div class="table-wrap"><table${gridAttrs}><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${list.map((r) => `<tr>${cols.map((c) => `<td class="truncate" title="${esc(r[c])}">${pretty(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  // Owner-reported finding, priority 3 of the second beta-rescue pass: shows
  // both MANAGED clients (explicit operator-created records) and
  // ACTIVE/OBSERVED clients (real DNS activity seen via the real,
  // asynchronous discovery pipeline -- never synchronously in the DNS
  // hot path) so a fresh appliance with real traffic and zero managed
  // clients shows the truth ("a real device is querying this
  // appliance") instead of "No managed clients." Observed rows carry
  // the same one-click Manage Client action as the full Clients page
  // (wired globally in wire()'s [data-promote] handler; label renamed
  // from "Promote" -- owner-reported: not understandable operator
  // language). Only ever rendered for a row not already managed
  // (filtered below), so this can never target an already-managed
  // observed client.
  function clientMini(managed, observed) {
    if (!managed.length && !observed.length) return `<div class="empty">No managed clients, and no DNS activity observed yet.</div>`;
    const managedRows = managed.slice(0, 5).map((c) => `<tr><td><span class="badge ok">managed</span></td><td>${esc(c.name)}</td><td>${(c.identifiers || []).map((i) => `<span class="badge">${esc(i.value)}</span>`).join(" ") || '<span class="muted">none</span>'}</td><td></td></tr>`).join("");
    const observedRows = observed.slice(0, 5).filter((o) => !o.managed_client_id).map((o) => `<tr><td><span class="badge inherit">observed</span></td><td class="mono">${esc(o.hostname_candidate || o.source_ip)}</td><td class="mono">${esc(o.source_ip)}<span class="muted"> -- ${esc(o.query_count || o.observation_count || 0)} queries</span></td><td><button data-promote="${esc(o.source_ip)}">Manage Client</button></td></tr>`).join("");
    if (!managedRows && !observedRows) return `<div class="empty">No managed clients, and no DNS activity observed yet.</div>`;
    return `<div class="table-wrap"><table data-grid data-grid-id="dashboard-clients"><thead><tr><th>State</th><th>Name / hostname</th><th>Identifier</th><th data-no-sort></th></tr></thead><tbody>${managedRows}${observedRows}</tbody></table></div>`;
  }

  async function analytics() {
    const [recent, top] = await Promise.all([
      api("/api/analytics/query-log?minutes=1440&limit=100").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message, filters: {} })),
      api("/api/analytics/top-domains?minutes=1440&limit=30").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
    ]);
    return page("Query Log", "Bounded recent query and top-domain views. Degraded analytics does not imply DNS outage.", `
      <button data-refresh>Refresh</button>`, `
      ${recent.degraded ? `<div class="alert warn">Recent query log degraded: ${esc(recent.degraded_reason || "unavailable")}</div>` : ""}
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Recent Queries</h2><span class="badge">${recent.rows.length} rows</span></div><div class="panel__body">${queryFilters()}<div id="query-active">${activeFilters(recent.filters || {})}</div><div id="query-results">${tableFromRows(recent.rows || [], 100, recent.columns, "query-log-results")}</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Top Domains</h2></div><div class="panel__body">${tableFromRows(top.rows || [], 30, top.columns, "query-log-top-domains")}</div></section>
      </div>`);
  }

  // Statistics is its own destination (a real owner-reported finding: it was
  // stapled onto the bottom of Query Log). Same real /api/statistics
  // export/clear endpoints as before -- this is a page move, not new
  // backend surface.
  async function statistics() {
    return page("Statistics", "Aggregate rollup export and reset -- separate from the raw Query Log above.", "", `
      <section class="panel"><div class="panel__head"><h2>Statistics Export / Clear</h2></div><div class="panel__body">
        <p class="muted">Export covers the aggregate rollups only (fast dashboard/top-domain data), never the raw per-query history -- use Query Log's own filters to export raw query data in bulk instead. Clear can optionally also remove the raw per-query history; the result always states exactly what was cleared.</p>
        <div class="field-row">
          <a class="btn" href="/api/statistics/export">Export aggregate statistics (JSON)</a>
        </div>
        <form data-form="statistics-clear" style="margin-top:12px">
          <div class="field-row">
            <label>Type CLEAR to confirm<input name="confirmation" placeholder="CLEAR" required></label>
            <label><span>Also clear raw query history</span><select name="include_raw_history" data-bool="1"><option value="true" selected>yes</option><option value="false">no, aggregates only</option></select></label>
          </div>
          <button class="danger">Clear statistics</button>
        </form>
      </div></section>`);
  }

  function activeFilters(filters) {
    const entries = Object.entries(filters).filter(([, v]) => v !== "" && v !== null && v !== undefined && v !== false);
    if (!entries.length) return `<div class="muted">No active filters.</div>`;
    return `<div class="field-row" style="margin-bottom:10px">${entries.map(([k, v]) => `<span class="badge info">${esc(k)}=${esc(v)}</span>`).join("")}</div>`;
  }

  function queryFilters() {
    return `<form data-form="querylog" class="query-filter">
      <label>Window<select name="minutes"><option value="60">1 hour</option><option value="1440" selected>24 hours</option><option value="10080">7 days</option></select></label>
      <label>Search<input name="search" placeholder="contains text"></label>
      <label>Domain<input name="domain" placeholder="example.com"></label>
      <label>Client<input name="client" placeholder="10.0.0.42"></label>
      <label>Qtype<input name="qtype" placeholder="A"></label>
      <label>Protocol<input name="protocol" placeholder="udp"></label>
      <label>Rcode<input name="rcode" placeholder="0"></label>
      <label>Upstream<input name="upstream"></label>
      <label>Cache<select name="cache_status" data-omit-empty="1"><option value="">any</option><option>hit</option><option>miss</option><option>bypass</option></select></label>
      <label>Limit<input name="limit" value="100" data-number="1"></label>
      <label><span>Blocked only</span><select name="blocked_only" data-bool="1"><option value="false">no</option><option value="true">yes</option></select></label>
      <button>Apply filters</button>
    </form>`;
  }

  async function clients() {
    const [managed, observed, dstat, groups] = await Promise.all([
      api("/api/clients"),
      api("/api/discovery/observed-clients?limit=100"),
      api("/api/discovery/status").catch(() => ({})),
      api("/api/groups").catch(() => ({ groups: [] })),
    ]);
    return page("Clients", "Managed clients and DNS-observed addresses stay distinct until you explicitly manage one.", `<button data-refresh>Refresh</button>`, `
      <div class="strip">
        <div class="metric"><strong>${managed.clients.length}</strong><span>Managed</span></div>
        <div class="metric"><strong>${dstat.observed_count ?? (observed.items || observed.observed_clients || []).length}</strong><span>Observed</span></div>
        <div class="metric"><strong>${dstat.evictions ?? 0}</strong><span>Discovery evictions</span></div>
        <div class="metric"><strong>${dstat.dropped_observations ?? 0}</strong><span>Dropped observations</span></div>
      </div>
      <div class="split">
        <div class="grid">
          <section class="panel"><div class="panel__head"><h2>Observed Clients</h2></div><div class="panel__body">
            <p class="muted">Devices seen making real DNS queries, not yet configured. Click <strong>Manage Client</strong> to give one a name and assign it policies/settings -- this creates a managed client record; it does not change anything about the device itself.</p>
            ${observedTable(observed.items || observed.observed_clients || observed.clients || [])}
          </div></section>
          <section class="panel"><div class="panel__head"><h2>Managed Clients</h2></div><div class="panel__body">${managedTable(managed.clients)}</div></section>
        </div>
        <aside class="panel drawer"><div class="panel__head"><h2>Create Managed Client</h2></div><div class="panel__body">${clientForm(groups.groups || [])}</div></aside>
      </div>`);
  }

  // Real defect fixed here (owner-reported: "Promote" is unclear
  // operator language, and duplicate managed-client creation was
  // reachable -- the Manage Client action rendered unconditionally,
  // even for a row already carrying a managed_client_id). Renamed to
  // "Manage Client" and only rendered when the row is not already
  // managed; an already-managed row instead shows which managed client
  // it maps to (already the case via the Association column) with no
  // redundant action next to it.
  function observedTable(items) {
    if (!items.length) return `<div class="empty">No observed clients yet. Real DNS packets populate this asynchronously.</div>`;
    return `<div class="table-wrap"><table data-grid data-grid-id="observed-clients"><thead><tr><th>IP</th><th>Hostname</th><th>First / Last seen</th><th>Queries</th><th>Association</th><th data-no-sort>Actions</th></tr></thead><tbody>${items.map((o) => `
      <tr><td class="mono">${esc(o.source_ip)}</td><td>${esc(o.hostname_candidate || "")}<br><span class="muted">${esc(o.hostname_source || "")}</span></td><td>${ts(o.first_seen, "")}<br>${ts(o.last_seen, "")}</td><td>${esc(o.query_count || o.observation_count || 0)}</td><td>${o.managed_client_id ? `<span class="badge ok">client ${esc(o.managed_client_id)}</span>` : `<span class="badge inherit">unmanaged</span>`}</td><td class="field-row">${o.managed_client_id ? "" : `<button data-promote="${esc(o.source_ip)}">Manage Client</button>`}<button class="danger" data-forget="${esc(o.source_ip)}">Forget</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  // Friendly-selector/internal-ID cleanup (workstream 1C): the immutable
  // database primary key `c.id` used to be this table's first, most
  // prominent column. Name is the client's real friendly identity here --
  // the id is still used internally (e.g. the Explain button's own
  // data-explain-client) but no longer needs to be shown in a normal
  // operator table; see Object Identity requirements in
  // docs/v2/v2-roadmap.md ("Internal IDs remain internal... Advanced/
  // details views may expose immutable IDs when genuinely useful").
  function managedTable(items) {
    if (!items.length) return `<div class="empty">No managed clients.</div>`;
    return `<div class="table-wrap"><table data-grid data-grid-id="managed-clients"><thead><tr><th>Name</th><th>Identifiers</th><th>Groups</th><th>Policy</th><th data-no-sort>Actions</th></tr></thead><tbody>${items.map((c) => `
      <tr><td>${esc(c.name)}<br><span class="muted">${esc(c.description)}</span></td><td>${(c.identifiers || []).map((i) => `<span class="badge">${esc(i.kind)} ${esc(i.value)}</span>`).join(" ")}</td><td>${(c.groups || []).map((g) => `<span class="badge info">${esc(g.name)}</span>`).join(" ")}</td><td>${policySummary(c.policy)}</td><td><button data-explain-client="${c.id}">Explain</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  function clientForm(groups) {
    return `<form data-form="client">
      <label>Name<input name="name" required maxlength="128"></label>
      <label>Description<input name="description" maxlength="256"></label>
      <div class="field-row"><label>Identifier kind<select name="kind"><option>ipv4</option><option>ipv4_cidr</option><option>ipv6</option><option>ipv6_cidr</option><option>clientid</option></select></label><label>Identifier value<input name="value" placeholder="10.0.0.42"></label></div>
      <label>Group<select name="group_id" data-omit-empty="1"><option value="">None</option>${groups.map((g) => `<option value="${esc(g.group_id)}">${esc(g.name)}</option>`).join("")}</select></label>
      <button class="primary">Create client</button>
    </form>`;
  }

  async function policies() {
    const [global, networks, groups, clients] = await Promise.all([api("/api/policy/global"), api("/api/networks"), api("/api/groups"), api("/api/clients")]);
    return page("Policies / Explain", "Inheritance is explicit: empty fields inherit, booleans use inherit / enabled / disabled.", `<button data-refresh>Refresh</button>`, `
      <div class="split">
        <div class="grid">
          <section class="panel"><div class="panel__head"><h2>Global Policy</h2></div><div class="panel__body">${policyEditor("global", "singleton", global.policy)}</div></section>
          <section class="panel"><div class="panel__head"><h2>Networks</h2></div><div class="panel__body">${networkForm()}${policyObjectList("network", networks.networks, "network_id")}</div></section>
          <section class="panel"><div class="panel__head"><h2>Groups</h2></div><div class="panel__body">${groupForm()}${policyObjectList("group", groups.groups, "group_id")}</div></section>
        </div>
        <aside class="panel drawer"><div class="panel__head"><h2>Effective Policy Explain</h2></div><div class="panel__body">${explainForm(clients.clients)}</div></aside>
      </div>`);
  }

  function policySummary(p) {
    if (!p) return `<span class="badge inherit">inherit</span>`;
    const active = Object.entries(p).filter(([, v]) => v !== null && v !== undefined && v !== "");
    return active.length ? active.slice(0, 3).map(([k, v]) => `<span class="badge">${esc(k)}=${esc(v)}</span>`).join(" ") : `<span class="badge inherit">inherit</span>`;
  }

  function policyObjectList(scope, items, idKey) {
    if (!items.length) return `<div class="empty">No ${scope} policies configured.</div>`;
    return items.map((item) => `<details class="panel compact" style="margin-top:12px"><summary class="panel__head"><h2>${esc(item.name || item[idKey])}</h2><span class="badge">${esc(item[idKey])}</span></summary><div class="panel__body">${policyEditor(scope, item[idKey], item.policy || {})}</div></details>`).join("");
  }

  function policyEditor(scope, ref, policy) {
    return `<form data-form="policy" data-scope="${esc(scope)}" data-ref="${esc(ref)}">
      <div class="form-grid">${policyFields.map(([key, label, ph, options]) => {
        const current = policy[key] || "";
        if (options) {
          const opts = [`<option value="">inherit</option>`].concat(
            options.map((o) => `<option value="${esc(o)}" ${o === current ? "selected" : ""}>${esc(o)}</option>`)
          ).join("");
          return `<label>${esc(label)}<select name="${esc(key)}" data-omit-empty="1">${opts}</select></label>`;
        }
        return `<label>${esc(label)}<input name="${esc(key)}" value="${esc(current)}" placeholder="${esc(ph)}" data-omit-empty="1"></label>`;
      }).join("")}</div>
      ${triState("query_log_enabled", "Query log", policy.query_log_enabled)}
      ${triState("statistics_enabled", "Statistics", policy.statistics_enabled)}
      <button class="primary">Save policy and promote runtime</button>
    </form>`;
  }

  function triState(name, label, value) {
    const v = value === true ? "true" : value === false ? "false" : "";
    return `<label>${esc(label)}<input type="hidden" name="${esc(name)}" value="${esc(v)}" data-bool="1" data-omit-empty="1"><span class="tri" data-tri="${esc(name)}"><button type="button" data-val="" class="${v === "" ? "active" : ""}">inherit</button><button type="button" data-val="true" class="${v === "true" ? "active" : ""}">enabled</button><button type="button" data-val="false" class="${v === "false" ? "active" : ""}">disabled</button></span></label>`;
  }

  function networkForm() {
    return `<form data-form="network" class="field-row"><label>Name<input name="name" required placeholder="Office"></label><label>CIDR<input name="cidr" required placeholder="10.0.0.0/24"></label><button>Create network</button></form>`;
  }

  function groupForm() {
    return `<form data-form="group" class="field-row"><label>Name<input name="name" required placeholder="Kids"></label><label>Priority<input name="priority" value="100" data-number="1"></label><button>Create group</button></form>`;
  }

  function explainForm(clients) {
    return `<form data-form="explain">
      <label>Client<select name="client_id">${clients.map((c) => `<option value="${c.id}">${esc(c.name)}</option>`).join("")}</select></label>
      <label>Client IP<input name="client_ip" placeholder="optional"></label>
      <button class="primary">Explain effective policy</button>
      <div id="explain-result" class="alert">Select a client to inspect global, network, group, client, schedule, filtering, upstream, ECS, and cache contributions.</div>
    </form>`;
  }

  async function filtering() {
    const [services, rulesets, schedules, global] = await Promise.all([api("/api/services?include_domains=false"), api("/api/service-rulesets"), api("/api/schedules"), api("/api/policy/global")]);
    return page("Filtering / Security", "SafeSearch, parental filtering, security filtering, service blocking, schedules, and response modes remain separate controls.", "", `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Global Answer Policy</h2></div><div class="panel__body">${policyEditor("global", "singleton", global.policy)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Service Catalog</h2></div><div class="panel__body">${serviceForm()}${serviceTable(services.services)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Service Rulesets</h2></div><div class="panel__body">${rulesetForm(services.services)}${tableFromRows(rulesets.rulesets, 20, undefined, "filtering-rulesets")}</div></section>
        <section class="panel"><div class="panel__head"><h2>Schedules</h2></div><div class="panel__body">${scheduleForm()}${tableFromRows(schedules.schedules, 20, undefined, "filtering-schedules")}</div></section>
      </div>`);
  }

  function serviceForm() {
    return `<form data-form="service"><div class="form-grid"><label>Display name<input name="display_name" required placeholder="TikTok"></label><label>Category<input name="category"></label><label>Domain<input name="domain" placeholder="example.com"></label><label>Match<select name="match_kind"><option>suffix</option><option>exact</option></select></label></div><button>Create service</button></form>`;
  }

  function serviceTable(services) {
    if (!services.length) return `<div class="empty">No service definitions.</div>`;
    const rows = services.slice(0, 100).map((s) => {
      const sample = (s.sample_domains || s.domains || []).slice(0, 3).map((d) => `${d.match_kind}:${d.domain}`).join(", ");
      return `<tr><td>${esc(s.display_name)}</td><td>${esc(s.category || "")}</td><td class="mono">${esc(s.service_id)}</td><td>${esc(s.domain_count ?? (s.domains || []).length)}</td><td class="truncate" title="${esc(sample)}">${esc(sample || "-")}</td></tr>`;
    }).join("");
    const overflow = services.length > 100 ? `<p class="muted">${esc(services.length - 100)} additional services hidden from this compact view.</p>` : "";
    return `<div style="margin-top:12px"><div class="table-wrap"><table data-grid data-grid-id="filtering-services"><thead><tr><th>Name</th><th>Category</th><th>ID</th><th>Domains</th><th>Examples</th></tr></thead><tbody>${rows}</tbody></table></div>${overflow}</div>`;
  }

  function rulesetForm(services) {
    return `<form data-form="ruleset"><label>Name<input name="name" required placeholder="Social media"></label><label>Services<select name="service_ids" multiple size="6">${services.map((s) => `<option value="${esc(s.service_id)}">${esc(s.display_name)}</option>`).join("")}</select></label><button>Create ruleset</button></form>`;
  }

  function scheduleForm() {
    return `<form data-form="schedule"><div class="form-grid"><label>Name<input name="name" required placeholder="School hours"></label><label>Timezone<input name="timezone" value="UTC"></label><label>Start<input name="start" value="08:00"></label><label>End<input name="end" value="17:00"></label><label>Weekdays<input name="weekdays" value="0,1,2,3,4"></label></div><button>Create schedule</button></form>`;
  }

  async function upstreams() {
    const [ups, routes] = await Promise.all([api("/api/upstreams"), api("/api/domain-routing")]);
    return page("Upstreams / Routing", "Plain, DoT, and DoH profiles with explicit routing rules. DoH requires TLS hostname validation.", "", `
      ${ups.native_recursion_active ? `<div class="alert info">No managed upstream is enabled. BIND is performing normal native recursive resolution using the root/authoritative hierarchy -- not a substituted third-party resolver.</div>` : ""}
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Upstream Profiles</h2></div><div class="panel__body">
          <p class="muted">Order is the operator-visible priority list for profile management. Runtime DNS uses the upstream profile selected by global/client policy or a matching domain route; endpoint order inside that selected profile controls ordered/failover behavior.</p>
          ${upstreamForm()}<div id="upstreams-table-host">${upstreamsTable(ups.upstreams)}</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Domain Routes</h2></div><div class="panel__body">${routeForm(ups.upstreams)}${tableFromRows(routes.routes, 50, undefined, "upstream-domain-routes")}</div></section>
      </div>`);
  }

  function upstreamForm() {
    return `<form data-form="upstream"><div class="form-grid"><label>Name<input name="name" required placeholder="Cloudflare"></label><label>Transport<select name="transport"><option>plain</option><option>dot</option><option>doh</option></select></label><label>Strategy<select name="strategy"><option>ordered</option><option>failover</option><option>load_balanced</option></select></label><label>Address<input name="address" required placeholder="1.1.1.1:53"></label><label>TLS hostname<input name="tls_hostname" placeholder="cloudflare-dns.com"></label><label>DoH path<input name="doh_path" placeholder="/dns-query"></label></div><button data-upstream-submit class="primary">Create upstream</button><button type="button" data-upstream-cancel-edit hidden>Cancel edit</button></form>`;
  }

  // Real owner-reported live defect fixed here: managed upstreams --
  // both default-seeded and operator-added -- could not be edited,
  // disabled, or removed at all; only Create + List ever existed. Real
  // lifecycle control per row, in one compact accessible overflow menu
  // (owner-reported: rows must not be "a pile of buttons") that opens
  // on click/keyboard/touch alike -- never hover-only -- see
  // wire()'s [data-row-menu-toggle] handler.
  function upstreamsTable(items) {
    if (!items.length) return `<div class="empty">No upstream profiles configured. BIND performs normal native recursive resolution until one is added and enabled.</div>`;
    const rows = items.map((u, i) => {
      const endpoints = u.endpoints || [];
      const addr = endpoints.map((e) => e.address).join(", ") || "-";
      const endpointMarkup = endpoints.length
        ? `<div class="endpoint-list">${endpoints.map((e) => `<code class="endpoint-chip">${esc(e.address)}</code>`).join("")}</div>`
        : `<span class="muted">-</span>`;
      return `<tr data-upstream-row="${esc(u.upstream_profile_id)}">
        <td>${esc(u.name)}<br><span class="muted mono">${esc(u.upstream_profile_id)}</span></td>
        <td class="mono"><span class="badge info">#${esc(u.order || i + 1)}</span></td>
        <td class="mono">${esc(u.transport)}</td>
        <td class="mono endpoint-cell" title="${esc(addr)}">${endpointMarkup}</td>
        <td>${esc(u.strategy)}</td>
        <td>${u.enabled ? '<span class="badge ok">enabled</span>' : '<span class="badge warn">disabled</span>'}</td>
        <td class="field-row" data-no-sort>
          <button class="icon-btn" data-reorder-upstream="up" data-upstream-id="${esc(u.upstream_profile_id)}" title="Move up" ${i === 0 ? "disabled" : ""} aria-label="Move ${esc(u.name)} up in order">&uarr;</button>
          <button class="icon-btn" data-reorder-upstream="down" data-upstream-id="${esc(u.upstream_profile_id)}" title="Move down" ${i === items.length - 1 ? "disabled" : ""} aria-label="Move ${esc(u.name)} down in order">&darr;</button>
          <div class="row-actions">
            <button type="button" class="row-actions__trigger" data-row-menu-toggle aria-haspopup="true" aria-expanded="false" aria-label="Actions for ${esc(u.name)}">&ctdot;</button>
            <div class="row-actions__menu" hidden role="menu">
              <button type="button" role="menuitem" data-edit-upstream="${esc(u.upstream_profile_id)}">Edit</button>
              <button type="button" role="menuitem" data-toggle-upstream="${esc(u.upstream_profile_id)}" data-currently-enabled="${u.enabled ? "1" : "0"}">${u.enabled ? "Disable" : "Enable"}</button>
              <button type="button" role="menuitem" class="danger" data-delete-upstream="${esc(u.upstream_profile_id)}">Delete</button>
            </div>
          </div>
        </td>
      </tr>`;
    }).join("");
    return `<div class="table-wrap"><table data-grid data-grid-id="upstream-profiles" data-grid-default-sort-column="1" data-grid-default-sort-direction="asc" data-grid-ignore-stored-sort="1"><thead><tr><th>Name</th><th>Display Order</th><th>Transport</th><th>Addresses</th><th>Strategy</th><th>Status</th><th data-no-sort>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }

  function routeForm(upstreams) {
    // "Routing group" (not "Ruleset ID"): a free-text label the operator
    // chooses and reuses across several route rules to group them --
    // genuinely operator-authored, unlike the synthetic ids removed
    // elsewhere on this pass, so it stays free text rather than being
    // generated from another field.
    return `<form data-form="route"><label>Routing group<input name="rule_id" required placeholder="corp-split"></label><label>Domain suffix<input name="suffix_domain" required placeholder="corp.example"></label><label>Upstream<select name="upstream_profile_id">${upstreams.map((u) => `<option value="${esc(u.upstream_profile_id)}">${esc(u.name)}</option>`).join("")}</select></label><button>Create route and promote runtime</button></form>`;
  }

  async function localdns() {
    const records = await api("/api/local-dns");
    return page("Local DNS", "Bounded Local DNS records with backend validation and runtime promotion.", "", `
      <div class="split"><section class="panel"><div class="panel__head"><h2>Records</h2></div><div class="panel__body">${tableFromRows(records.records, 200, undefined, "local-dns-records", ["id"])}</div></section><aside class="panel drawer"><div class="panel__head"><h2>Add Record</h2></div><div class="panel__body">${localDnsForm()}</div></aside></div>`);
  }

  function localDnsForm() {
    return `<form data-form="localdns"><label>Name<input name="name" required placeholder="printer.lan"></label><label>Type<select name="record_type"><option>A</option><option>AAAA</option><option>CNAME</option><option>PTR</option></select></label><label>Value<input name="value" required placeholder="10.0.0.10"></label><label>TTL<input name="ttl" value="300" data-number="1"></label><button class="primary">Add and promote runtime</button></form>`;
  }

  async function replication() {
    const [node, health, peers] = await Promise.all([api("/api/node-identity"), api("/api/replication/health"), api("/api/replication/peers")]);
    return page("Replication", "Node identity, explicit peer authorization, trust material, and synchronization status.", "", `
      <div class="strip"><div class="metric"><strong class="mono">${esc(node.node_id).slice(0, 8)}</strong><span>Node identity</span></div><div class="metric"><strong>${esc(health.protocol_version)}</strong><span>Protocol</span></div><div class="metric"><strong>${peers.peers.length}</strong><span>Peers</span></div></div>
      <div class="grid two"><section class="panel"><div class="panel__head"><h2>Peers</h2></div><div class="panel__body">${peerTable(peers.peers)}</div></section><section class="panel"><div class="panel__head"><h2>Add / Update Peer</h2></div><div class="panel__body">${peerForm()}</div></section></div>`);
  }

  function peerTable(peers) {
    if (!peers.length) return `<div class="empty">No peers configured.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>Peer</th><th>URL</th><th>Auth</th><th>Sync</th><th>Error</th><th>Actions</th></tr></thead><tbody>${peers.map((p) => `<tr><td class="mono">${esc(p.peer_node_id)}</td><td>${esc(p.url)}</td><td><span class="badge ${p.authorized ? "ok" : "bad"}">${p.authorized ? "authorized" : "disabled"}</span></td><td>last success ${ts(p.last_success_at, "never")}<br>lag ${esc(p.lag ?? "")}</td><td>${esc(p.last_error || "")}</td><td><button data-sync="${esc(p.peer_node_id)}">Sync</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  function peerForm() {
    return `<form data-form="peer"><label>Peer's node identity<input name="peer_node_id" required placeholder="from the peer's own Node Identity panel"></label><label>Display name<input name="display_name" placeholder="Backup site"></label><label>URL<input name="url" required placeholder="https://10.0.0.2:9443/replication/v1/apply"></label><label>Expected cert SHA-256<input name="expected_cert_sha256" required minlength="64" maxlength="64"></label><label>Trusted CA PEM<textarea name="ca_pem" required></textarea></label><label>Client certificate PEM<textarea name="client_cert_pem"></textarea></label><label>Client key PEM<textarea name="client_key_pem"></textarea></label><label>Direction<select name="direction"><option>bidirectional</option><option>push</option><option>pull</option></select></label><button class="primary">Save peer</button></form>`;
  }

  async function backup() {
    const [applianceBackups, backups] = await Promise.all([
      api("/api/backup/appliance").catch((e) => ({ backups: [], restore_jobs: [], error: e.message })),
      api("/api/backup/secrets").catch((e) => ({ backups: [], restore_jobs: [], error: e.message })),
    ]);
    return page("Backup / Restore / Migration", "Safe entry points for backup and migration preview. Opening this page does not start destructive work.", "", `
      <section class="panel"><div class="panel__head"><h2>Appliance Backup / Restore</h2></div><div class="panel__body">
        <p class="muted">A full encrypted snapshot: control database (clients, groups, networks, policies, filtering, Local DNS, upstream profiles, domain routing, schedules, DNS-transport/encryption settings, notifications, replication identity/peers), protected secrets, and the active HTTPS/DNSCrypt certificates. Raw query history is never included -- control.db cannot hold it. Restore is staged and validated before anything live changes, and the prior appliance state is snapshotted first so a failed restore leaves it untouched.</p>
        <button data-appliance-backup class="primary">Create local appliance backup</button>
        <form data-form="appliance-backup" class="field-row">
          <label>Portable passphrase <input name="passphrase" type="password" autocomplete="new-password" data-omit-empty="1" placeholder="required for cross-appliance restore"></label>
          <button>Create portable appliance backup</button>
        </form>
        <form data-form="appliance-upload" class="backup-upload" data-drop-upload>
          <label class="dropzone">Upload and preview native backup
            <input type="file" name="file" accept=".apdnsbak,.tar.gz">
          </label>
          <label>Restore passphrase <input name="passphrase" type="password" autocomplete="current-password" data-omit-empty="1" placeholder="if backup is portable"></label>
          <button>Upload and preview</button>
          <div class="muted" data-upload-hint>Choose a native backup file or drop it here.</div>
        </form>
        ${applianceBackupTable(applianceBackups.backups || [])}
        ${uploadedArchiveSection(applianceBackups)}
        ${safetyBackupTable(applianceBackups.safety_backups || [])}
        ${restoreJobs(applianceBackups.restore_jobs || [])}
      </div></section>
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Secret Backup / Restore</h2></div><div class="panel__body"><p class="muted">One component of the appliance backup above, also available standalone: encrypted protected secrets only. Secret values are never displayed.</p><button data-backup class="primary">Create secret-only backup</button>${backupTable(backups.backups || [])}${restoreJobs(backups.restore_jobs || [])}</div></section>
        <section class="panel"><div class="panel__head"><h2>Migration Detection</h2></div><div class="panel__body"><p class="muted">Run detection only when you have a source path to inspect.</p><form data-form="migration"><label>Source path<input name="source_path" value="/var/lib/alderpointdns/alderpointdns.db"></label><button>Detect source</button></form><div id="migration-result"></div></div></section>
      </div>`);
  }

  function applianceBackupTable(backups) {
    const body = backups.length ? `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th><th>Restore</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${ts(b.created_at)}</td><td>${esc(b.size_bytes)}</td><td><button data-validate-appliance-backup="${esc(b.name)}">Preview</button><input name="passphrase" type="password" data-omit-empty="1" placeholder="passphrase if required"></td></tr><tr id="preview-${esc(b.name).replace(/[^A-Za-z0-9_-]/g, "-")}" class="restore-preview-row" hidden><td colspan="4"></td></tr>`).join("")}</tbody></table></div>` : `<div class="empty">No appliance-created backups.</div>`;
    return `<section class="subpanel"><h3>Appliance-created Backups</h3>${body}</section>`;
  }

  function uploadedArchiveSection(data) {
    const archives = data.uploaded_archives || [];
    const settings = data.uploaded_archive_settings || {};
    const cleanup = data.cleanup || {};
    const rows = archives.map((a) => `<tr>
      <td class="truncate" title="${esc(a.original_filename)}">${esc(a.original_filename)}<br><span class="muted mono" title="${esc(a.name)}">${esc(a.name)}</span></td>
      <td>${esc(backupFormatLabel(a.detected_format, a.source_version))}</td>
      <td>${ts(a.uploaded_at)}</td>
      <td title="${esc(a.size_bytes)} bytes">${esc(bytes(a.size_bytes))}</td>
      <td><span class="badge ${a.validation_status === "valid" ? "ok" : "bad"}">${esc(a.validation_status)}</span></td>
      <td>${esc(a.restore_status)}</td>
      <td class="compact-actions">${a.requires_passphrase ? `<input name="passphrase" type="password" data-omit-empty="1" placeholder="passphrase" aria-label="Restore passphrase for ${esc(a.original_filename)}">` : ""}<button class="compact" data-validate-appliance-backup="${esc(a.name)}">Preview</button><button class="compact danger" data-delete-uploaded-archive="${esc(a.archive_id)}" data-filename="${esc(a.original_filename)}" data-size="${esc(a.size_bytes)}">Delete</button></td>
    </tr><tr id="preview-${esc(a.name).replace(/[^A-Za-z0-9_-]/g, "-")}" class="restore-preview-row" hidden><td colspan="7"></td></tr>`).join("");
    const failures = (cleanup.failures || []).length ? `<div class="alert error">${esc(cleanup.failures.join("; "))}</div>` : "";
    return `<section class="subpanel"><h3>Uploaded Restore Archives</h3>
      <div class="summary-metrics">
        <div class="summary-metric"><span class="summary-metric__label">Total uploaded storage</span><strong class="summary-metric__value" title="${esc(data.uploaded_storage_bytes || 0)} bytes">${esc(bytes(data.uploaded_storage_bytes || 0))}</strong></div>
        <div class="summary-metric"><span class="summary-metric__label">Retention</span><strong class="summary-metric__value">${esc((settings.retention_label || "").replace("hour(s)", "hours"))}</strong></div>
        <div class="summary-metric"><span class="summary-metric__label">Last cleanup</span><strong class="summary-metric__value">${esc(cleanup.removed || 0)} removed</strong></div>
      </div>
      ${failures}
      <form data-form="uploaded-archive-settings" class="field-row">
        <label>Retention <select name="retention_seconds"><option value="86400" ${settings.retention_seconds === 86400 ? "selected" : ""}>24 hours</option><option value="3600" ${settings.retention_seconds === 3600 ? "selected" : ""}>1 hour</option><option value="21600" ${settings.retention_seconds === 21600 ? "selected" : ""}>6 hours</option><option value="604800" ${settings.retention_seconds === 604800 ? "selected" : ""}>7 days</option><option value="0" ${settings.retention_seconds === 0 ? "selected" : ""}>Manual Only</option></select></label>
        <label class="row"><input type="checkbox" name="remove_after_successful_restore" value="true" data-bool="1" ${settings.remove_after_successful_restore ? "checked" : ""}> Remove uploaded archive after successful restore</label>
        <button class="compact">Save</button>
      </form>
      ${archives.length ? `<div class="table-wrap" style="margin-top:12px"><table data-grid data-grid-id="uploaded-restore-archives"><thead><tr><th>Original filename</th><th>Format / Version</th><th>Uploaded</th><th>Size</th><th>Validation</th><th>Restore status</th><th data-no-sort>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No uploaded restore archives.</div>`}
    </section>`;
  }

  function safetyBackupTable(backups) {
    if (!backups.length) return "";
    return `<section class="subpanel"><h3>Pre-restore Safety Backups</h3><div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${ts(b.created_at)}</td><td>${esc(b.size_bytes)}</td></tr>`).join("")}</tbody></table></div></section>`;
  }

  function backupPreviewId(name) {
    return `preview-${String(name).replace(/[^A-Za-z0-9_-]/g, "-")}`;
  }

  function restorePreview(res) {
    const inv = res.inventory;
    if (!inv) return `<div class="alert error">The backup is valid, but no structured inventory was returned. Restore is blocked until preview can be generated.</div>`;
    const meta = inv.metadata || {};
    const cats = inv.categories || [];
    const categoryRows = cats.map((c) => {
      const disabled = !c.supported ? "disabled" : "";
      const checked = c.selected_by_default ? "checked" : "";
      const samples = (c.samples || []).slice(0, 5).map((s) => `<li>${esc(s)}</li>`).join("");
      const detail = c.unsupported_reason || c.warning || c.transform || "";
      return `<tr>
        <td><label class="row"><input type="checkbox" name="selected_categories" value="${esc(c.id)}" ${checked} ${disabled}> ${esc(c.label)}${c.sensitive ? ' <span class="badge warn">sensitive</span>' : ""}</label></td>
        <td>${esc(c.found_count)}</td><td>${esc(c.restorable_count)}</td><td>${esc(c.skipped_count)}</td><td>${esc(c.conflict_count)}</td>
        <td>${c.supported ? '<span class="badge ok">supported</span>' : '<span class="badge bad">unsupported</span>'}<br><span class="muted">${esc(detail)}</span>${samples ? `<details><summary>Items</summary><ul>${samples}</ul></details>` : ""}</td>
      </tr>`;
    }).join("");
    return `<section class="panel stack restore-preview">
      <div class="panel__head"><h2>Restore Preview</h2><span class="badge ok">valid</span></div>
      <div class="grid compact">
        <div><strong>Original filename</strong><br><span class="mono">${esc(meta.original_filename)}</span></div>
        <div><strong>Detected format</strong><br>${esc(meta.detected_format)}</div>
        <div><strong>Source version</strong><br>${esc(meta.source_alderpoint_version)}</div>
        <div><strong>Created</strong><br>${ts(meta.created_at)}</div>
        <div><strong>Archive size</strong><br>${esc(meta.archive_size_bytes)} bytes</div>
        <div><strong>Encryption</strong><br>${meta.encrypted ? esc(meta.key_mode) : "not encrypted"}</div>
      </div>
      <form data-form="appliance-restore" data-backup-name="${esc(res.backup_name)}" class="stack">
        <input type="hidden" name="archive_digest" value="${esc(inv.archive_digest)}">
        <input type="hidden" name="confirmation" value="${esc(res.backup_name)}">
        <div class="field-row">
          <button type="button" data-select-restore="recommended">Recommended Selection</button>
          <button type="button" data-select-restore="all">Select All Supported</button>
          <button type="button" data-select-restore="none">Select None</button>
          <label>Conflict policy <select name="conflict_policy"><option value="merge">Merge / skip duplicates</option><option value="replace">Replace selected category</option></select></label>
          <label><input type="checkbox" name="acknowledge_sensitive" value="true" data-bool="1"> I understand selected sensitive categories can affect access or identity</label>
        </div>
        <div class="table-wrap"><table><thead><tr><th>Category</th><th>Found</th><th>Restorable</th><th>Skipped</th><th>Conflicts</th><th>Details</th></tr></thead><tbody>${categoryRows}</tbody></table></div>
        <label>Final confirmation <input name="confirmation" value="${esc(res.backup_name)}" required></label>
        <button class="danger">Restore selected categories</button>
      </form>
    </section>`;
  }

  function backupTable(backups) {
    if (!backups.length) return `<div class="empty">No encrypted secret backups.</div>`;
    return `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th><th>Restore</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${ts(b.created_at)}</td><td>${esc(b.size_bytes)}</td><td><button data-validate-backup="${esc(b.name)}">Validate</button><form data-form="restore" data-backup-name="${esc(b.name)}" class="field-row"><input name="confirmation" placeholder="type exact file name"><select name="overwrite" data-bool="1"><option value="false">no overwrite</option><option value="true">overwrite</option></select><button class="danger">Restore</button></form></td></tr>`).join("")}</tbody></table></div>`;
  }

  function restoreJobs(jobs) {
    if (!jobs.length) return `<div class="muted" style="margin-top:12px">No restore jobs recorded.</div>`;
    return `<div style="margin-top:12px"><h3>Restore Status</h3>${tableFromRows(jobs, 20)}</div>`;
  }

  // Encryption and Notifications are now two separate destinations
  // (a real owner-reported finding, priority 1 of the second beta-rescue pass: they
  // were mixed into one "HTTPS / Notifications" page -- unrelated
  // concepts, exactly the "concept soup" callout). Matches V1.1.1's own
  // separate encryption.html / notifications.html templates.
  async function encryption() {
    const [tls, transports] = await Promise.all([api("/api/tls/status"), api("/api/dns-transports")]);
    return page("Encryption", "HTTPS management certificate and encrypted DNS transports (DoT/DoH/DoQ/DoH3). Certificate replacement uses stage, validate, promote.", "", `
      <section class="panel"><div class="panel__head"><h2>HTTPS Certificate</h2><span class="badge ${tls.is_self_signed ? "warn" : "ok"}">${tls.active ? (tls.is_self_signed ? "self-signed" : "active") : "missing"}</span></div><div class="panel__body">${tableFromRows([tls], 1)}${tlsForm()}</div></section>
      <section class="panel"><div class="panel__head"><h2>Encrypted DNS Transports</h2></div><div class="panel__body">
        ${dnsTransportForm(transports)}
        <div style="margin-top:12px"><p class="muted">Apple enrollment profiles (.mobileconfig) for whichever transport below is enabled, using the active HTTPS certificate's own hostname -- never advertised for a disabled transport.</p>
          <div class="field-row">
            <a class="btn ${transports.doh_enabled ? "" : "muted"}" href="/api/dns-transports/mobileconfig/doh">Download DoH profile</a>
            <a class="btn ${transports.dot_enabled ? "" : "muted"}" href="/api/dns-transports/mobileconfig/dot">Download DoT profile</a>
          </div>
        </div>
      </div></section>`);
  }

  async function notifications() {
    const data = await api("/api/notifications");
    return page("Notifications", "Provider secrets are write-only and redacted once saved.", "", `
      <section class="panel"><div class="panel__head"><h2>Providers</h2></div><div class="panel__body">${tableFromRows(data.providers || [], 50, undefined, "notification-providers")}${notificationForm()}</div></section>`);
  }

  function dnsTransportForm(t) {
    return `<form data-form="dns-transports"><div class="form-grid">
      <label><span>DoT</span><select name="dot_enabled" data-bool="1"><option value="true" ${t.dot_enabled ? "selected" : ""}>enabled</option><option value="false" ${!t.dot_enabled ? "selected" : ""}>disabled</option></select></label>
      <label>DoT port<input name="dot_port" value="${esc(t.dot_port)}" data-number="1"></label>
      <label><span>DoH</span><select name="doh_enabled" data-bool="1"><option value="true" ${t.doh_enabled ? "selected" : ""}>enabled</option><option value="false" ${!t.doh_enabled ? "selected" : ""}>disabled</option></select></label>
      <label>DoH port<input name="doh_port" value="${esc(t.doh_port)}" data-number="1"></label>
      <label>DoH path<input name="doh_path" value="${esc(t.doh_path)}"></label>
      <label><span>DoQ</span><select name="doq_enabled" data-bool="1"><option value="true" ${t.doq_enabled ? "selected" : ""}>enabled</option><option value="false" ${!t.doq_enabled ? "selected" : ""}>disabled</option></select></label>
      <label>DoQ port<input name="doq_port" value="${esc(t.doq_port)}" data-number="1"></label>
      <label><span>DoH3</span><select name="doh3_enabled" data-bool="1"><option value="true" ${t.doh3_enabled ? "selected" : ""}>enabled</option><option value="false" ${!t.doh3_enabled ? "selected" : ""}>disabled</option></select></label>
      <label>DoH3 port<input name="doh3_port" value="${esc(t.doh3_port)}" data-number="1"></label>
      <input type="hidden" name="dnscrypt_enabled" value="${t.dnscrypt_enabled ? "true" : "false"}" data-bool="1">
      <input type="hidden" name="dnscrypt_port" value="${esc(t.dnscrypt_port)}" data-number="1">
    </div><button class="primary">Save and promote runtime</button></form>`;
  }

  function tlsForm() {
    return `<form data-form="tls"><label>Certificate PEM<textarea name="certificate_pem" required></textarea></label><label>Private key PEM<textarea name="private_key_pem" required></textarea></label><button class="primary">Validate and promote certificate</button></form>`;
  }

  function notificationForm() {
    return `<form data-form="notification"><div class="form-grid"><label>Display name<input name="display_name" required placeholder="Ops Slack"></label><label>Kind<select name="kind"><option value="webhook">webhook</option><option value="email_smtp">email_smtp</option><option value="pushover">pushover</option><option value="slack">slack</option></select></label><label>Endpoint<input name="endpoint" required></label></div><label>Secret value<input name="secret_value" type="password" autocomplete="new-password"></label><button>Create provider</button></form>`;
  }

  // Administration and Logs are now their own destinations (a real
  // owner-reported finding, priority 1 of the second beta-rescue pass: Administration
  // was buried inside System Status, which is really about DNS/runtime
  // component health -- an unrelated concern from changing your own
  // password). Matches V1.1.1's own separate administration.html /
  // system_logs_results.html templates.
  async function health() {
    const [h, s, n, d] = await Promise.all([api("/api/health"), api("/api/system/status"), api("/api/node-identity"), api("/api/discovery/status")]);
    return page("System Status", "Operational status separates DNS/runtime health from optional subsystem degradation.", `<button data-copy-perf>Copy UI Performance Report</button><button data-clear-perf>Clear Measurements</button><button data-refresh>Refresh</button>`, `
      <div class="strip"><div class="metric"><strong>${esc(h.status)}</strong><span>Overall</span></div><div class="metric"><strong>${esc(s.version)}</strong><span>Version</span></div><div class="metric"><strong>${s.compiled_runtime_present ? "yes" : "no"}</strong><span>Compiled runtime</span></div><div class="metric"><strong>${esc(d.observed_count ?? 0)}</strong><span>Observed clients</span></div></div>
      <section class="panel"><div class="panel__head"><h2>UI Performance</h2></div><div class="panel__body"><p class="muted">Recent in-browser route and API timings are kept only in this browser session. Copy the report after reproducing slow navigation.</p>${performanceSummaryTable()}</div></section>
      <div class="grid two"><section class="panel"><div class="panel__head"><h2>Components</h2></div><div class="panel__body">${componentList(h.components || {})}</div></section><section class="panel"><div class="panel__head"><h2>Node Identity</h2></div><div class="panel__body">${tableFromRows([n], 1)}</div></section></div>`);
  }

  function performanceSummaryTable() {
    const routes = state.perfHistory.filter((e) => e.type === "route").slice(0, 12);
    if (!routes.length) return `<div class="empty">No route measurements yet.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>Route</th><th>Navigation ID</th><th>When</th><th>Shell</th><th>Useful</th><th>Total</th><th>Cache</th><th>Slowest API</th></tr></thead><tbody>${routes.map((r) => `<tr><td>${esc(r.route)}</td><td class="mono">${esc(r.navigation_id || "")}</td><td>${esc(r.timestamp)}</td><td>${esc(r.shell_paint_ms)} ms</td><td>${esc(r.first_useful_ms)} ms</td><td>${esc(r.total_ms)} ms</td><td>${esc(r.cache_status)}</td><td>${esc(r.slowest_api || "")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  async function administration() {
    await ensureApplianceTimezone();
    return page("Administration", "Your own account, session, and interface preferences.", "", `
      <section class="panel"><div class="panel__head"><h2>Account</h2></div><div class="panel__body"><div class="grid two">
        <form data-form="change-password"><label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label><label>New password (min. 12 characters)<input name="new_password" type="password" autocomplete="new-password" minlength="12" required></label><button class="primary">Change password</button></form>
        <div><p class="muted">Signs out every other active session for your account (not this one). Use after a shared/compromised session.</p><button data-revoke-sessions class="danger">Revoke other sessions</button></div>
      </div></div></section>
      <section class="panel"><div class="panel__head"><h2>Preferences</h2></div><div class="panel__body">
        <label class="row"><input type="checkbox" data-action="nav-keep-multiple-open" ${navKeepMultipleOpen() ? "checked" : ""}> Keep multiple navigation sections open</label>
        <p class="muted">Off by default: opening a main navigation section closes whichever other one was open. Turn this on to expand and collapse each section independently instead. Saved on this device/browser.</p>
        <label style="margin-top:16px">Timestamp display${timezonePreferenceSelector()}</label>
        <p class="muted">Every timestamp shown anywhere in the app updates immediately when you change this -- no reload. Storage, the API, sorting, and filtering always use the exact UTC value regardless of this display choice.</p>
      </div></section>`);
  }

  // Real defect fixed here (owner-reported: raw UTC ISO strings were
  // the default presentation everywhere, and later, that the display
  // mode must never hardcode a geographic timezone). Three modes, each
  // labeled with the REAL zone it will use -- never a static label --
  // so the operator can see exactly what "Browser Local" and
  // "Appliance Time" actually mean on this box, right now.
  function timezonePreferenceSelector() {
    const mode = timestampDisplayMode();
    const browserTz = browserTimezone();
    const applianceTz = applianceTimezone();
    const browserLabel = browserTz ? `Browser Local — ${browserTz}` : "Browser Local (undetected)";
    const applianceLabel = applianceTz ? `Appliance Time — ${applianceTz}` : "Appliance Time (unavailable)";
    return `<select data-action="timestamp-display-mode" aria-label="Timestamp display timezone">
      <option value="browser" ${mode === "browser" ? "selected" : ""}>${esc(browserLabel)}</option>
      <option value="appliance" ${mode === "appliance" ? "selected" : ""}>${esc(applianceLabel)}</option>
      <option value="utc" ${mode === "utc" ? "selected" : ""}>UTC</option>
    </select>`;
  }

  async function logs() {
    return page("Logs", "Service logs, on demand and bounded.", "", `
      <section class="panel"><div class="panel__head"><h2>Service Logs</h2></div><div class="panel__body">
        <form data-form="logs-view" class="query-filter">
          <label>Service<select name="unit">${LOG_UNITS.map((u) => `<option value="${esc(u)}">${esc(u)}</option>`).join("")}</select></label>
          <label>Severity<select name="severity"><option value="all">all</option><option value="error">error</option><option value="warning">warning</option><option value="info">info</option><option value="debug">debug</option></select></label>
          <label>Lines<input name="lines" value="100" data-number="1"></label>
          <button>View</button>
        </form>
        <div id="log-results" class="empty">Choose a service and click View.</div>
      </div></section>`);
  }

  const LOG_UNITS = [
    "alderpointdns-v2-web", "alderpointdns-v2-dnsdist", "alderpointdns-v2-bind@ctx0",
    "alderpointdns-v2-analytics", "alderpointdns-v2-discovery", "alderpointdns-v2-replication",
    "alderpointdns-v2-tierb", "alderpointdns-v2-schedule",
  ];

  function logEntriesTable(entries) {
    if (!entries.length) return `<div class="empty">No log entries for this window.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>Time</th><th>Severity</th><th>Message</th></tr></thead><tbody>${entries.map((e) => `<tr><td class="mono">${esc(e.ts)}</td><td><span class="badge ${e.severity === "error" || e.severity === "crit" || e.severity === "alert" || e.severity === "emerg" ? "bad" : e.severity === "warning" ? "warn" : "info"}">${esc(e.severity)}</span></td><td class="mono">${esc(e.message)}</td></tr>`).join("")}</tbody></table></div>`;
  }

  async function blocklists() {
    const data = await api("/api/blocklists");
    const presets = (data.settings && data.settings.interval_presets) || [];
    const rows = (data.subscriptions || []).map((s) => `
      <tr>
        <td>${esc(s.name)}<br><span class="muted mono">${esc(s.subscription_id)}</span></td>
        <td class="truncate" title="${esc(s.url)}">${esc(s.url)}</td>
        <td><span class="badge ${s.enabled ? "ok" : "inherit"}">${s.enabled ? "enabled" : "disabled"}</span></td>
        <td>${esc(s.rule_count)}</td>
        <td>${ts(s.last_success_at || s.last_refresh_at, "never")}</td>
        <td>${s.effective_interval_seconds ? ts(s.next_retry_at || s.next_update_at, "not scheduled") : "Manual Only"}</td>
        <td>${esc(s.effective_interval_label || "")}</td>
        <td><span class="badge ${s.update_in_progress ? "warn" : tone(s.last_status)}">${s.update_in_progress ? "updating" : esc(s.last_status)}</span>${s.last_error ? `<br><span class="muted">${esc(s.last_error)}</span>` : ""}${s.update_duration_ms ? `<br><span class="muted">${esc(s.update_duration_ms)} ms</span>` : ""}</td>
        <td class="actions-cell" data-no-sort>
          <div class="row-actions">
            <button type="button" class="row-actions__trigger" data-row-menu-toggle aria-haspopup="true" aria-expanded="false" aria-label="More actions for ${esc(s.name)}">&ctdot;</button>
            <div class="row-actions__menu" hidden role="menu" aria-label="Actions for ${esc(s.name)}">
              <button type="button" role="menuitem" data-blocklist-edit="${esc(s.subscription_id)}" ${s.update_in_progress ? "disabled" : ""}>Edit Update Interval</button>
              <button type="button" role="menuitem" data-blocklist-refresh="${esc(s.subscription_id)}" ${s.update_in_progress ? "disabled" : ""}>Update Now</button>
              <button type="button" role="menuitem" data-blocklist-toggle="${esc(s.subscription_id)}" ${s.update_in_progress ? "disabled" : ""}>${s.enabled ? "Disable" : "Enable"}</button>
              <div class="overflow-menu__divider" role="separator"></div>
              <button type="button" role="menuitem" data-blocklist-delete="${esc(s.subscription_id)}" class="danger" ${s.update_in_progress ? "disabled" : ""}>Delete</button>
            </div>
          </div>
        </td>
      </tr>
      <tr class="row-edit" id="blocklist-interval-${esc(s.subscription_id).replace(/[^A-Za-z0-9_-]/g, "-")}" hidden><td colspan="9">
        <form data-form="blocklist-interval" data-subscription-id="${esc(s.subscription_id)}" class="field-row">
          <label>Update interval <select name="update_interval_seconds"><option value="">Use global default</option>${presets.map((p) => `<option value="${esc(p.seconds)}" ${s.update_interval_seconds === p.seconds ? "selected" : ""}>${esc(p.label)}</option>`).join("")}</select></label>
          <button>Save</button>
        </form>
      </td>
      </tr>`).join("");
    const jobRows = (data.jobs || []).slice(0, 5).map((j) => `<tr><td>${ts(j.started_at)}</td><td><span class="badge ${tone(j.status)}">${esc(j.status)}</span></td><td>${esc(j.kind)}</td><td>${esc((j.subscription_ids || []).join(", "))}</td><td>${esc(j.error || Object.values(j.results || {}).map((r) => r.message).join("; "))}</td></tr>`).join("");
    return page("Blocklists", "Subscribed, refreshable domain-block feeds. A failed refresh keeps the previous valid list enforced -- it never clears filtering on error.", `<button data-blocklist-refresh-all class="primary">Update All</button><button data-refresh>Refresh page</button>`, `
      <section class="panel"><div class="panel__head"><h2>Update Schedule</h2></div><div class="panel__body">
        <form data-form="blocklist-settings" class="field-row">
          <label>Global default Update Interval <select name="default_interval_seconds">${presets.map((p) => `<option value="${esc(p.seconds)}" ${Number(data.settings.default_interval_seconds) === Number(p.seconds) ? "selected" : ""}>${esc(p.label)}</option>`).join("")}</select></label>
          <button>Save</button>
        </form>
      </div></section>
      <section class="panel"><div class="panel__head"><h2>Subscriptions</h2></div><div class="panel__body">
        ${(data.subscriptions || []).length ? `<div class="table-wrap"><table data-grid data-grid-id="blocklist-subscriptions"><thead><tr><th>Name</th><th>URL</th><th>Enabled</th><th>Rules</th><th>Last successful update</th><th>Next update</th><th>Effective interval</th><th>Status</th><th class="actions-cell" data-no-sort aria-label="Actions"></th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No blocklist subscriptions yet.</div>`}
      </div></section>
      ${jobRows ? `<section class="panel"><div class="panel__head"><h2>Recent Updates</h2></div><div class="panel__body"><div class="table-wrap"><table><thead><tr><th>Started</th><th>Status</th><th>Scope</th><th>Sources</th><th>Result</th></tr></thead><tbody>${jobRows}</tbody></table></div></div></section>` : ""}
      <section class="panel"><div class="panel__head"><h2>Add Subscription</h2></div><div class="panel__body">
        <form data-form="blocklist-create"><div class="form-grid">
          <label>Name<input name="name" required placeholder="StevenBlack Unified Hosts"></label>
          <label>Category<input name="category" placeholder="ads_trackers"></label>
        </div><label>URL<input name="url" required placeholder="https://example.com/hosts.txt"></label>
        <button class="primary">Add subscription</button></form>
      </div></section>`);
  }

  async function cache() {
    const status = await api("/api/cache/status");
    const bindRows = (status.bind || []).map((b) => `
      <tr><td class="mono">${esc(b.context)}</td><td>${b.available ? `${esc(b.hits)} / ${esc(b.misses)}` : '<span class="badge bad">unavailable</span>'}</td><td>${b.available && b.hit_ratio != null ? esc(Math.round(b.hit_ratio * 100)) + "%" : "-"}</td><td>
        <form data-form="cache-flush" data-layer="bind" data-context="${esc(b.context)}" class="field-row">
          <select name="scope"><option value="all">entire context</option><option value="name">exact name</option><option value="tree">subtree</option></select>
          <input name="target" placeholder="name (for name/subtree scope)">
          <button class="danger">Flush</button>
        </form>
      </td></tr>`).join("");
    return page("Cache", "Two independent RAM cache layers: dnsdist's packet cache (per query, in front of policy) and BIND's recursive cache (per context, behind it). A flush always targets one layer explicitly.", `<button data-refresh>Refresh</button>`, `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>BIND Recursive Cache</h2></div><div class="panel__body">
          ${(status.bind || []).length ? `<div class="table-wrap"><table><thead><tr><th>Context</th><th>Hits / Misses</th><th>Hit ratio</th><th>Flush</th></tr></thead><tbody>${bindRows}</tbody></table></div>` : `<div class="empty">No compiled BIND context yet -- promote a policy change first.</div>`}
        </section>
        <section class="panel"><div class="panel__head"><h2>dnsdist Packet Cache</h2></div><div class="panel__body">
          <p class="muted">${esc((status.dnsdist || {}).note || "")}</p>
          <form data-form="cache-flush" data-layer="dnsdist"><button class="danger">Flush (restarts dnsdist)</button></form>
        </section>
      </div>`);
  }

  async function network() {
    const status = await api("/api/network/status");
    const current = status.current || {};
    const pending = status.pending;
    const ifaceOptions = (current.interfaces || []).map((i) => `<option value="${esc(i)}" ${i === current.interface ? "selected" : ""}>${esc(i)}</option>`).join("");
    const source = current.source || {};
    const sourceText = source.label || (source.kind === "host_metadata" ? "Detected from appliance host" : "Detected from appliance OS");
    const row = (label, value) => `<tr><td>${esc(label)}</td><td class="mono">${esc(value ?? "unknown")}</td></tr>`;
    const changeForm = current.backend && current.backend !== "unsupported" && current.backend !== "external" && !pending ? `
      <section class="panel"><div class="panel__head"><h2>Change Network Configuration</h2></div><div class="panel__body">
        <p class="muted">Changing this appliance's IP address may disconnect your browser. The previous configuration is automatically restored if the new settings are not confirmed within about 120 seconds -- no reboot required.</p>
        <form data-form="network-apply">
          <label>Interface<select name="interface">${ifaceOptions}</select></label>
          <div class="form-grid">
            <label>IPv4 mode<select name="ipv4_mode"><option value="unchanged">Leave unchanged</option><option value="dhcp">DHCP</option><option value="static">Static</option></select></label>
            <label>Static IPv4 address<input name="ipv4_address" placeholder="192.168.1.10"></label>
            <label>Prefix length<input name="ipv4_prefix" type="number" min="0" max="32" placeholder="24"></label>
            <label>Gateway<input name="ipv4_gateway" placeholder="192.168.1.1"></label>
          </div>
          <details><summary>IPv6 (optional)</summary><div class="form-grid">
            <label>IPv6 mode<select name="ipv6_mode"><option value="unchanged">Leave unchanged</option><option value="slaac">SLAAC</option><option value="dhcp">DHCPv6</option><option value="static">Static</option></select></label>
            <label>Static IPv6 address<input name="ipv6_address" placeholder="2001:db8::10"></label>
            <label>Prefix length<input name="ipv6_prefix" type="number" min="0" max="128" placeholder="64"></label>
            <label>Gateway<input name="ipv6_gateway" placeholder="2001:db8::1"></label>
          </div></details>
          <button class="primary">Apply</button>
        </form>
      </div></section>` : (!pending ? `<div class="empty">${esc(current.backend_detail || "Network configuration is read-only on this host.")}</div>` : "");
    const pendingPanel = pending ? `
      <section class="panel"><div class="panel__head"><h2>Network configuration changed</h2><span class="badge warn">Awaiting confirmation</span></div><div class="panel__body">
        <p>New address: <span class="mono">${esc((pending.proposed || {}).ipv4 ? `${pending.proposed.ipv4.address}/${pending.proposed.ipv4.prefix}` : "-")}</span></p>
        <p class="muted">Confirm before <span class="mono">${esc(pending.rollback_deadline)}</span> (about 120 seconds after it was applied), or the previous configuration is automatically restored -- no reboot required. If you are reading this from the <strong>new</strong> address, everything is working; confirm below to make it permanent.</p>
        <form data-form="network-confirm"><button class="primary">Keep Configuration</button></form>
      </div></section>` : "";
    return page("Network Configuration", "This appliance's own interface/address (DHCP or static IP, gateway) -- separate from DNS upstream/resolver settings. Alderpoint DNS is DNS-only: no DHCP server, NAT, firewall, or router functionality is added here.", `<button data-refresh>Refresh</button>`, `
      ${pendingPanel}
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Detected Backend</h2></div><div class="panel__body">
          <span class="badge ${current.backend && current.backend !== "unsupported" ? "ok" : "bad"}">${esc(current.backend || "unknown")}</span>
          <p class="muted">${esc(current.backend_detail || "")}</p>
          <p class="muted">${esc(sourceText)}${source.generated_at ? ` at ${ts(source.generated_at, "")}` : ""}${source.stale ? " (stale)" : ""}</p>
          ${current.ambiguous ? `<p class="alert error">Multiple networking backends appear active on this host. Settings are shown read-only until this is resolved.</p>` : ""}
        </section>
        <section class="panel"><div class="panel__head"><h2>Management Interface</h2></div><div class="panel__body"><p class="mono">${esc(current.interface || "none detected")}</p></section>
      </div>
      <section class="panel"><div class="panel__head"><h2>Current Network Settings</h2></div><div class="panel__body">
        <div class="table-wrap"><table><tbody>
          ${row("IPv4 mode", current.ipv4 && current.ipv4.mode)}
          ${row("Current IPv4 address", current.ipv4 && current.ipv4.address ? `${current.ipv4.address}/${current.ipv4.prefixlen}` : "none")}
          ${row("Default gateway (IPv4)", current.ipv4 && current.ipv4.gateway)}
          ${row("IPv6 mode", current.ipv6 && current.ipv6.mode)}
          ${row("Current IPv6 address", current.ipv6 && current.ipv6.address ? `${current.ipv6.address}/${current.ipv6.prefixlen}` : "none")}
          ${row("Default gateway (IPv6)", current.ipv6 && current.ipv6.gateway)}
        </tbody></table></div>
      </div></section>
      ${changeForm}`);
  }

  const IMPORT_SOURCE_LABELS = {
    adguard_yaml: "AdGuard Home (YAML config file)",
    adguard_api: "AdGuard Home (live API connection)",
    pihole: "Pi-hole (exported lists, pasted or concatenated)",
    hosts: "Hosts file",
    bind_zone: "BIND zone file",
    csv: "Alderpoint-native CSV",
    xlsx: "Alderpoint-native XLSX",
    alderpointdns_json: "Alderpoint-native JSON",
  };
  const IMPORT_BINARY_SOURCES = new Set(["xlsx"]);
  const IMPORT_API_SOURCES = new Set(["adguard_api"]);

  async function importexport() {
    const jobs = await api("/api/import/jobs").catch(() => ({ jobs: [] }));
    return page("Import", "AdGuard Home, Pi-hole, hosts/BIND zone, Alderpoint-native CSV/XLSX/JSON. Every import is previewed before anything is written.", "", `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>New Import</h2></div><div class="panel__body">${importSourceForm()}</div></section>
        <section class="panel"><div class="panel__head"><h2>Recent Import Jobs</h2></div><div class="panel__body"><div id="import-jobs">${importJobsTable(jobs.jobs || [])}</div></div></section>
      </div>
      <section class="panel" id="import-preview-panel" hidden><div class="panel__head"><h2>Preview</h2></div><div class="panel__body" id="import-preview"></div></section>`);
  }

  function importSourceForm() {
    const options = Object.entries(IMPORT_SOURCE_LABELS).map(([id, label]) => `<option value="${esc(id)}">${esc(label)}</option>`).join("");
    return `<form data-form="import-parse">
      <label>Source type<select name="source_type" data-import-type>${options}</select></label>
      <label>Source name<input name="source_name" value="import" maxlength="128"></label>
      <label>Default domain (for hosts/zone/AdGuard rewrites without one)<input name="default_domain" placeholder="home.arpa"></label>
      <div data-import-field="file"><label>File<input type="file" name="file"></label></div>
      <div data-import-field="text" hidden><label>Paste content<textarea name="text_paste" placeholder="Paste Pi-hole export lines here"></textarea></label></div>
      <div data-import-field="api" hidden>
        <div class="form-grid">
          <label>AdGuard Home base URL<input name="base_url" placeholder="https://10.0.0.5:3000"></label>
          <label>Username<input name="username"></label>
          <label>Password<input name="password" type="password"></label>
        </div>
      </div>
      <button class="primary">Parse and preview</button>
    </form>`;
  }

  function importJobsTable(jobs) {
    if (!jobs.length) return `<div class="empty">No import jobs yet.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Source</th><th>Name</th><th>Status</th><th>Items</th><th>Created</th></tr></thead><tbody>${jobs.map((j) => `
      <tr><td>${j.id}</td><td>${esc(j.source_type)}</td><td>${esc(j.source_name)}</td><td><span class="badge ${tone(j.status)}">${esc(j.status)}</span></td><td>${esc((j.plan || {}).item_count ?? "")}</td><td>${ts(j.created_at, "")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  function importPlanPreview(jobId, plan) {
    const items = plan.items || [];
    const rows = items.map((item, index) => {
      const desc = item.kind === "local_dns" ? `${item.fqdn} ${item.record_type} -> ${item.value}`
        : item.kind === "block_domain" ? `block ${item.domain} (${item.match_kind})`
        : item.kind === "upstream" ? `${item.name} (${item.transport}) ${item.address}`
        : item.kind === "client" ? `client ${item.name}`
        : `${item.text || ""}`;
      const status = item.kind === "unsupported" ? `<span class="badge warn">unsupported</span>` : item.already_applied ? `<span class="badge ok">already applied</span>` : item.conflict ? `<span class="badge bad">conflict</span>` : `<span class="badge info">new</span>`;
      return `<tr><td><input type="checkbox" data-skip-index="${index}" ${item.kind === "unsupported" ? "disabled" : "checked"}></td><td>${esc(item.kind)}</td><td>${esc(desc)}</td><td>${status}</td><td class="muted">${esc(item.reason || item.conflict_note || item.note || "")}</td></tr>`;
    }).join("");
    return `
      <div class="strip"><div class="metric"><strong>${plan.item_count ?? items.length}</strong><span>Total items</span></div><div class="metric"><strong>${plan.conflict_count ?? 0}</strong><span>Conflicts</span></div>${Object.entries(plan.summary || {}).map(([k, v]) => `<div class="metric"><strong>${esc(v)}</strong><span>${esc(k)}</span></div>`).join("")}</div>
      <div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Apply</th><th>Kind</th><th>Item</th><th>Status</th><th>Note</th></tr></thead><tbody>${rows || `<tr><td colspan="5" class="empty">Nothing to import.</td></tr>`}</tbody></table></div>
      <form data-form="import-apply" data-job-id="${jobId}" style="margin-top:12px"><button class="primary">Apply selected items and promote runtime</button></form>`;
  }

  async function updates() {
    const [status, jobs] = await Promise.all([
      api("/api/updates/status"),
      api("/api/updates/jobs").catch(() => ({ jobs: [] })),
    ]);
    return page("Software Updates", "V2 is private: there is no public release channel. Check a configured private feed, or upload and apply a package manually.", `<button data-refresh>Refresh</button>`, `
      <div class="strip">
        <div class="metric"><strong class="mono">${esc(status.installed_source_version)}</strong><span>Installed (source)</span></div>
        <div class="metric"><strong class="mono">${esc(status.installed_package_version || "unmanaged")}</strong><span>Installed (package)</span></div>
        <div class="metric"><strong>${esc(status.channel)}</strong><span>Channel</span></div>
        <div class="metric"><strong class="badge ${status.public_release_available ? 'ok' : 'warn'}">${status.public_release_available ? "candidate available" : "none available"}</strong><span>Private feed</span></div>
      </div>
      <div class="alert ${status.public_release_available ? 'ok' : 'info'}">${esc(status.message)}</div>
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Private Update Feed</h2></div><div class="panel__body">
          <p class="muted">Point at a directory (e.g. a mounted private artifact share) containing a <code>metadata.json</code> describing one candidate package. Leave empty for "no public release available."</p>
          <form data-form="update-settings"><label>Feed directory<input name="private_feed_dir" value="${esc(status.private_feed_dir || "")}" placeholder="/mnt/private-updates"></label><button>Save</button></form>
        </div></section>
        <section class="panel"><div class="panel__head"><h2>Manual Package Upload</h2></div><div class="panel__body">
          <p class="muted">Validated before anything is staged: package name, amd64 architecture, and a version strictly newer than what's installed. Nothing is installed until you explicitly confirm Apply below -- an unprivileged process never runs apt itself.</p>
          <form data-form="update-upload"><label>Package (.deb)<input type="file" name="file" accept=".deb"></label><button class="primary">Validate and stage</button></form>
        </div></section>
      </div>
      <section class="panel"><div class="panel__head"><h2>Update Jobs</h2></div><div class="panel__body" id="update-jobs">${updateJobsTable(jobs.jobs || [])}</div></section>`);
  }

  function updateJobsTable(jobs) {
    if (!jobs.length) return `<div class="empty">No update jobs yet.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Status</th><th>Version</th><th>Started</th><th>Finished</th><th>Actions</th></tr></thead><tbody>${jobs.map((j) => `
      <tr><td>${j.id}</td><td><span class="badge ${tone(j.status)}">${esc(j.status)}</span></td><td>${esc(j.detail.candidate_version || "")}</td><td>${ts(j.started_at, "")}</td><td>${ts(j.finished_at, "")}</td><td>${j.status === "staged" ? `<button data-apply-update="${j.id}" class="danger">Apply</button>` : ""}${j.detail.apply_result && j.detail.apply_result.error ? `<span class="muted">${esc(j.detail.apply_result.error)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
  }

  const renderers = { dashboard, analytics, clients, policies, filtering, blocklists, encryption, upstreams, localdns, cache, network, replication, backup, statistics, notifications, administration, health, importexport, updates, logs };

  // Real defect fixed here (found by the expanded stateful-navigation
  // regression, priority 1 of the beta-rescue brief): loadPage() had no
  // guard against out-of-order async completion. A theme toggle re-renders
  // the shell and then re-awaits loadPage(state.route) for whichever route
  // was active *at that moment*; if the operator clicks a different nav
  // item before that in-flight fetch resolves, state.route moves on but
  // the stale fetch still unconditionally overwrote #page with the old
  // route's content once it finally settled -- silently reverting a
  // completed, more-recent navigation. `token` makes every load request
  // self-identifying so a load only ever writes the DOM if it is still the
  // most recently requested one.
  let loadToken = 0;
  async function loadPage(id, opts = {}) {
    const requested = id || "dashboard";
    const token = ++loadToken;
    const navigationId = `nav-${token}-${Date.now().toString(36)}`;
    state.currentNavigationId = navigationId;
    const navAcceptedAt = nowMs();
    const routeStartAt = state.lastNavClickAt || navAcceptedAt;
    performance.mark(`route-${token}-accepted`);
    // Cancel the previous page-load's own in-flight GETs (see api()'s
    // pageLoadController note) before starting this one's.
    if (pageLoadController) pageLoadController.abort();
    cleanupDashboardLive();
    closeRowActionMenus();
    state.inFlightGets.clear();
    pageLoadController = new AbortController();
    // Real defect fixed here (owner-beta closure item 3, found live via
    // the Chromium harness's own browser back/forward proof): every
    // navigation -- a real route change from a sidebar click AND a
    // same-route re-render from a theme toggle or sidebar collapse --
    // called history.replaceState, so the SPA never accumulated more
    // than the one history entry the browser started on. Back/forward
    // did nothing (or, worse, navigated the browser straight out of the
    // app). Only an actual route change earns a new history entry;
    // same-route re-renders and popstate-driven loads (opts.replace)
    // still replace in place, so toggling the theme or collapsing the
    // sidebar doesn't spam back with no-op entries.
    const routeChanged = state.route !== requested;
    state.route = requested;
    const url = `/ui/${requested}`;
    if (!opts.replace && routeChanged) history.pushState(null, "", url);
    else history.replaceState(null, "", url);
    document.querySelectorAll("[data-route]").forEach((b) => {
      const isActive = b.dataset.route === state.route;
      b.classList.toggle("active", isActive);
      if (isActive) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current");
    });
    // Navigating (via a link, a promote/back action, or a deep link) into
    // a section that is currently collapsed must reveal the newly active
    // item rather than leaving the sidebar showing no visible selection --
    // same real-navigation expectation as V1.1.1's server-rendered nav,
    // where the active section is always expanded regardless of prior
    // collapsed state. Only the containing section is touched; every
    // other section's open/closed state (and its persisted preference)
    // is left exactly as the operator left it.
    const keepMultipleOpen = navKeepMultipleOpen();
    document.querySelectorAll("[data-nav-section]").forEach((section) => {
      const inSection = section.querySelector(`[data-route="${CSS.escape(requested)}"]`);
      section.classList.toggle("is-active", !!inSection);
      const toggle = section.querySelector("[data-nav-section-toggle]");
      if (!inSection) {
        // Accordion default: navigating into a different section closes
        // every other one, same as an explicit click (owner-reported
        // requirement: "route navigation" must behave consistently with
        // clicking the section header). Skipped entirely when the
        // operator has opted into keeping multiple sections open.
        if (!keepMultipleOpen && toggle && toggle.getAttribute("aria-expanded") === "true") {
          toggle.setAttribute("aria-expanded", "false");
          toggle.removeAttribute("aria-current");
          const panel = document.getElementById(toggle.getAttribute("aria-controls"));
          if (panel) panel.hidden = true;
          const chevron = toggle.querySelector(".nav-section__chevron");
          if (chevron) chevron.textContent = "▸";
          setNavSectionOpen(section.getAttribute("data-nav-section"), false);
        }
        return;
      }
      const panel = document.getElementById(toggle.getAttribute("aria-controls"));
      toggle.setAttribute("aria-expanded", "true");
      toggle.setAttribute("aria-current", "true");
      panel.hidden = false;
      const chevron = toggle.querySelector(".nav-section__chevron");
      if (chevron) chevron.textContent = "▾";
      setNavSectionOpen(section.getAttribute("data-nav-section"), true);
    });
    const target = document.getElementById("page");
    const cached = state.routeCache.get(requested);
    const cacheFresh = cached && (Date.now() - cached.at) < ROUTE_CACHE_TTL_MS;
    target.setAttribute("data-route-name", requested);
    target.setAttribute("data-route-ready", "0");
    target.innerHTML = cacheFresh ? cached.html : routeSkeleton(requested, "Loading live appliance data.");
    if (cacheFresh) target.insertAdjacentHTML("afterbegin", `<div class="alert info" data-cache-note>Refreshing ${esc(pageTitleFor(requested))}...</div>`);
    await nextPaint();
    const shellPaintAt = nowMs();
    performance.measure(`route-${token}-shell`, { start: `route-${token}-accepted`, duration: shellPaintAt - navAcceptedAt });
    try {
      const html = await renderers[requested]();
      if (token !== loadToken) return;
      target.innerHTML = html;
      target.setAttribute("data-route-ready", "1");
      state.routeCache.set(requested, { at: Date.now(), html });
      await nextPaint();
      const doneAt = nowMs();
      performance.measure(`route-${token}-complete`, { start: `route-${token}-accepted`, duration: doneAt - navAcceptedAt });
      const recentApis = state.perfHistory.filter((e) => e.type === "api" && e.navigation_id === navigationId && !e.background);
      const slowestApi = recentApis.sort((a, b) => (b.total_ms || 0) - (a.total_ms || 0))[0];
      perfSave({
        type: "route",
        route: requested,
        navigation_id: navigationId,
        timestamp: absNow(),
        viewport: `${window.innerWidth}x${window.innerHeight}`,
        browser_timezone: browserTimezone(),
        click_to_accept_ms: Math.round(navAcceptedAt - routeStartAt),
        shell_paint_ms: Math.round(shellPaintAt - routeStartAt),
        first_useful_ms: Math.round((cacheFresh ? shellPaintAt : doneAt) - routeStartAt),
        total_ms: Math.round(doneAt - routeStartAt),
        cache_status: cacheFresh ? "warm-route-cache" : "miss",
        slowest_api: slowestApi ? `${slowestApi.path} ${slowestApi.total_ms}ms` : "",
      });
    } catch (err) {
      if (token !== loadToken) return;
      if (err.status === 401) return boot();
      target.innerHTML = page("Page unavailable", "The backend rejected or failed this request.", `<button data-refresh>Retry</button>`, `<div class="alert bad">${esc(err.message)}</div>`);
    }
    state.lastNavClickAt = 0;
  }

  function authScreen(setupRequired) {
    // Owner-approved removal of a prior mandatory SSH-retrieved setup-
    // token flow: first-run setup is still "create the first administrator
    // right here" -- no token field, no instruction to go retrieve a
    // secret from the appliance's state directory. But the owner
    // finding (priority 2 of the beta-rescue brief) was that setup had
    // regressed to username+password alone; V1.1.1's actual first-run
    // fields (confirm password, appliance hostname/address for Local DNS)
    // are restored here, adapted to V2 -- see docs/v2/beta-rescue-setup-fields.md.
    if (!setupRequired) {
      return `<main class="auth"><section class="auth-card"><div class="mark">A</div><h1>Sign in</h1><p>Use your Alderpoint DNS administrator account.</p>
        <form data-auth="login">
          <label>Username<input name="username" required autocomplete="username"></label>
          <label>Password<input name="password" type="password" required minlength="1" autocomplete="current-password"></label>
          <button class="primary">Sign in</button>
        </form></section></main>`;
    }
    return `<main class="auth"><section class="auth-card auth-card--setup"><div class="mark">A</div><h1>Initial administrator setup</h1><p>Create the first local administrator. No default password exists.</p>
      <div class="alert bad" data-setup-error hidden></div>
      <form data-auth="setup" data-password-match>
        <fieldset><legend>Administration</legend>
          <label>Username<input name="username" value="admin" required autocomplete="username"></label>
          <label>Password
            <span class="password-field"><input name="password" type="password" minlength="12" required autocomplete="new-password" data-password-input>
              <button type="button" class="password-toggle" data-password-toggle aria-pressed="false" aria-label="Show password">Show</button></span>
          </label>
          <label>Confirm password
            <span class="password-field"><input name="confirm_password" type="password" minlength="12" required autocomplete="new-password" data-password-input>
              <button type="button" class="password-toggle" data-password-toggle aria-pressed="false" aria-label="Show password">Show</button></span>
          </label>
          <p class="muted" data-password-hint>Minimum 12 characters.</p>
        </fieldset>
        <fieldset><legend>Local DNS</legend>
          <label class="row"><input type="checkbox" name="create_local_dns" value="1" checked> Create Alderpoint DNS local DNS records</label>
          <label>Alderpoint DNS hostname<input name="server_hostname" value="alderpointdns"></label>
          <label>Alderpoint DNS IP address<input name="server_ip" placeholder="detected automatically if left blank"></label>
          <p class="muted">Creates an A record for the appliance's hostname. The address is detected automatically when left blank and can be changed later from Local DNS or Network Configuration.</p>
        </fieldset>
        <button class="primary">Create administrator</button>
      </form></section></main>`;
  }

  // Post-bootstrap application lifecycle (real defect fixed here, owner-
  // reported: the root #app container kept its initial "boot-screen"
  // class -- a centered, content-sized layout meant only for the loading
  // splash/auth card -- forever after the real app shell replaced its
  // contents. Since "boot-screen" is `display:grid; place-items:center`,
  // its child (the real .layout grid) was never stretched to fill the
  // viewport, so the whole sidebar+shell visibly resized and re-centered
  // itself depending on how wide each route's own content happened to
  // be. #app's class is now set explicitly and exactly once per state
  // transition -- "app-shell" (stable, full-viewport, see app.css) for
  // the real management console, "boot-screen" (centered card) for the
  // loading splash and the login/setup screen -- instead of relying on
  // whatever class happened to be left over from page load.
  let wired = false;
  let popstateWired = false;

  async function boot() {
    setTheme(state.theme);
    try {
      const session = await api("/api/session");
      state.csrf = session.csrf;
      state.user = session.username;
      const app = document.getElementById("app");
      app.className = "app-shell";
      renderShell();
      // wire() attaches delegated click/submit listeners on
      // document.body, which is never replaced by any re-render (only
      // #app's innerHTML changes) -- so it must be attached exactly
      // once per page load, never per render. Attaching it again on
      // every rerender (real defect fixed here, owner-reported: dark ->
      // light worked, light -> dark silently did nothing) stacked a new
      // listener on top of every prior one, so a single click ran every
      // still-attached handler in sequence -- each one toggling
      // state.theme again -- and an even total of stacked handlers left
      // the theme back where it started.
      if (!wired) { wire(); wired = true; }
      await loadPage(location.pathname.startsWith("/ui/") ? location.pathname.slice(4) || "dashboard" : "dashboard", { replace: true });
      if (!popstateWired) {
        // Real browser back/forward support (owner-beta closure item
        // 3): the browser itself already moved the history cursor by
        // the time this fires -- just render whatever route the URL
        // now names, in place, without pushing yet another entry.
        window.addEventListener("popstate", () => {
          loadPage(location.pathname.startsWith("/ui/") ? location.pathname.slice(4) || "dashboard" : "dashboard", { replace: true });
        });
        popstateWired = true;
      }
    } catch (_) {
      const setup = await api("/api/setup/status").catch(() => ({ setup_required: false }));
      const app = document.getElementById("app");
      app.className = "boot-screen";
      app.innerHTML = authScreen(setup.setup_required);
      wireAuth();
    }
  }

  function wireAuth() {
    const form = document.querySelector("[data-auth]");
    // Password visibility toggle (V1.1.1 parity + owner-approved
    // improvement -- V1's setup screen never had one).
    form.querySelectorAll("[data-password-toggle]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const input = btn.previousElementSibling;
        const showing = input.type === "text";
        input.type = showing ? "password" : "text";
        btn.setAttribute("aria-pressed", String(!showing));
        btn.textContent = showing ? "Show" : "Hide";
        btn.setAttribute("aria-label", showing ? "Show password" : "Hide password");
      });
    });
    // Client-side mismatch feedback (a real owner-reported finding, priority 2):
    // live as-you-type, in addition to the server's own enforcement in
    // /api/setup -- neither replaces the other.
    if (form.dataset.passwordMatch !== undefined) {
      const pw = form.querySelector('[name="password"]');
      const confirm = form.querySelector('[name="confirm_password"]');
      if (pw && confirm) {
        const checkMatch = () => {
          const mismatched = confirm.value.length > 0 && pw.value !== confirm.value;
          confirm.setCustomValidity(mismatched ? "Passwords do not match." : "");
        };
        pw.addEventListener("input", checkMatch);
        confirm.addEventListener("input", checkMatch);
      }
    }
    form.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const errorBox = form.querySelector("[data-setup-error]");
      if (errorBox) errorBox.hidden = true;
      await submitOnce(form, async () => {
        const username = form.elements.username.value;
        const password = form.elements.password.value;
        try {
          if (form.dataset.auth === "setup") {
            const confirmPassword = form.elements.confirm_password.value;
            if (password !== confirmPassword) {
              throw new Error("Passwords do not match.");
            }
            await api("/api/setup", {
              method: "POST",
              body: JSON.stringify({
                username,
                password,
                confirm_password: confirmPassword,
                create_local_dns: form.elements.create_local_dns.checked,
                server_hostname: form.elements.server_hostname.value,
                server_ip: form.elements.server_ip.value,
              }),
            });
          }
          const login = await api("/api/login", { method: "POST", body: JSON.stringify({ username, password }) });
          state.csrf = login.csrf;
          await boot();
          return "skip-reload";
        } catch (err) {
          if (errorBox) { errorBox.hidden = false; errorBox.textContent = err.message; }
          throw err;
        }
      });
    });
  }

  // Real defect fixed here (owner-reported: a native SVG <title> alone
  // is not an adequate operator tooltip system -- invisible until
  // hover, unreachable by keyboard, unusable on touch). One shared
  // floating tooltip element, positioned above whichever chart point is
  // currently hovered/focused/tapped, driven by that point's own
  // data-tp-* attributes (already respecting the active Browser/
  // Appliance/UTC display mode -- see renderActivitySvgMarkup).
  function chartTooltipEl() {
    let tip = document.getElementById("apdns-chart-tooltip");
    if (!tip) {
      tip = document.createElement("div");
      tip.id = "apdns-chart-tooltip";
      tip.className = "ts-tooltip";
      tip.setAttribute("role", "status");
      tip.setAttribute("aria-live", "polite");
      document.body.appendChild(tip);
    }
    return tip;
  }
  function showChartTooltip(el) {
    const tip = chartTooltipEl();
    const time = el.getAttribute("data-tp-time") || "";
    const total = el.getAttribute("data-tp-total") || "0";
    const blocked = el.getAttribute("data-tp-blocked") || "0";
    const pct = el.getAttribute("data-tp-pct") || "0";
    tip.innerHTML = `<strong>${esc(time)}</strong><br>${esc(total)} queries<br>${esc(blocked)} blocked (${esc(pct)}%)`;
    const rect = el.getBoundingClientRect();
    let left = rect.left + rect.width / 2;
    left = Math.max(70, Math.min(left, window.innerWidth - 70));
    tip.style.left = `${left}px`;
    tip.style.top = `${Math.max(8, rect.top - 8)}px`;
    tip.classList.add("is-visible");
  }
  function hideChartTooltip() {
    const tip = document.getElementById("apdns-chart-tooltip");
    if (tip) tip.classList.remove("is-visible");
  }

  function wire() {
    document.body.addEventListener("mouseover", (ev) => {
      const pt = ev.target.closest(".ts-point-hit");
      if (pt) showChartTooltip(pt);
    });
    document.body.addEventListener("mouseout", (ev) => {
      const pt = ev.target.closest(".ts-point-hit");
      if (pt) hideChartTooltip();
    });
    // Real defect fixed here (found live via the Chromium harness, not
    // source inspection): "focusin"/"focusout" are the usual delegation
    // choice (they bubble, unlike plain "focus"/"blur"), but a focused
    // SVG <circle> did not reliably dispatch a bubbling focusin this
    // browser could observe at document.body even though
    // document.activeElement correctly became the circle. "focus"/
    // "blur" don't bubble at all, but registering them with the
    // capture-phase flag lets one delegated listener at document.body
    // still observe every focus/blur anywhere beneath it, SVG included
    // -- the traditional, reliable way to delegate non-bubbling focus
    // events.
    document.body.addEventListener("focus", (ev) => {
      const pt = ev.target.closest && ev.target.closest(".ts-point-hit");
      if (pt) showChartTooltip(pt);
    }, true);
    document.body.addEventListener("blur", (ev) => {
      const pt = ev.target.closest && ev.target.closest(".ts-point-hit");
      if (pt) hideChartTooltip();
    }, true);
    document.body.addEventListener("dragover", (ev) => {
      const drop = ev.target.closest && ev.target.closest("[data-drop-upload]");
      if (!drop) return;
      ev.preventDefault();
      drop.classList.add("is-dragging");
    });
    document.body.addEventListener("dragleave", (ev) => {
      const drop = ev.target.closest && ev.target.closest("[data-drop-upload]");
      if (drop && !drop.contains(ev.relatedTarget)) drop.classList.remove("is-dragging");
    });
    document.body.addEventListener("drop", (ev) => {
      const drop = ev.target.closest && ev.target.closest("[data-drop-upload]");
      if (!drop) return;
      ev.preventDefault();
      drop.classList.remove("is-dragging");
      const file = ev.dataTransfer && ev.dataTransfer.files && ev.dataTransfer.files[0];
      const input = drop.querySelector('input[type=file]');
      if (file && input) {
        const dt = new DataTransfer();
        dt.items.add(file);
        input.files = dt.files;
        const hint = drop.querySelector("[data-upload-hint]");
        if (hint) hint.textContent = `Selected ${file.name}`;
      }
    });
    document.body.addEventListener("change", (ev) => {
      const input = ev.target.closest && ev.target.closest("[data-drop-upload] input[type=file]");
      if (!input) return;
      const hint = input.closest("[data-drop-upload]").querySelector("[data-upload-hint]");
      if (hint && input.files[0]) hint.textContent = `Selected ${input.files[0].name}`;
    });
    document.body.addEventListener("click", async (ev) => {
      // Touch/click activation for the chart tooltip (mouseover/focusin
      // above already cover mouse and keyboard) -- toggles so a second
      // tap on the same point dismisses it, and any other click in the
      // app dismisses a currently-shown tooltip rather than leaving it
      // stuck open.
      const chartPoint = ev.target.closest(".ts-point-hit");
      if (chartPoint) {
        const tip = chartTooltipEl();
        if (tip.classList.contains("is-visible") && tip.dataset.forPoint === chartPoint.getAttribute("data-tp-time") + chartPoint.className) hideChartTooltip();
        else { showChartTooltip(chartPoint); chartTooltipEl().dataset.forPoint = chartPoint.getAttribute("data-tp-time") + chartPoint.className; }
      } else {
        hideChartTooltip();
      }
      const route = ev.target.closest("[data-route]");
      if (route) {
        state.lastNavClickAt = nowMs();
        document.body.classList.remove("nav-open");
        document.querySelectorAll(".nav-section.is-flyout-open").forEach((s) => {
          s.classList.remove("is-flyout-open");
          const t = s.querySelector("[data-nav-section-toggle]");
          if (t) t.setAttribute("aria-expanded", "false");
        });
        await loadPage(route.dataset.route);
        return;
      }
      if (ev.target.closest("[data-action='menu']")) { document.body.classList.toggle("nav-open"); return; }
      if (ev.target.closest("[data-copy-perf]")) {
        const report = performanceReportText();
        if (navigator.clipboard && navigator.clipboard.writeText) await navigator.clipboard.writeText(report);
        else window.prompt("Copy UI Performance Report", report);
        toast("UI performance report copied", "ok");
        return;
      }
      if (ev.target.closest("[data-clear-perf]")) {
        clearPerformanceMeasurements();
        toast("UI performance measurements cleared", "ok");
        await loadPage("health");
        return;
      }
      if (ev.target.closest("[data-action='theme']")) { setTheme(state.theme === "dark" ? "light" : "dark"); renderShell(); await loadPage(state.route); return; }
      if (ev.target.closest("[data-action='collapse']")) { state.navCollapsed = !state.navCollapsed; localStorage.setItem("apdnsNavCollapsed", state.navCollapsed ? "1" : "0"); renderShell(); await loadPage(state.route); return; }
      const sectionToggle = ev.target.closest("[data-nav-section-toggle]");
      if (sectionToggle) {
        const section = sectionToggle.closest("[data-nav-section]");
        const group = section && section.getAttribute("data-nav-section");
        // In the collapsed icon-rail, a section's toggle opens/closes a
        // transient flyout beside the rail rather than the persisted
        // expanded-mode disclosure state -- switching collapse modes must
        // not fight over the same stored preference, and only one flyout
        // is open at a time (real owner-reported finding: collapsed
        // navigation was not properly usable).
        if (state.navCollapsed) {
          const wasOpen = section.classList.contains("is-flyout-open");
          document.querySelectorAll(".nav-section.is-flyout-open").forEach((s) => {
            s.classList.remove("is-flyout-open");
            const t = s.querySelector("[data-nav-section-toggle]");
            if (t) t.setAttribute("aria-expanded", "false");
          });
          if (!wasOpen) {
            section.classList.add("is-flyout-open");
            sectionToggle.setAttribute("aria-expanded", "true");
          }
          return;
        }
        // Real defect found live via the Chromium harness (not source
        // inspection, per the corrected contract): this used to call
        // renderShell(), which replaces #app's ENTIRE innerHTML --
        // including the empty `<section id="page"></section>` shell
        // markup -- and never re-ran loadPage() afterward the way the
        // theme/collapse toggles above do. A parent click in expanded
        // mode therefore blanked whatever page was currently showing.
        // (Depending on state.route's async fetch timing this could also
        // show a genuinely wrong page's stale content mid-flight -- the
        // owner-reported "parent click lands on Query Log" class of bug.)
        // A section toggle only needs to open/close its own panel; it
        // must never touch #page at all, so this now mutates exactly the
        // DOM nodes involved -- the same direct-update approach loadPage()
        // itself already uses to reveal the active route's section.
        const open = sectionToggle.getAttribute("aria-expanded") !== "true";
        // Default accordion behavior (owner-reported requirement):
        // opening one main section closes whichever other one was open,
        // unless the operator has turned on "keep multiple navigation
        // sections open" (Administration -> Preferences). Closing a
        // section never touches this one, and this only runs when
        // actually opening (not when collapsing the clicked section),
        // so a click that just closes its own section behaves exactly
        // as before.
        if (open && !navKeepMultipleOpen()) {
          document.querySelectorAll("[data-nav-section]").forEach((otherSection) => {
            if (otherSection === section) return;
            const otherToggle = otherSection.querySelector("[data-nav-section-toggle]");
            if (!otherToggle || otherToggle.getAttribute("aria-expanded") !== "true") return;
            otherToggle.setAttribute("aria-expanded", "false");
            const otherGroup = otherSection.getAttribute("data-nav-section");
            if (otherGroup) setNavSectionOpen(otherGroup, false);
            const otherPanel = document.getElementById(otherToggle.getAttribute("aria-controls"));
            if (otherPanel) otherPanel.hidden = true;
            const otherChevron = otherToggle.querySelector(".nav-section__chevron");
            if (otherChevron) otherChevron.textContent = "▸";
          });
        }
        if (group) setNavSectionOpen(group, open);
        const panel = document.getElementById(sectionToggle.getAttribute("aria-controls"));
        sectionToggle.setAttribute("aria-expanded", String(open));
        if (panel) panel.hidden = !open;
        const chevron = sectionToggle.querySelector(".nav-section__chevron");
        if (chevron) chevron.textContent = open ? "▾" : "▸";
        return;
      }
      if (ev.target.closest("[data-action='logout']")) { await api("/api/logout", { method: "POST" }).catch(() => {}); state.csrf = ""; await boot(); return; }
      if (ev.target.closest("[data-refresh]")) { await loadPage(state.route); return; }
      const tri = ev.target.closest("[data-tri] button");
      if (tri) {
        const wrap = tri.closest("[data-tri]");
        wrap.querySelectorAll("button").forEach((b) => b.classList.remove("active"));
        tri.classList.add("active");
        wrap.closest("label").querySelector("input[type=hidden]").value = tri.dataset.val;
        return;
      }
      const restoreSelect = ev.target.closest("[data-select-restore]");
      if (restoreSelect) {
        const form = restoreSelect.closest('form[data-form="appliance-restore"]');
        if (!form) return;
        const mode = restoreSelect.dataset.selectRestore;
        form.querySelectorAll('input[name="selected_categories"]').forEach((box) => {
          if (box.disabled) return;
          box.checked = mode === "all" || (mode === "recommended" && box.defaultChecked);
          if (mode === "none") box.checked = false;
        });
        return;
      }
      // Real defect fixed here (owner-reported: "Promote" is not
      // understandable operator language). Renamed everywhere to
      // "Manage Client" -- the internal data-promote attribute/API path
      // are unchanged (they're not operator-visible), only the label,
      // prompt, and toast wording. The observedTable()/clientMini()
      // renderers already only ever show this button for a row with no
      // managed_client_id yet, so a click here can never target an
      // already-managed observed client -- no duplicate managed-client
      // creation is reachable from the UI, and promote() itself is
      // still idempotent server-side as a second line of defense.
      const promote = ev.target.closest("[data-promote]");
      if (promote) {
        const ip = promote.dataset.promote;
        const name = prompt(`Name for the managed client at ${ip}`, `Client ${ip}`);
        if (name) {
          await api(`/api/discovery/observed-clients/${encodeURIComponent(ip)}/promote`, { method: "POST", body: JSON.stringify({ display_name: name }) });
          toast("Client is now managed", "ok");
          // Reload wherever the operator actually is (Dashboard now has
          // its own Manage Client action, not just the Clients page)
          // rather than always redirecting to Clients.
          await loadPage(state.route);
        }
        return;
      }
      const forget = ev.target.closest("[data-forget]");
      if (forget && confirm(`Forget observed client ${forget.dataset.forget}?`)) {
        await api(`/api/discovery/observed-clients/${encodeURIComponent(forget.dataset.forget)}`, { method: "DELETE" });
        toast("Observed client forgotten", "ok");
        await loadPage(state.route);
        return;
      }
      const sync = ev.target.closest("[data-sync]");
      if (sync) {
        await api(`/api/replication/peers/${encodeURIComponent(sync.dataset.sync)}/sync`, { method: "POST" });
        toast("Synchronization completed", "ok");
        await loadPage("replication");
        return;
      }
      const backup = ev.target.closest("[data-backup]");
      if (backup) {
        const res = await api("/api/backup/secrets", { method: "POST" });
        await loadPage("backup");
        toast(`Encrypted backup created for ${res.secret_count} secrets`, "ok");
        return;
      }
      const validate = ev.target.closest("[data-validate-backup]");
      if (validate) {
        const name = validate.dataset.validateBackup;
        const res = await api(`/api/backup/secrets/${encodeURIComponent(name)}/validate`, { method: "POST" });
        await loadPage("backup");
        toast(`Backup ${res.backup_name} is valid (${res.secret_count} secrets)`, "ok");
        return;
      }
      const applianceBackup = ev.target.closest("[data-appliance-backup]");
      if (applianceBackup && !applianceBackup.closest('form[data-form="appliance-backup"]')) {
        const res = await api("/api/backup/appliance", { method: "POST" });
        await loadPage("backup");
        toast(`Appliance backup created (${res.contents.join(", ")})`, "ok");
        return;
      }
      const validateAppliance = ev.target.closest("[data-validate-appliance-backup]");
      if (validateAppliance) {
        const name = validateAppliance.dataset.validateApplianceBackup;
        const row = validateAppliance.closest("tr");
        const passphrase = row && row.querySelector('input[name="passphrase"]') ? row.querySelector('input[name="passphrase"]').value : "";
        const payload = passphrase ? { passphrase } : {};
        const res = await api(`/api/backup/appliance/${encodeURIComponent(name)}/validate`, { method: "POST", body: JSON.stringify(payload) });
        const previewRow = document.getElementById(backupPreviewId(name));
        if (previewRow) {
          previewRow.hidden = false;
          previewRow.querySelector("td").innerHTML = restorePreview(res);
        }
        toast(`Backup ${res.backup_name} preview is ready`, "ok");
        return;
      }
      const applyUpdate = ev.target.closest("[data-apply-update]");
      if (applyUpdate) {
        if (!confirm("Apply this update? The web service will restart automatically if the install succeeds.")) return;
        const id = applyUpdate.dataset.applyUpdate;
        await api(`/api/updates/jobs/${encodeURIComponent(id)}/apply`, { method: "POST" });
        toast("Update apply requested -- the appliance will reconnect automatically once it restarts", "ok");
        await waitForReconnectAfterUpdate();
        return;
      }
      const revokeSessions = ev.target.closest("[data-revoke-sessions]");
      if (revokeSessions) {
        if (!confirm("Sign out every other active session for your account?")) return;
        const res = await api("/api/session/revoke-others", { method: "POST" });
        toast(`${res.revoked_count} other session(s) revoked`, "ok");
        return;
      }
      const blRefresh = ev.target.closest("[data-blocklist-refresh]");
      if (blRefresh) {
        closeRowActionMenus();
        const id = blRefresh.dataset.blocklistRefresh;
        const res = await api(`/api/blocklists/${encodeURIComponent(id)}/refresh`, { method: "POST" });
        toast(`${id}: update queued`, "info");
        (async () => {
          const job = await waitBlocklistJob(res.job_id);
          if (state.route === "blocklists") await loadPage("blocklists");
          const result = job && job.results ? job.results[id] : null;
          toast(`${id}: ${result ? result.message : (job.error || job.status)}`, result && result.status === "succeeded" ? "ok" : "bad");
        })().catch((e) => toast(e.message, "bad"));
        return;
      }
      const blRefreshAll = ev.target.closest("[data-blocklist-refresh-all]");
      if (blRefreshAll) {
        const res = await api("/api/blocklists/refresh-all", { method: "POST" });
        if (!res.job_id) {
          toast(res.message || "No enabled blocklists", "info");
          return;
        }
        toast(`Updating ${res.count} blocklist source(s)`, "info");
        (async () => {
          const job = await waitBlocklistJob(res.job_id);
          if (state.route === "blocklists") await loadPage("blocklists");
          toast(`Update All ${job.status}`, job.status === "succeeded" ? "ok" : job.status === "partial" ? "warn" : "bad");
        })().catch((e) => toast(e.message, "bad"));
        return;
      }
      const blToggle = ev.target.closest("[data-blocklist-toggle]");
      if (blToggle) {
        closeRowActionMenus();
        const id = blToggle.dataset.blocklistToggle;
        await api(`/api/blocklists/${encodeURIComponent(id)}/toggle`, { method: "POST" });
        await loadPage("blocklists");
        toast("Subscription updated", "ok");
        return;
      }
      const blDelete = ev.target.closest("[data-blocklist-delete]");
      if (blDelete) {
        closeRowActionMenus();
        const id = blDelete.dataset.blocklistDelete;
        if (!confirm(`Delete subscription ${id}? Its domains will stop being blocked.`)) return;
        await api(`/api/blocklists/${encodeURIComponent(id)}`, { method: "DELETE" });
        await loadPage("blocklists");
        toast("Subscription deleted", "ok");
        return;
      }
      const blEdit = ev.target.closest("[data-blocklist-edit]");
      if (blEdit) {
        closeRowActionMenus();
        const id = blEdit.dataset.blocklistEdit.replace(/[^A-Za-z0-9_-]/g, "-");
        const row = document.getElementById(`blocklist-interval-${id}`);
        if (row) row.hidden = !row.hidden;
        return;
      }
      const uploadDelete = ev.target.closest("[data-delete-uploaded-archive]");
      if (uploadDelete) {
        const filename = uploadDelete.dataset.filename;
        const size = uploadDelete.dataset.size;
        if (!confirm(`Delete uploaded restore archive "${filename}" (${size} bytes)?`)) return;
        await api(`/api/backup/appliance/uploads/${encodeURIComponent(uploadDelete.dataset.deleteUploadedArchive)}`, { method: "DELETE" });
        await loadPage("backup");
        toast("Uploaded archive deleted", "ok");
        return;
      }
      const livePause = ev.target.closest("[data-action='dashboard-live-pause']");
      if (livePause) {
        state.dashboardLivePaused = !state.dashboardLivePaused;
        livePause.textContent = state.dashboardLivePaused ? "Resume" : "Pause";
        const status = document.querySelector("[data-live-status]");
        if (status) status.textContent = state.dashboardLivePaused ? "Paused" : "Reconnecting";
        return;
      }

      // Real owner-reported live defect fixed here: managed upstreams
      // could not be edited, disabled, or removed at all. Compact
      // per-row overflow menu (opens on plain click -- works for mouse,
      // keyboard Enter/Space on the real <button>, and touch alike;
      // never hover-only) plus real up/down reordering.
      const rowMenuToggle = ev.target.closest("[data-row-menu-toggle]");
      if (rowMenuToggle) {
        const wrap = rowMenuToggle.closest(".row-actions");
        const menu = wrap.querySelector(".row-actions__menu");
        const wasOpen = !menu.hidden;
        closeRowActionMenus();
        if (!wasOpen) openRowActionMenu(rowMenuToggle, menu);
        return;
      }
      const editUpstream = ev.target.closest("[data-edit-upstream]");
      if (editUpstream) {
        closeRowActionMenus();
        const id = editUpstream.dataset.editUpstream;
        const current = (await api("/api/upstreams")).upstreams.find((u) => u.upstream_profile_id === id);
        if (!current) return;
        const form = document.querySelector('form[data-form="upstream"]');
        form.dataset.editingId = id;
        form.elements.name.value = current.name;
        form.elements.transport.value = current.transport;
        form.elements.strategy.value = current.strategy;
        const ep = (current.endpoints || [])[0] || {};
        form.elements.address.value = ep.address || "";
        form.elements.tls_hostname.value = ep.tls_hostname || "";
        form.elements.doh_path.value = ep.doh_path || "";
        form.querySelector("[data-upstream-submit]").textContent = `Save changes to ${current.name}`;
        form.querySelector("[data-upstream-cancel-edit]").hidden = false;
        form.scrollIntoView({ behavior: "smooth", block: "center" });
        return;
      }
      const cancelEdit = ev.target.closest("[data-upstream-cancel-edit]");
      if (cancelEdit) {
        const form = cancelEdit.closest("form");
        delete form.dataset.editingId;
        form.reset();
        form.querySelector("[data-upstream-submit]").textContent = "Create upstream";
        cancelEdit.hidden = true;
        return;
      }
      const toggleUpstream = ev.target.closest("[data-toggle-upstream]");
      if (toggleUpstream) {
        closeRowActionMenus();
        const id = toggleUpstream.dataset.toggleUpstream;
        const currentlyEnabled = toggleUpstream.dataset.currentlyEnabled === "1";
        const action = currentlyEnabled ? "disable" : "enable";
        try {
          await api(`/api/upstreams/${encodeURIComponent(id)}/${action}`, { method: "POST" });
        } catch (err) {
          // Real owner-required workflow: disabling the FINAL enabled
          // managed upstream is refused once (409 last_enabled_upstream)
          // with a real warning; a real confirmation resubmits with
          // confirm_last -- never silently substituted for a different
          // resolver, and never a second, separate confirm() dialog
          // stacked on top of the server's own real rejection.
          if (err.status === 409 && err.body && err.body.error === "last_enabled_upstream") {
            if (!confirm(err.message)) return;
            await api(`/api/upstreams/${encodeURIComponent(id)}/disable`, { method: "POST", body: JSON.stringify({ confirm_last: true }) });
          } else {
            throw err;
          }
        }
        await loadPage("upstreams");
        toast(currentlyEnabled ? "Upstream disabled" : "Upstream enabled", "ok");
        return;
      }
      const deleteUpstream = ev.target.closest("[data-delete-upstream]");
      if (deleteUpstream) {
        closeRowActionMenus();
        const id = deleteUpstream.dataset.deleteUpstream;
        if (!confirm(`Delete upstream ${id}? This cannot be undone.`)) return;
        try {
          await api(`/api/upstreams/${encodeURIComponent(id)}`, { method: "DELETE" });
        } catch (err) {
          if (err.status === 409 && err.body && err.body.error === "last_enabled_upstream") {
            if (!confirm(err.message)) return;
            await api(`/api/upstreams/${encodeURIComponent(id)}`, { method: "DELETE", body: JSON.stringify({ confirm_last: true }) });
          } else {
            throw err;
          }
        }
        await loadPage("upstreams");
        toast("Upstream deleted", "ok");
        return;
      }
      const reorderUpstream = ev.target.closest("[data-reorder-upstream]");
      if (reorderUpstream) {
        const id = reorderUpstream.dataset.upstreamId;
        const direction = reorderUpstream.dataset.reorderUpstream;
        reorderUpstream.disabled = true;
        const current = (await api("/api/upstreams")).upstreams.map((u) => u.upstream_profile_id);
        const idx = current.indexOf(id);
        const swapWith = direction === "up" ? idx - 1 : idx + 1;
        if (swapWith < 0 || swapWith >= current.length) return;
        [current[idx], current[swapWith]] = [current[swapWith], current[idx]];
        const result = await api("/api/upstreams/reorder", { method: "POST", body: JSON.stringify({ ordered_upstream_profile_ids: current }) });
        const host = document.getElementById("upstreams-table-host");
        if (host && result.upstreams) host.innerHTML = upstreamsTable(result.upstreams);
        else await loadPage("upstreams");
        const moved = (result.upstreams || []).find((u) => u.upstream_profile_id === id);
        toast(moved ? `${moved.name} moved to display position ${moved.order}.` : "Upstream order saved", "ok");
        return;
      }
    });

    document.body.addEventListener("change", async (ev) => {
      const range = ev.target.closest("[data-action='dashboard-range']");
      if (range) { state.dashboardRangeMinutes = range.value === "live" ? "live" : Number(range.value); await loadPage("dashboard"); return; }
      const topMode = ev.target.closest("[data-action='dashboard-top-mode']");
      if (topMode) { state.dashboardTopMode = topMode.value; await loadPage("dashboard"); return; }
      const keepOpen = ev.target.closest("[data-action='nav-keep-multiple-open']");
      if (keepOpen) { setNavKeepMultipleOpen(keepOpen.checked); toast(keepOpen.checked ? "Multiple navigation sections can now stay open" : "Navigation sections now close each other (accordion)", "ok"); return; }
      const tsMode = ev.target.closest("[data-action='timestamp-display-mode']");
      if (tsMode) {
        setTimestampDisplayMode(tsMode.value);
        reformatVisibleTimestamps();
        // The dashboard activity chart's axis/tooltip labels are real
        // SVG text, not a simple [data-ts-utc] cell -- re-rendering the
        // current route (no browser navigation/reload, just this SPA's
        // normal in-place DOM replacement) picks up the new zone there
        // too, so no timestamp anywhere is left stale after a mode
        // switch.
        if (state.route === "dashboard") await loadPage("dashboard");
        return;
      }
      const sel = ev.target.closest("[data-import-type]");
      if (!sel) return;
      const type = sel.value;
      const form = sel.closest("form");
      const isApi = IMPORT_API_SOURCES.has(type);
      const isBinary = IMPORT_BINARY_SOURCES.has(type);
      const isPihole = type === "pihole";
      form.querySelector('[data-import-field="api"]').hidden = !isApi;
      form.querySelector('[data-import-field="file"]').hidden = isApi;
      form.querySelector('[data-import-field="text"]').hidden = !isPihole;
      if (isBinary) form.querySelector('[data-import-field="file"] input[type=file]').accept = ".xlsx";
    });

    document.body.addEventListener("submit", async (ev) => {
      const form = ev.target.closest("form[data-form]");
      if (!form) return;
      ev.preventDefault();
      await submitOnce(form, handleForm);
    });
  }

  async function handleForm(form) {
    const type = form.dataset.form;
    const body = jsonForm(form);
    if (type === "client") {
      const created = await api("/api/clients", { method: "POST", body: JSON.stringify({ name: body.name, description: body.description || "" }) });
      if (body.value) await api(`/api/clients/${created.client_id}/identifiers`, { method: "POST", body: JSON.stringify({ kind: body.kind, value: body.value }) });
      if (body.group_id) await api(`/api/clients/${created.client_id}/groups`, { method: "POST", body: JSON.stringify({ group_id: body.group_id }) });
    } else if (type === "policy") {
      const payload = {};
      for (const [k, v] of Object.entries(body)) {
        if (v === "") continue;
        payload[k] = v;
      }
      const scope = form.dataset.scope;
      const ref = form.dataset.ref;
      const path = scope === "global" ? "/api/policy/global" : `/api/policy/${scope}/${encodeURIComponent(ref)}`;
      await api(path, { method: "PUT", body: JSON.stringify(payload) });
    } else if (type === "network") {
      await api("/api/networks", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "group") {
      await api("/api/groups", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "explain") {
      // Real defect fixed here (root-caused via the browser harness under
      // rapid real-world navigation, priority 10 of the beta-rescue
      // brief): every "skip-reload" branch below writes its result
      // directly into a specific #id element rather than going through
      // loadPage()'s own stale-response guard (see loadToken). If the
      // operator navigates away before this fetch resolves, that element
      // no longer exists and the naive `.innerHTML = ...` throws
      // "Cannot set properties of null" -- silently surfaced to the user
      // only as a generic error toast, with no indication of what
      // actually happened. Every such write here is now null-guarded: if
      // the element is gone, the now-irrelevant result is simply dropped.
      const q = new URLSearchParams({ client_id: body.client_id });
      if (body.client_ip) q.set("client_ip", body.client_ip);
      const res = await api(`/api/policy/explain?${q}`);
      const explainTarget = document.getElementById("explain-result");
      if (explainTarget) explainTarget.innerHTML = `<pre class="mono">${esc(JSON.stringify(res, null, 2))}</pre>`;
      return "skip-reload";
    } else if (type === "querylog") {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(body)) {
        if (v === "" || v === null || v === undefined) continue;
        q.set(k, String(v));
      }
      const res = await api(`/api/analytics/query-log?${q}`);
      const activeTarget = document.getElementById("query-active");
      const resultsTarget = document.getElementById("query-results");
      if (activeTarget) activeTarget.innerHTML = activeFilters(res.filters || {});
      if (resultsTarget) resultsTarget.innerHTML = tableFromRows(res.rows || [], Number(body.limit || 100), res.columns, "query-log-results");
      return "skip-reload";
    } else if (type === "service") {
      // No service_id from the form -- the backend generates a stable id
      // from display_name (see _unique_id in app/v2/webapp.py).
      await api("/api/services", { method: "POST", body: JSON.stringify({ display_name: body.display_name, category: body.category || "", domains: body.domain ? [{ match_kind: body.match_kind, domain: body.domain }] : [] }) });
    } else if (type === "ruleset") {
      const selected = Array.from(form.elements.service_ids.selectedOptions).map((o) => o.value);
      await api("/api/service-rulesets", { method: "POST", body: JSON.stringify({ name: body.name, service_ids: selected }) });
    } else if (type === "schedule") {
      await api("/api/schedules", { method: "POST", body: JSON.stringify({ name: body.name, timezone: body.timezone || "UTC", windows: [{ start: body.start, end: body.end, weekdays: String(body.weekdays || "").split(",").map((x) => Number(x.trim())).filter((x) => Number.isInteger(x)) }] }) });
    } else if (type === "upstream") {
      const editingId = form.dataset.editingId;
      const payload = { name: body.name, transport: body.transport, strategy: body.strategy, endpoints: [{ address: body.address, tls_hostname: body.tls_hostname || null, doh_path: body.doh_path || null }] };
      if (editingId) {
        await api(`/api/upstreams/${encodeURIComponent(editingId)}`, { method: "PUT", body: JSON.stringify(payload) });
        delete form.dataset.editingId;
      } else {
        await api("/api/upstreams", { method: "POST", body: JSON.stringify(payload) });
      }
    } else if (type === "route") {
      await api("/api/domain-routing", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "localdns") {
      await api("/api/local-dns", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "peer") {
      await api(`/api/replication/peers/${encodeURIComponent(body.peer_node_id)}`, { method: "PUT", body: JSON.stringify(Object.assign({ authorized: true }, body)) });
    } else if (type === "migration") {
      const res = await api(`/api/migration/detect?source_path=${encodeURIComponent(body.source_path)}`);
      const migrationTarget = document.getElementById("migration-result");
      if (migrationTarget) migrationTarget.innerHTML = tableFromRows([res], 1);
      return "skip-reload";
    } else if (type === "restore") {
      const name = form.dataset.backupName;
      await api(`/api/backup/secrets/${encodeURIComponent(name)}/restore`, { method: "POST", body: JSON.stringify(body) });
    } else if (type === "appliance-backup") {
      if (!body.passphrase) throw new Error("enter a portable passphrase for cross-appliance backup export");
      const payload = {};
      payload.passphrase = body.passphrase;
      const res = await api("/api/backup/appliance", { method: "POST", body: JSON.stringify(payload) });
      toast(`Appliance backup created (${res.contents.join(", ")})`, "ok");
    } else if (type === "appliance-upload") {
      const fileInput = form.querySelector('input[type=file]');
      const file = fileInput && fileInput.files[0];
      if (!file) throw new Error("choose a native .apdnsbak or V1.1.1 .tar.gz backup to upload");
      const data_base64 = await fileToBase64(file);
      const payload = { filename: file.name, data_base64 };
      if (body.passphrase) payload.passphrase = body.passphrase;
      const res = await api("/api/backup/appliance/upload", { method: "POST", body: JSON.stringify(payload) });
      await loadPage("backup");
      const previewRow = document.getElementById(backupPreviewId(res.backup_name));
      if (previewRow) {
        previewRow.hidden = false;
        previewRow.querySelector("td").innerHTML = restorePreview(res);
      }
      toast(`Uploaded ${res.backup_name}; preview is ready`, "ok");
      return "skip-reload";
    } else if (type === "appliance-restore") {
      const name = form.dataset.backupName;
      body.selected_categories = Array.from(form.querySelectorAll('input[name="selected_categories"]:checked')).map((box) => box.value);
      body.acknowledge_sensitive = !!form.querySelector('input[name="acknowledge_sensitive"]:checked');
      if (!body.selected_categories.length) throw new Error("select at least one supported category to restore");
      const labels = body.selected_categories.join(", ");
      if (!confirm(`Restore selected categories from ${name}: ${labels}?`)) return "skip-reload";
      await api(`/api/backup/appliance/${encodeURIComponent(name)}/restore`, { method: "POST", body: JSON.stringify(body) });
    } else if (type === "dns-transports") {
      await api("/api/dns-transports", { method: "PUT", body: JSON.stringify(body) });
    } else if (type === "tls") {
      await api("/api/tls/replace", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "notification") {
      await api("/api/notifications", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "import-parse") {
      const sourceType = form.querySelector('[data-import-type]').value;
      const payload = { source_type: sourceType, source_name: body.source_name || "import", default_domain: body.default_domain || null };
      if (IMPORT_API_SOURCES.has(sourceType)) {
        Object.assign(payload, { base_url: body.base_url, username: body.username, password: body.password });
      } else if (sourceType === "pihole" && (body.text_paste || "").trim()) {
        payload.text = body.text_paste;
      } else {
        const fileInput = form.querySelector('input[type=file]');
        const file = fileInput && fileInput.files[0];
        if (!file) throw new Error("choose a file to import (or paste content for Pi-hole)");
        if (IMPORT_BINARY_SOURCES.has(sourceType)) {
          payload.data_base64 = await fileToBase64(file);
        } else {
          payload.text = await file.text();
        }
      }
      const res = await api("/api/import/jobs", { method: "POST", body: JSON.stringify(payload) });
      const panel = document.getElementById("import-preview-panel");
      const previewTarget = document.getElementById("import-preview");
      if (panel && previewTarget) {
        panel.hidden = false;
        previewTarget.innerHTML = importPlanPreview(res.job_id, res.plan);
        panel.scrollIntoView({ behavior: "smooth", block: "start" });
      }
      return "skip-reload";
    } else if (type === "import-apply") {
      const jobId = form.dataset.jobId;
      const skip = Array.from(document.querySelectorAll(`#import-preview input[data-skip-index]`))
        .filter((cb) => !cb.checked && !cb.disabled)
        .map((cb) => Number(cb.dataset.skipIndex));
      const res = await api(`/api/import/jobs/${encodeURIComponent(jobId)}/apply`, { method: "POST", body: JSON.stringify({ skip_indexes: skip }) });
      // Same ordering fix as submitOnce (priority 10): reload before
      // toast, so the toast is never visible while the jobs list is
      // still mid-refresh.
      await loadPage("importexport");
      toast(`Import applied: ${Object.entries(res.counts).map(([k, v]) => `${k}=${v}`).join(", ")}`, "ok");
      return "skip-reload";
    } else if (type === "logs-view") {
      const q = new URLSearchParams({ severity: body.severity || "all", lines: String(body.lines || 100) });
      const res = await api(`/api/logs/${encodeURIComponent(body.unit)}?${q}`);
      const target = document.getElementById("log-results");
      if (target) target.innerHTML = logEntriesTable(res.entries || []);
      return "skip-reload";
    } else if (type === "change-password") {
      await api("/api/session/password", { method: "POST", body: JSON.stringify({ current_password: body.current_password, new_password: body.new_password }) });
      form.reset();
    } else if (type === "statistics-clear") {
      const res = await api("/api/statistics/clear", { method: "POST", body: JSON.stringify(body) });
      toast(`Cleared ${res.aggregate_buckets_cleared} aggregate bucket(s), ${res.aggregate_dimension_rows_cleared} dimension row(s)${res.raw_history_cleared ? `, ${res.raw_partition_files_removed} raw history file(s)` : " (raw history kept)"}`, "ok");
    } else if (type === "blocklist-create") {
      await api("/api/blocklists", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "blocklist-settings") {
      await api("/api/blocklists/settings", { method: "POST", body: JSON.stringify({ default_interval_seconds: Number(body.default_interval_seconds) }) });
    } else if (type === "blocklist-interval") {
      const value = body.update_interval_seconds === "" || body.update_interval_seconds === undefined ? null : Number(body.update_interval_seconds);
      await api(`/api/blocklists/${encodeURIComponent(form.dataset.subscriptionId)}/interval`, { method: "POST", body: JSON.stringify({ update_interval_seconds: value }) });
    } else if (type === "uploaded-archive-settings") {
      await api("/api/backup/appliance/upload-settings", { method: "POST", body: JSON.stringify({ retention_seconds: Number(body.retention_seconds), remove_after_successful_restore: Boolean(body.remove_after_successful_restore) }) });
    } else if (type === "cache-flush") {
      const layer = form.dataset.layer;
      const payload = { layer };
      if (layer === "bind") {
        payload.scope = body.scope;
        payload.target = body.target || null;
        payload.context = form.dataset.context || null;
      }
      const res = await api("/api/cache/flush", { method: "POST", body: JSON.stringify(payload) });
      await loadPage("cache");
      toast(res.results.map((r) => `${r.context}: ${r.ok ? "ok" : "failed"} (${r.message})`).join("; "), res.results.every((r) => r.ok) ? "ok" : "bad");
      return "skip-reload";
    } else if (type === "network-apply") {
      if (!confirm("Apply this network configuration? Alderpoint DNS will automatically roll back if it is not confirmed within about 2 minutes.")) return "skip-reload";
      const payload = {
        interface: body.interface, ipv4_mode: body.ipv4_mode || "unchanged",
        ipv4_address: body.ipv4_address || null, ipv4_prefix: body.ipv4_prefix ? Number(body.ipv4_prefix) : null, ipv4_gateway: body.ipv4_gateway || null,
        ipv6_mode: body.ipv6_mode || "unchanged",
        ipv6_address: body.ipv6_address || null, ipv6_prefix: body.ipv6_prefix ? Number(body.ipv6_prefix) : null, ipv6_gateway: body.ipv6_gateway || null,
      };
      await api("/api/network/apply", { method: "POST", body: JSON.stringify(payload) });
      // Applying may change the browser's own route to this appliance
      // (a real address change), so the standard "wait for the network
      // to notice, then reconnect" flow -- not an immediate reload --
      // matches Software Update apply's own real-world-tested pattern.
      await waitForReconnect("network", "Network configuration change requested -- the appliance may become briefly unreachable while it applies");
      return "skip-reload";
    } else if (type === "network-confirm") {
      await api("/api/network/confirm", { method: "POST" });
      await loadPage("network");
      toast("Network configuration confirmed; automatic rollback cancelled", "ok");
      return "skip-reload";
    } else if (type === "update-settings") {
      await api("/api/updates/settings", { method: "PUT", body: JSON.stringify({ private_feed_dir: body.private_feed_dir || null }) });
    } else if (type === "update-upload") {
      const fileInput = form.querySelector('input[type=file]');
      const file = fileInput && fileInput.files[0];
      if (!file) throw new Error("choose a .deb package to upload");
      const data_base64 = await fileToBase64(file);
      await api("/api/updates/upload", { method: "POST", body: JSON.stringify({ filename: file.name, data_base64 }) });
    }
  }

  function fileToBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result).split(",", 2)[1] || "");
      reader.onerror = () => reject(reader.error || new Error("file read failed"));
      reader.readAsDataURL(file);
    });
  }

  // Collapsed-rail flyout dismissal: a click outside the open flyout, or
  // Escape, closes it. Kept separate from wire()'s single delegated click
  // handler (rather than folded into an early-return branch there) so it
  // runs regardless of which branch above handled the click, including
  // clicks on ordinary page content that none of wire()'s specific
  // `data-*` branches match.
  document.addEventListener("click", (ev) => {
    document.querySelectorAll(".nav-section.is-flyout-open").forEach((section) => {
      if (section.contains(ev.target)) return;
      section.classList.remove("is-flyout-open");
      const toggle = section.querySelector("[data-nav-section-toggle]");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    });
    // Compact row-action ("...") menus (owner-reported requirement:
    // one intentional overflow control per row instead of a pile of
    // buttons) -- same outside-click-closes contract as the nav
    // flyouts above.
    closeRowActionMenus(ev.target);
  });
  document.addEventListener("keydown", (ev) => {
    const openMenu = document.querySelector(".row-actions__menu:not([hidden])");
    if (openMenu && ["ArrowDown", "ArrowUp", "Home", "End"].includes(ev.key)) {
      const items = rowMenuItems(openMenu);
      if (!items.length) return;
      ev.preventDefault();
      const current = items.indexOf(document.activeElement);
      let next = current;
      if (ev.key === "ArrowDown") next = current < 0 ? 0 : (current + 1) % items.length;
      if (ev.key === "ArrowUp") next = current < 0 ? items.length - 1 : (current - 1 + items.length) % items.length;
      if (ev.key === "Home") next = 0;
      if (ev.key === "End") next = items.length - 1;
      items[next].focus();
      return;
    }
    if (ev.key !== "Escape") return;
    const open = document.querySelectorAll(".nav-section.is-flyout-open");
    open.forEach((section) => {
      section.classList.remove("is-flyout-open");
      const toggle = section.querySelector("[data-nav-section-toggle]");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    });
    closeRowActionMenus();
  });

  function closeRowActionMenus(exceptWithin) {
    document.querySelectorAll(".row-actions__menu:not([hidden])").forEach((menu) => {
      const wrap = menu.closest(".row-actions");
      if (exceptWithin && wrap && wrap.contains(exceptWithin)) return;
      menu.hidden = true;
      menu.style.left = "";
      menu.style.top = "";
      const trigger = wrap && wrap.querySelector("[data-row-menu-toggle]");
      if (trigger) trigger.setAttribute("aria-expanded", "false");
    });
  }

  function rowMenuItems(menu) {
    return [...menu.querySelectorAll('button[role="menuitem"]:not(:disabled)')];
  }

  function openRowActionMenu(trigger, menu) {
    menu.hidden = false;
    trigger.setAttribute("aria-expanded", "true");
    positionRowActionMenu(trigger, menu);
  }

  function positionRowActionMenu(trigger, menu) {
    const gap = 6;
    const rect = trigger.getBoundingClientRect();
    const width = menu.offsetWidth || 190;
    const height = menu.offsetHeight || 160;
    let left = Math.min(window.innerWidth - width - 8, Math.max(8, rect.right - width));
    let top = rect.bottom + gap;
    if (top + height > window.innerHeight - 8) top = Math.max(8, rect.top - height - gap);
    menu.style.left = `${Math.round(left)}px`;
    menu.style.top = `${Math.round(top)}px`;
  }

  document.addEventListener("scroll", () => closeRowActionMenus(), true);
  window.addEventListener("resize", () => closeRowActionMenus());

  boot();
}());
