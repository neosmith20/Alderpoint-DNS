(function () {
  "use strict";

  const state = {
    csrf: "",
    user: "",
    route: "dashboard",
    theme: localStorage.getItem("apdnsTheme") || "dark",
    navCollapsed: localStorage.getItem("apdnsNavCollapsed") === "1",
    cache: {},
    busy: new Set(),
  };

  // Grouping/order intentionally mirrors V1.1.1's information architecture
  // (docs/v2/... parity work, priority 1 of the beta-rescue brief) rather
  // than V2's prior ad hoc "Operations/Policy/DNS/System" split, which mixed
  // unrelated concerns (e.g. Replication and Backup living under the same
  // group as Dashboard) and gave the owner no stable mental model to
  // navigate by. Dashboard stays a standalone top-level item, matching V1.
  // IA split (owner RC45 finding, priority 1 of the second beta-rescue
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
    ["DNS", "analytics", "Query Log", "Q"],
    ["DNS", "clients", "Clients", "C"],
    ["DNS", "policies", "Clients & Access", "P"],
    ["DNS", "localdns", "Local DNS", "L"],
    ["DNS", "upstreams", "DNS Settings", "U"],
    ["DNS", "cache", "Cache", "K"],
    ["Security", "filtering", "Filters", "F"],
    ["Security", "blocklists", "Blocklists", "X"],
    ["Security", "encryption", "Encryption", "E"],
    ["Operations", "importexport", "Import", "I"],
    ["Operations", "backup", "Backup & Restore", "B"],
    ["Operations", "replication", "Replication", "R"],
    ["System", "statistics", "Statistics", "T"],
    ["System", "health", "System Status", "Y"],
    ["System", "administration", "Administration", "A"],
    ["System", "network", "Network Configuration", "W"],
    ["System", "notifications", "Notifications", "N"],
    ["System", "updates", "Software Updates", "V"],
    ["System", "logs", "Logs", "G"],
  ];
  const GROUP_ORDER = ["DNS", "Security", "Operations", "System"];

  // Real per-section expand/collapse state (owner RC45 finding, priority
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

  function pretty(value) {
    if (value === null || value === undefined || value === "") return '<span class="badge inherit">inherit</span>';
    if (typeof value === "boolean") return value ? '<span class="badge ok">enabled</span>' : '<span class="badge warn">disabled</span>';
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

  async function api(path, options) {
    const opts = Object.assign({ credentials: "same-origin", headers: {} }, options || {});
    opts.headers = Object.assign({ "Accept": "application/json" }, opts.headers || {});
    if (opts.body && !(opts.body instanceof FormData)) opts.headers["Content-Type"] = "application/json";
    if (!/^(GET|HEAD)$/i.test(opts.method || "GET")) opts.headers["X-CSRF-Token"] = state.csrf;
    const res = await fetch(path, opts);
    let body = null;
    const text = await res.text();
    try { body = text ? JSON.parse(text) : null; } catch (_) { body = { error: "invalid_json", detail: text.slice(0, 240) }; }
    if (!res.ok) {
      const detail = body && (body.detail || body.error) ? `${body.error || "error"}: ${body.detail || ""}` : `HTTP ${res.status}`;
      const err = new Error(detail);
      err.status = res.status;
      err.body = body;
      throw err;
    }
    return body || {};
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
    const dashboardBtn = `<button data-route="dashboard" class="nav-top ${state.route === "dashboard" ? "active" : ""}"><span class="glyph">#</span><span>Dashboard</span></button>`;
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
                <button type="button" class="nav-section__toggle" data-nav-section-toggle aria-expanded="${open}" aria-controls="${panelId}" ${activeInGroup ? 'aria-current="true"' : ""}>
                  <span class="glyph">${activeInGroup ? "*" : "-"}</span>
                  <span class="nav-section__label">${esc(group)}</span>
                  <span class="nav-section__chevron" aria-hidden="true">${open ? "▾" : "▸"}</span>
                </button>
                <div class="nav-section__panel" id="${panelId}" ${open ? "" : "hidden"}>
                  ${items.map(([, id, label, glyph]) => `<button data-route="${id}" class="nav-subitem${state.route === id ? " active" : ""}" title="${esc(label)}" ${state.route === id ? 'aria-current="page"' : ""}><span class="glyph">${esc(glyph)}</span><span>${esc(label)}</span></button>`).join("")}
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
    return { health, system, replication, discovery };
  }

  async function dashboard() {
    const [c, recent, top, clients, observed, upstreams] = await Promise.all([
      common(),
      api("/api/analytics/recent?minutes=60").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
      api("/api/analytics/top-domains?minutes=60&limit=10").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
      api("/api/clients").catch(() => ({ clients: [] })),
      // Owner RC45 finding, priority 3 of the second beta-rescue pass: a
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
    const countIdx = (top.columns || []).indexOf("count");
    const bars = (top.rows || []).slice(0, 10).map((r) => Number(countIdx === -1 ? 1 : r[countIdx]) || 1);
    const max = Math.max(1, ...bars);
    return page("Dashboard", "Operational state from the real V2 HTTPS APIs.", `<button data-refresh>Refresh</button>`, `
      <div class="strip">
        <div class="metric"><strong>${esc(c.health.status || "unknown")}</strong><span>Management / runtime status</span></div>
        <div class="metric"><strong>${rows.length}</strong><span>Recent query rows</span></div>
        <div class="metric"><strong>${blocked}</strong><span>Blocked signals in recent rows</span></div>
        <div class="metric"><strong>${esc(c.discovery.observed_count ?? 0)}</strong><span>Observed clients</span></div>
        <div class="metric"><strong>${esc((c.replication.peers || []).length)}</strong><span>Replication peers</span></div>
      </div>
      ${recent.degraded ? `<div class="alert warn">Analytics degraded: ${esc(recent.degraded_reason || "query data unavailable")}. DNS status is reported separately.</div>` : ""}
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Top Domains</h2><span class="badge ${top.degraded ? "warn" : "ok"}">${top.degraded ? "degraded" : "live"}</span></div><div class="panel__body">${chart(bars, max)}${tableFromRows(top.rows || [], 6, top.columns)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Runtime Components</h2></div><div class="panel__body">${componentList(c.health.components || {})}</div></section>
        <section class="panel"><div class="panel__head"><h2>Clients</h2><button class="link" data-route="clients">Manage</button></div><div class="panel__body">${clientMini(clients.clients || [], observed.items || observed.observed_clients || observed.clients || [])}</div></section>
        <section class="panel"><div class="panel__head"><h2>Upstreams</h2></div><div class="panel__body">${upstreams.upstreams?.length ? tableFromRows(upstreams.upstreams, 5) : `<div class="empty">No upstream profiles configured.</div>`}</div></section>
      </div>`);
  }

  function chart(values, max) {
    if (!values.length) return `<div class="empty">No chartable data in this window.</div>`;
    return `<div class="chart" aria-label="Top-domain activity bars">${values.map((v) => `<div class="bar" style="height:${Math.max(6, Math.round(v / max * 155))}px" title="${esc(v)}"></div>`).join("")}</div>`;
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
  function tableFromRows(rows, limit, columns) {
    let list = rows.slice(0, limit || 50);
    if (columns && columns.length) {
      list = list.map((r) => Object.fromEntries(columns.map((c, i) => [c, r[i]])));
    }
    if (!list.length) return `<div class="empty">No records.</div>`;
    const cols = Object.keys(list[0]).slice(0, 8);
    return `<div class="table-wrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${list.map((r) => `<tr>${cols.map((c) => `<td class="truncate" title="${esc(r[c])}">${pretty(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  // Owner RC45 finding, priority 3 of the second beta-rescue pass: shows
  // both MANAGED clients (explicit operator-created records) and
  // ACTIVE/OBSERVED clients (real DNS activity seen via the real,
  // asynchronous discovery pipeline -- never synchronously in the DNS
  // hot path) so a fresh appliance with real traffic and zero managed
  // clients shows the truth ("a real device is querying this
  // appliance") instead of "No managed clients." Observed rows carry
  // the same one-click Promote action as the full Clients page (wired
  // globally in wire()'s [data-promote] handler).
  function clientMini(managed, observed) {
    if (!managed.length && !observed.length) return `<div class="empty">No managed clients, and no DNS activity observed yet.</div>`;
    const managedRows = managed.slice(0, 5).map((c) => `<tr><td><span class="badge ok">managed</span></td><td>${esc(c.name)}</td><td>${(c.identifiers || []).map((i) => `<span class="badge">${esc(i.value)}</span>`).join(" ") || '<span class="muted">none</span>'}</td><td></td></tr>`).join("");
    const observedRows = observed.slice(0, 5).filter((o) => !o.managed_client_id).map((o) => `<tr><td><span class="badge inherit">observed</span></td><td class="mono">${esc(o.hostname_candidate || o.source_ip)}</td><td class="mono">${esc(o.source_ip)}<span class="muted"> -- ${esc(o.query_count || o.observation_count || 0)} queries</span></td><td><button data-promote="${esc(o.source_ip)}">Promote</button></td></tr>`).join("");
    if (!managedRows && !observedRows) return `<div class="empty">No managed clients, and no DNS activity observed yet.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>State</th><th>Name / hostname</th><th>Identifier</th><th></th></tr></thead><tbody>${managedRows}${observedRows}</tbody></table></div>`;
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
        <section class="panel"><div class="panel__head"><h2>Recent Queries</h2><span class="badge">${recent.rows.length} rows</span></div><div class="panel__body">${queryFilters()}<div id="query-active">${activeFilters(recent.filters || {})}</div><div id="query-results">${tableFromRows(recent.rows || [], 100, recent.columns)}</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Top Domains</h2></div><div class="panel__body">${tableFromRows(top.rows || [], 30, top.columns)}</div></section>
      </div>`);
  }

  // Statistics is its own destination (owner RC45 finding: it was
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
    return page("Clients", "Managed clients and DNS-observed addresses stay distinct until explicit promotion.", `<button data-refresh>Refresh</button>`, `
      <div class="strip">
        <div class="metric"><strong>${managed.clients.length}</strong><span>Managed</span></div>
        <div class="metric"><strong>${dstat.observed_count ?? (observed.items || observed.observed_clients || []).length}</strong><span>Observed</span></div>
        <div class="metric"><strong>${dstat.evictions ?? 0}</strong><span>Discovery evictions</span></div>
        <div class="metric"><strong>${dstat.dropped_observations ?? 0}</strong><span>Dropped observations</span></div>
      </div>
      <div class="split">
        <div class="grid">
          <section class="panel"><div class="panel__head"><h2>Observed Clients</h2></div><div class="panel__body">${observedTable(observed.items || observed.observed_clients || observed.clients || [])}</div></section>
          <section class="panel"><div class="panel__head"><h2>Managed Clients</h2></div><div class="panel__body">${managedTable(managed.clients)}</div></section>
        </div>
        <aside class="panel drawer"><div class="panel__head"><h2>Create Managed Client</h2></div><div class="panel__body">${clientForm(groups.groups || [])}</div></aside>
      </div>`);
  }

  function observedTable(items) {
    if (!items.length) return `<div class="empty">No observed clients yet. Real DNS packets populate this asynchronously.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>IP</th><th>Hostname</th><th>First / Last seen</th><th>Queries</th><th>Association</th><th>Actions</th></tr></thead><tbody>${items.map((o) => `
      <tr><td class="mono">${esc(o.source_ip)}</td><td>${esc(o.hostname_candidate || "")}<br><span class="muted">${esc(o.hostname_source || "")}</span></td><td>${esc(o.first_seen || "")}<br>${esc(o.last_seen || "")}</td><td>${esc(o.query_count || o.observation_count || 0)}</td><td>${o.managed_client_id ? `<span class="badge ok">client ${esc(o.managed_client_id)}</span>` : `<span class="badge inherit">unmanaged</span>`}</td><td class="field-row"><button data-promote="${esc(o.source_ip)}">Promote</button><button class="danger" data-forget="${esc(o.source_ip)}">Forget</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  function managedTable(items) {
    if (!items.length) return `<div class="empty">No managed clients.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>ID</th><th>Name</th><th>Identifiers</th><th>Groups</th><th>Policy</th><th>Actions</th></tr></thead><tbody>${items.map((c) => `
      <tr><td>${c.id}</td><td>${esc(c.name)}<br><span class="muted">${esc(c.description)}</span></td><td>${(c.identifiers || []).map((i) => `<span class="badge">${esc(i.kind)} ${esc(i.value)}</span>`).join(" ")}</td><td>${(c.groups || []).map((g) => `<span class="badge info">${esc(g.name)}</span>`).join(" ")}</td><td>${policySummary(c.policy)}</td><td><button data-explain-client="${c.id}">Explain</button></td></tr>`).join("")}</tbody></table></div>`;
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
      <label>Client<select name="client_id">${clients.map((c) => `<option value="${c.id}">${esc(c.name)} (#${c.id})</option>`).join("")}</select></label>
      <label>Client IP<input name="client_ip" placeholder="optional"></label>
      <button class="primary">Explain effective policy</button>
      <div id="explain-result" class="alert">Select a client to inspect global, network, group, client, schedule, filtering, upstream, ECS, and cache contributions.</div>
    </form>`;
  }

  async function filtering() {
    const [services, rulesets, schedules, global] = await Promise.all([api("/api/services"), api("/api/service-rulesets"), api("/api/schedules"), api("/api/policy/global")]);
    return page("Filtering / Security", "SafeSearch, parental filtering, security filtering, service blocking, schedules, and response modes remain separate controls.", "", `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Global Answer Policy</h2></div><div class="panel__body">${policyEditor("global", "singleton", global.policy)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Service Catalog</h2></div><div class="panel__body">${serviceForm()}${serviceTable(services.services)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Service Rulesets</h2></div><div class="panel__body">${rulesetForm(services.services)}${tableFromRows(rulesets.rulesets, 20)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Schedules</h2></div><div class="panel__body">${scheduleForm()}${tableFromRows(schedules.schedules, 20)}</div></section>
      </div>`);
  }

  function serviceForm() {
    return `<form data-form="service"><div class="form-grid"><label>Display name<input name="display_name" required placeholder="TikTok"></label><label>Category<input name="category"></label><label>Domain<input name="domain" placeholder="example.com"></label><label>Match<select name="match_kind"><option>suffix</option><option>exact</option></select></label></div><button>Create service</button></form>`;
  }

  function serviceTable(services) {
    if (!services.length) return `<div class="empty">No service definitions.</div>`;
    return `<div style="margin-top:12px">${tableFromRows(services, 50)}</div>`;
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
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Upstream Profiles</h2></div><div class="panel__body">${upstreamForm()}${tableFromRows(ups.upstreams, 50)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Domain Routes</h2></div><div class="panel__body">${routeForm(ups.upstreams)}${tableFromRows(routes.routes, 50)}</div></section>
      </div>`);
  }

  function upstreamForm() {
    return `<form data-form="upstream"><div class="form-grid"><label>Name<input name="name" required placeholder="Cloudflare"></label><label>Transport<select name="transport"><option>plain</option><option>dot</option><option>doh</option></select></label><label>Strategy<select name="strategy"><option>ordered</option><option>failover</option><option>load_balanced</option></select></label><label>Address<input name="address" required placeholder="1.1.1.1:53"></label><label>TLS hostname<input name="tls_hostname" placeholder="cloudflare-dns.com"></label><label>DoH path<input name="doh_path" placeholder="/dns-query"></label></div><button>Create upstream</button></form>`;
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
      <div class="split"><section class="panel"><div class="panel__head"><h2>Records</h2></div><div class="panel__body">${tableFromRows(records.records, 200)}</div></section><aside class="panel drawer"><div class="panel__head"><h2>Add Record</h2></div><div class="panel__body">${localDnsForm()}</div></aside></div>`);
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
    return `<div class="table-wrap"><table><thead><tr><th>Peer</th><th>URL</th><th>Auth</th><th>Sync</th><th>Error</th><th>Actions</th></tr></thead><tbody>${peers.map((p) => `<tr><td class="mono">${esc(p.peer_node_id)}</td><td>${esc(p.url)}</td><td><span class="badge ${p.authorized ? "ok" : "bad"}">${p.authorized ? "authorized" : "disabled"}</span></td><td>last success ${esc(p.last_success_at || "never")}<br>lag ${esc(p.lag ?? "")}</td><td>${esc(p.last_error || "")}</td><td><button data-sync="${esc(p.peer_node_id)}">Sync</button></td></tr>`).join("")}</tbody></table></div>`;
  }

  function peerForm() {
    return `<form data-form="peer"><label>Peer's node identity<input name="peer_node_id" required placeholder="from the peer's own Node Identity panel"></label><label>Display name<input name="display_name" placeholder="Backup site"></label><label>URL<input name="url" required placeholder="https://10.0.0.2:9443/replication/v1/apply"></label><label>Expected cert SHA-256<input name="expected_cert_sha256" required minlength="64" maxlength="64"></label><label>Trusted CA PEM<textarea name="ca_pem" required></textarea></label><label>Client certificate PEM<textarea name="client_cert_pem"></textarea></label><label>Client key PEM<textarea name="client_key_pem"></textarea></label><label>Direction<select name="direction"><option>bidirectional</option><option>push</option><option>pull</option></select></label><button class="primary">Save peer</button></form>`;
  }

  async function backup() {
    const [applianceBackups, backups, migration] = await Promise.all([
      api("/api/backup/appliance").catch((e) => ({ backups: [], restore_jobs: [], error: e.message })),
      api("/api/backup/secrets").catch((e) => ({ backups: [], restore_jobs: [], error: e.message })),
      api("/api/migration/detect?source_path=/var/lib/alderpointdns/alderpointdns.db").catch((e) => ({ error: e.message })),
    ]);
    return page("Backup / Restore / Migration", "Safe entry points for backup and migration preview. Opening this page does not start destructive work.", "", `
      <section class="panel"><div class="panel__head"><h2>Appliance Backup / Restore</h2></div><div class="panel__body">
        <p class="muted">A full encrypted snapshot: control database (clients, groups, networks, policies, filtering, Local DNS, upstream profiles, domain routing, schedules, DNS-transport/encryption settings, notifications, replication identity/peers), protected secrets, and the active HTTPS/DNSCrypt certificates. Raw query history is never included -- control.db cannot hold it. Restore is staged and validated before anything live changes, and the prior appliance state is snapshotted first so a failed restore leaves it untouched.</p>
        <button data-appliance-backup class="primary">Create appliance backup</button>
        ${applianceBackupTable(applianceBackups.backups || [])}
        ${restoreJobs(applianceBackups.restore_jobs || [])}
      </div></section>
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Secret Backup / Restore</h2></div><div class="panel__body"><p class="muted">One component of the appliance backup above, also available standalone: encrypted protected secrets only. Secret values are never displayed.</p><button data-backup class="primary">Create secret-only backup</button>${backupTable(backups.backups || [])}${restoreJobs(backups.restore_jobs || [])}</div></section>
        <section class="panel"><div class="panel__head"><h2>Migration Detection</h2></div><div class="panel__body">${migration.error ? `<div class="alert warn">${esc(migration.error)}</div>` : tableFromRows([migration], 1)}<form data-form="migration"><label>Source path<input name="source_path" value="/var/lib/alderpointdns/alderpointdns.db"></label><button>Detect source</button></form><div id="migration-result"></div></div></section>
      </div>`);
  }

  function applianceBackupTable(backups) {
    if (!backups.length) return `<div class="empty">No appliance backups.</div>`;
    return `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th><th>Restore</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${esc(b.created_at)}</td><td>${esc(b.size_bytes)}</td><td><button data-validate-appliance-backup="${esc(b.name)}">Validate</button><form data-form="appliance-restore" data-backup-name="${esc(b.name)}" class="field-row"><input name="confirmation" placeholder="type exact file name"><button class="danger">Restore</button></form></td></tr>`).join("")}</tbody></table></div>`;
  }

  function backupTable(backups) {
    if (!backups.length) return `<div class="empty">No encrypted secret backups.</div>`;
    return `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th><th>Restore</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${esc(b.created_at)}</td><td>${esc(b.size_bytes)}</td><td><button data-validate-backup="${esc(b.name)}">Validate</button><form data-form="restore" data-backup-name="${esc(b.name)}" class="field-row"><input name="confirmation" placeholder="type exact file name"><select name="overwrite" data-bool="1"><option value="false">no overwrite</option><option value="true">overwrite</option></select><button class="danger">Restore</button></form></td></tr>`).join("")}</tbody></table></div>`;
  }

  function restoreJobs(jobs) {
    if (!jobs.length) return `<div class="muted" style="margin-top:12px">No restore jobs recorded.</div>`;
    return `<div style="margin-top:12px"><h3>Restore Status</h3>${tableFromRows(jobs, 20)}</div>`;
  }

  // Encryption and Notifications are now two separate destinations
  // (owner RC45 finding, priority 1 of the second beta-rescue pass: they
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
      <section class="panel"><div class="panel__head"><h2>Providers</h2></div><div class="panel__body">${tableFromRows(data.providers || [], 50)}${notificationForm()}</div></section>`);
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

  // Administration and Logs are now their own destinations (owner RC45
  // finding, priority 1 of the second beta-rescue pass: Administration
  // was buried inside System Status, which is really about DNS/runtime
  // component health -- an unrelated concern from changing your own
  // password). Matches V1.1.1's own separate administration.html /
  // system_logs_results.html templates.
  async function health() {
    const [h, s, n, d] = await Promise.all([api("/api/health"), api("/api/system/status"), api("/api/node-identity"), api("/api/discovery/status")]);
    return page("System Status", "Operational status separates DNS/runtime health from optional subsystem degradation.", `<button data-refresh>Refresh</button>`, `
      <div class="strip"><div class="metric"><strong>${esc(h.status)}</strong><span>Overall</span></div><div class="metric"><strong>${esc(s.version)}</strong><span>Version</span></div><div class="metric"><strong>${s.compiled_runtime_present ? "yes" : "no"}</strong><span>Compiled runtime</span></div><div class="metric"><strong>${esc(d.observed_count ?? 0)}</strong><span>Observed clients</span></div></div>
      <div class="grid two"><section class="panel"><div class="panel__head"><h2>Components</h2></div><div class="panel__body">${componentList(h.components || {})}</div></section><section class="panel"><div class="panel__head"><h2>Node Identity</h2></div><div class="panel__body">${tableFromRows([n], 1)}</div></section></div>`);
  }

  async function administration() {
    return page("Administration", "Your own account and session controls.", "", `
      <section class="panel"><div class="panel__head"><h2>Account</h2></div><div class="panel__body"><div class="grid two">
        <form data-form="change-password"><label>Current password<input name="current_password" type="password" autocomplete="current-password" required></label><label>New password (min. 12 characters)<input name="new_password" type="password" autocomplete="new-password" minlength="12" required></label><button class="primary">Change password</button></form>
        <div><p class="muted">Signs out every other active session for your account (not this one). Use after a shared/compromised session.</p><button data-revoke-sessions class="danger">Revoke other sessions</button></div>
      </div></div></section>`);
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
    const rows = (data.subscriptions || []).map((s) => `
      <tr>
        <td>${esc(s.name)}<br><span class="muted mono">${esc(s.subscription_id)}</span></td>
        <td class="truncate" title="${esc(s.url)}">${esc(s.url)}</td>
        <td><span class="badge ${s.enabled ? "ok" : "inherit"}">${s.enabled ? "enabled" : "disabled"}</span></td>
        <td><span class="badge ${tone(s.last_status)}">${esc(s.last_status)}</span>${s.last_error ? `<br><span class="muted">${esc(s.last_error)}</span>` : ""}</td>
        <td>${esc(s.rule_count)}</td>
        <td>${esc(s.last_refresh_at || "never")}</td>
        <td class="field-row">
          <button data-blocklist-refresh="${esc(s.subscription_id)}">Refresh</button>
          <button data-blocklist-toggle="${esc(s.subscription_id)}">${s.enabled ? "Disable" : "Enable"}</button>
          <button data-blocklist-delete="${esc(s.subscription_id)}" class="danger">Delete</button>
        </td>
      </tr>`).join("");
    return page("Blocklists", "Subscribed, refreshable domain-block feeds. A failed refresh keeps the previous valid list enforced -- it never clears filtering on error. Refreshed automatically every 24h, or on demand below.", `<button data-refresh>Refresh page</button>`, `
      <section class="panel"><div class="panel__head"><h2>Subscriptions</h2></div><div class="panel__body">
        ${(data.subscriptions || []).length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>URL</th><th>Enabled</th><th>Last status</th><th>Rules</th><th>Last refresh</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>` : `<div class="empty">No blocklist subscriptions yet.</div>`}
      </div></section>
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
    const row = (label, value) => `<tr><td>${esc(label)}</td><td class="mono">${esc(value ?? "unknown")}</td></tr>`;
    const changeForm = current.backend && current.backend !== "unsupported" && !pending ? `
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
          ${current.ambiguous ? `<p class="alert error">Multiple networking backends appear active on this host. Settings are shown read-only until this is resolved.</p>` : ""}
        </section>
        <section class="panel"><div class="panel__head"><h2>Active Interface</h2></div><div class="panel__body"><p class="mono">${esc(current.interface || "none detected")}</p></section>
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
      <tr><td>${j.id}</td><td>${esc(j.source_type)}</td><td>${esc(j.source_name)}</td><td><span class="badge ${tone(j.status)}">${esc(j.status)}</span></td><td>${esc((j.plan || {}).item_count ?? "")}</td><td>${esc(j.created_at || "")}</td></tr>`).join("")}</tbody></table></div>`;
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
      <tr><td>${j.id}</td><td><span class="badge ${tone(j.status)}">${esc(j.status)}</span></td><td>${esc(j.detail.candidate_version || "")}</td><td>${esc(j.started_at || "")}</td><td>${esc(j.finished_at || "")}</td><td>${j.status === "staged" ? `<button data-apply-update="${j.id}" class="danger">Apply</button>` : ""}${j.detail.apply_result && j.detail.apply_result.error ? `<span class="muted">${esc(j.detail.apply_result.error)}</span>` : ""}</td></tr>`).join("")}</tbody></table></div>`;
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
  async function loadPage(id) {
    const requested = id || "dashboard";
    const token = ++loadToken;
    state.route = requested;
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
    document.querySelectorAll("[data-nav-section]").forEach((section) => {
      const inSection = section.querySelector(`[data-route="${CSS.escape(requested)}"]`);
      section.classList.toggle("is-active", !!inSection);
      if (!inSection) return;
      const toggle = section.querySelector("[data-nav-section-toggle]");
      const panel = document.getElementById(toggle.getAttribute("aria-controls"));
      toggle.setAttribute("aria-expanded", "true");
      toggle.setAttribute("aria-current", "true");
      panel.hidden = false;
      const chevron = toggle.querySelector(".nav-section__chevron");
      if (chevron) chevron.textContent = "▾";
      setNavSectionOpen(section.getAttribute("data-nav-section"), true);
    });
    const target = document.getElementById("page");
    target.innerHTML = page("Loading", "Fetching live appliance state.", "", `<div class="empty">Loading...</div>`);
    try {
      const html = await renderers[requested]();
      if (token !== loadToken) return;
      target.innerHTML = html;
      history.replaceState(null, "", `/ui/${requested}`);
    } catch (err) {
      if (token !== loadToken) return;
      if (err.status === 401) return boot();
      target.innerHTML = page("Page unavailable", "The backend rejected or failed this request.", `<button data-refresh>Retry</button>`, `<div class="alert bad">${esc(err.message)}</div>`);
    }
  }

  function authScreen(setupRequired) {
    // Owner-approved removal of RC42's mandatory SSH-retrieved setup-
    // token flow: first-run setup is still "create the first administrator
    // right here" -- no token field, no instruction to go retrieve a
    // secret from the appliance's state directory. But the RC45 owner
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
      await loadPage(location.pathname.startsWith("/ui/") ? location.pathname.slice(4) || "dashboard" : "dashboard");
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
    // Client-side mismatch feedback (owner RC45 finding, priority 2):
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

  function wire() {
    document.body.addEventListener("click", async (ev) => {
      const route = ev.target.closest("[data-route]");
      if (route) { document.body.classList.remove("nav-open"); await loadPage(route.dataset.route); return; }
      if (ev.target.closest("[data-action='menu']")) { document.body.classList.toggle("nav-open"); return; }
      if (ev.target.closest("[data-action='theme']")) { setTheme(state.theme === "dark" ? "light" : "dark"); renderShell(); await loadPage(state.route); return; }
      if (ev.target.closest("[data-action='collapse']")) { state.navCollapsed = !state.navCollapsed; localStorage.setItem("apdnsNavCollapsed", state.navCollapsed ? "1" : "0"); renderShell(); await loadPage(state.route); return; }
      const sectionToggle = ev.target.closest("[data-nav-section-toggle]");
      if (sectionToggle) {
        const section = sectionToggle.closest("[data-nav-section]");
        const group = section && section.getAttribute("data-nav-section");
        const open = sectionToggle.getAttribute("aria-expanded") !== "true";
        if (group) setNavSectionOpen(group, open);
        renderShell();
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
      const promote = ev.target.closest("[data-promote]");
      if (promote) {
        const ip = promote.dataset.promote;
        const name = prompt(`Managed client name for ${ip}`, `Client ${ip}`);
        if (name) {
          await api(`/api/discovery/observed-clients/${encodeURIComponent(ip)}/promote`, { method: "POST", body: JSON.stringify({ display_name: name }) });
          toast("Observed client promoted", "ok");
          // Reload wherever the operator actually is (Dashboard now has
          // its own promote action, not just the Clients page) rather
          // than always redirecting to Clients.
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
      if (applianceBackup) {
        const res = await api("/api/backup/appliance", { method: "POST" });
        await loadPage("backup");
        toast(`Appliance backup created (${res.contents.join(", ")})`, "ok");
        return;
      }
      const validateAppliance = ev.target.closest("[data-validate-appliance-backup]");
      if (validateAppliance) {
        const name = validateAppliance.dataset.validateApplianceBackup;
        const res = await api(`/api/backup/appliance/${encodeURIComponent(name)}/validate`, { method: "POST" });
        await loadPage("backup");
        toast(`Backup ${res.backup_name} is valid (${res.contents.join(", ")})`, "ok");
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
        const id = blRefresh.dataset.blocklistRefresh;
        const res = await api(`/api/blocklists/${encodeURIComponent(id)}/refresh`, { method: "POST" });
        await loadPage("blocklists");
        toast(`${id}: ${res.message}`, res.status === "succeeded" ? "ok" : "bad");
        return;
      }
      const blToggle = ev.target.closest("[data-blocklist-toggle]");
      if (blToggle) {
        const id = blToggle.dataset.blocklistToggle;
        await api(`/api/blocklists/${encodeURIComponent(id)}/toggle`, { method: "POST" });
        await loadPage("blocklists");
        toast("Subscription updated", "ok");
        return;
      }
      const blDelete = ev.target.closest("[data-blocklist-delete]");
      if (blDelete) {
        const id = blDelete.dataset.blocklistDelete;
        if (!confirm(`Delete subscription ${id}? Its domains will stop being blocked.`)) return;
        await api(`/api/blocklists/${encodeURIComponent(id)}`, { method: "DELETE" });
        await loadPage("blocklists");
        toast("Subscription deleted", "ok");
        return;
      }
    });

    document.body.addEventListener("change", (ev) => {
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
      if (resultsTarget) resultsTarget.innerHTML = tableFromRows(res.rows || [], Number(body.limit || 100), res.columns);
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
      await api("/api/upstreams", { method: "POST", body: JSON.stringify({ name: body.name, transport: body.transport, strategy: body.strategy, endpoints: [{ address: body.address, tls_hostname: body.tls_hostname || null, doh_path: body.doh_path || null }] }) });
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
    } else if (type === "appliance-restore") {
      const name = form.dataset.backupName;
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

  boot();
}());
