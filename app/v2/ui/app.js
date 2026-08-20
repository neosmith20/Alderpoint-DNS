(function () {
  "use strict";

  const state = {
    csrf: "",
    user: "",
    route: "dashboard",
    theme: localStorage.getItem("apdnsTheme") || "dark",
    cache: {},
    busy: new Set(),
  };

  const pages = [
    ["Operations", "dashboard", "Dashboard", "#"],
    ["Operations", "analytics", "Query Log / Analytics", "Q"],
    ["Policy", "clients", "Clients", "C"],
    ["Policy", "policies", "Policies / Explain", "P"],
    ["Policy", "filtering", "Filtering / Security", "F"],
    ["DNS", "upstreams", "Upstreams / Routing", "U"],
    ["DNS", "localdns", "Local DNS", "L"],
    ["Operations", "replication", "Replication", "R"],
    ["Operations", "backup", "Backup / Migration", "B"],
    ["System", "settings", "HTTPS / Notifications", "S"],
    ["System", "health", "System / Health", "H"],
  ];

  const policyFields = [
    ["filtering_profile_id", "Filtering profile", "default"],
    ["safesearch_mode", "SafeSearch", "off | moderate | strict"],
    ["parental_policy_id", "Parental policy", "none | family"],
    ["security_policy_id", "Security policy", "none | standard"],
    ["service_blocking_ruleset_id", "Service ruleset", "ruleset id"],
    ["blocking_response_mode", "Response mode", "refused | nxdomain | sinkhole"],
    ["upstream_profile_id", "Upstream profile", "profile id"],
    ["fallback_strategy", "Fallback", "ordered | failover"],
    ["ecs_mode", "ECS", "off | privacy | full"],
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

  async function submitOnce(form, handler) {
    if (form.dataset.busy === "1") return;
    form.dataset.busy = "1";
    const buttons = form.querySelectorAll("button");
    buttons.forEach((b) => b.disabled = true);
    try {
      await handler(form);
      toast("Operation completed", "ok");
      await loadPage(state.route);
    } catch (err) {
      toast(err.message, "bad");
    } finally {
      form.dataset.busy = "0";
      buttons.forEach((b) => b.disabled = false);
    }
  }

  function shell() {
    const grouped = pages.reduce((acc, p) => ((acc[p[0]] = acc[p[0]] || []).push(p), acc), {});
    return `
      <div class="layout">
        <aside class="sidebar">
          <div class="brand"><div class="mark">A</div><span><strong>Alderpoint DNS</strong><small>V2 management console</small></span></div>
          <nav class="nav" aria-label="Main navigation">
            ${Object.entries(grouped).map(([group, items]) => `
              <div class="section-label">${esc(group)}</div>
              ${items.map(([, id, label, glyph]) => `<button data-route="${id}" class="${state.route === id ? "active" : ""}"><span class="glyph">${esc(glyph)}</span><span>${esc(label)}</span></button>`).join("")}
            `).join("")}
          </nav>
          <div class="side-footer">
            <button data-action="theme">${state.theme === "dark" ? "Light theme" : "Dark theme"}</button>
            <button data-action="logout" class="danger">Log out</button>
          </div>
        </aside>
        <main class="main">
          <div class="topbar"><button data-action="menu">Menu</button><strong>Alderpoint DNS</strong><button data-action="theme">${state.theme === "dark" ? "Light" : "Dark"}</button></div>
          <section id="page"></section>
        </main>
      </div>`;
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
    const [c, recent, top, clients, upstreams] = await Promise.all([
      common(),
      api("/api/analytics/recent?minutes=60").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
      api("/api/analytics/top-domains?minutes=60&limit=10").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
      api("/api/clients").catch(() => ({ clients: [] })),
      api("/api/upstreams").catch(() => ({ upstreams: [] })),
    ]);
    const rows = recent.rows || [];
    const blocked = rows.filter((r) => String(JSON.stringify(r)).toLowerCase().includes("block")).length;
    const bars = (top.rows || []).slice(0, 10).map((r) => Number(Object.values(r).find((v) => typeof v === "number")) || 1);
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
        <section class="panel"><div class="panel__head"><h2>Top Domains</h2><span class="badge ${top.degraded ? "warn" : "ok"}">${top.degraded ? "degraded" : "live"}</span></div><div class="panel__body">${chart(bars, max)}${tableFromRows(top.rows || [], 6)}</div></section>
        <section class="panel"><div class="panel__head"><h2>Runtime Components</h2></div><div class="panel__body">${componentList(c.health.components || {})}</div></section>
        <section class="panel"><div class="panel__head"><h2>Clients</h2></div><div class="panel__body">${clientMini(clients.clients || [])}</div></section>
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

  function tableFromRows(rows, limit) {
    const list = rows.slice(0, limit || 50);
    if (!list.length) return `<div class="empty">No records.</div>`;
    const cols = Object.keys(list[0]).slice(0, 8);
    return `<div class="table-wrap"><table><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join("")}</tr></thead><tbody>${list.map((r) => `<tr>${cols.map((c) => `<td class="truncate" title="${esc(r[c])}">${pretty(r[c])}</td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
  }

  function clientMini(clients) {
    if (!clients.length) return `<div class="empty">No managed clients.</div>`;
    return `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Identifiers</th><th>Groups</th></tr></thead><tbody>${clients.slice(0, 8).map((c) => `<tr><td>${esc(c.name)}</td><td>${(c.identifiers || []).map((i) => `<span class="badge">${esc(i.value)}</span>`).join(" ") || '<span class="muted">none</span>'}</td><td>${(c.groups || []).map((g) => `<span class="badge info">${esc(g.name)}</span>`).join(" ") || '<span class="muted">none</span>'}</td></tr>`).join("")}</tbody></table></div>`;
  }

  async function analytics() {
    const [recent, top] = await Promise.all([
      api("/api/analytics/query-log?minutes=1440&limit=100").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message, filters: {} })),
      api("/api/analytics/top-domains?minutes=1440&limit=30").catch((e) => ({ rows: [], degraded: true, degraded_reason: e.message })),
    ]);
    return page("Query Log / Analytics", "Bounded recent query and top-domain views. Degraded analytics does not imply DNS outage.", `
      <button data-refresh>Refresh</button>`, `
      ${recent.degraded ? `<div class="alert warn">Recent query log degraded: ${esc(recent.degraded_reason || "unavailable")}</div>` : ""}
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Recent Queries</h2><span class="badge">${recent.rows.length} rows</span></div><div class="panel__body">${queryFilters()}<div id="query-active">${activeFilters(recent.filters || {})}</div><div id="query-results">${tableFromRows(recent.rows || [], 100)}</div></div></section>
        <section class="panel"><div class="panel__head"><h2>Top Domains</h2></div><div class="panel__body">${tableFromRows(top.rows || [], 30)}</div></section>
      </div>`);
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
      <div class="form-grid">${policyFields.map(([key, label, ph]) => `<label>${esc(label)}<input name="${esc(key)}" value="${esc(policy[key] || "")}" placeholder="${esc(ph)}" data-omit-empty="1"></label>`).join("")}</div>
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
    return `<form data-form="network" class="field-row"><label>Network ID<input name="network_id" required></label><label>CIDR<input name="cidr" required placeholder="10.0.0.0/24"></label><button>Create network</button></form>`;
  }

  function groupForm() {
    return `<form data-form="group" class="field-row"><label>Group ID<input name="group_id" required></label><label>Name<input name="name" required></label><label>Priority<input name="priority" value="100" data-number="1"></label><button>Create group</button></form>`;
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
    return `<form data-form="service"><div class="form-grid"><label>Service ID<input name="service_id" required></label><label>Display name<input name="display_name" required></label><label>Category<input name="category"></label><label>Domain<input name="domain" placeholder="example.com"></label><label>Match<select name="match_kind"><option>suffix</option><option>exact</option></select></label></div><button>Create service</button></form>`;
  }

  function serviceTable(services) {
    if (!services.length) return `<div class="empty">No service definitions.</div>`;
    return `<div style="margin-top:12px">${tableFromRows(services, 50)}</div>`;
  }

  function rulesetForm(services) {
    return `<form data-form="ruleset"><label>Ruleset ID<input name="ruleset_id" required></label><label>Services<select name="service_ids" multiple size="6">${services.map((s) => `<option value="${esc(s.service_id)}">${esc(s.display_name)}</option>`).join("")}</select></label><button>Create ruleset</button></form>`;
  }

  function scheduleForm() {
    return `<form data-form="schedule"><div class="form-grid"><label>Schedule ID<input name="schedule_id" required></label><label>Timezone<input name="timezone" value="UTC"></label><label>Start<input name="start" value="08:00"></label><label>End<input name="end" value="17:00"></label><label>Weekdays<input name="weekdays" value="0,1,2,3,4"></label></div><button>Create schedule</button></form>`;
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
    return `<form data-form="upstream"><div class="form-grid"><label>Profile ID<input name="upstream_profile_id" required></label><label>Name<input name="name" required></label><label>Transport<select name="transport"><option>plain</option><option>dot</option><option>doh</option></select></label><label>Strategy<select name="strategy"><option>ordered</option><option>failover</option><option>load_balanced</option><option>parallel_first_success</option></select></label><label>Address<input name="address" required placeholder="1.1.1.1:53"></label><label>TLS hostname<input name="tls_hostname" placeholder="cloudflare-dns.com"></label><label>DoH path<input name="doh_path" placeholder="/dns-query"></label></div><button>Create upstream</button></form>`;
  }

  function routeForm(upstreams) {
    return `<form data-form="route"><label>Ruleset ID<input name="rule_id" required></label><label>Domain suffix<input name="suffix_domain" required placeholder="corp.example"></label><label>Upstream<select name="upstream_profile_id">${upstreams.map((u) => `<option value="${esc(u.upstream_profile_id)}">${esc(u.name)}</option>`).join("")}</select></label><button>Create route and promote runtime</button></form>`;
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
    return `<form data-form="peer"><label>Peer node ID<input name="peer_node_id" required></label><label>Display name<input name="display_name"></label><label>URL<input name="url" required placeholder="https://10.0.0.2:9443/replication/v1/apply"></label><label>Expected cert SHA-256<input name="expected_cert_sha256" required minlength="64" maxlength="64"></label><label>Trusted CA PEM<textarea name="ca_pem" required></textarea></label><label>Client certificate PEM<textarea name="client_cert_pem"></textarea></label><label>Client key PEM<textarea name="client_key_pem"></textarea></label><label>Direction<select name="direction"><option>bidirectional</option><option>push</option><option>pull</option></select></label><button class="primary">Save peer</button></form>`;
  }

  async function backup() {
    const [backups, migration] = await Promise.all([
      api("/api/backup/secrets").catch((e) => ({ backups: [], restore_jobs: [], error: e.message })),
      api("/api/migration/detect?source_path=/var/lib/alderpointdns/alderpointdns.db").catch((e) => ({ error: e.message })),
    ]);
    return page("Backup / Restore / Migration", "Safe entry points for backup and migration preview. Opening this page does not start destructive work.", "", `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>Secret Backup / Restore</h2></div><div class="panel__body"><p class="muted">Creates encrypted server-side backups. Restore requires validation plus exact file-name confirmation. Secret values are never displayed.</p><button data-backup class="primary">Create secret backup</button>${backupTable(backups.backups || [])}${restoreJobs(backups.restore_jobs || [])}</div></section>
        <section class="panel"><div class="panel__head"><h2>Migration Detection</h2></div><div class="panel__body">${migration.error ? `<div class="alert warn">${esc(migration.error)}</div>` : tableFromRows([migration], 1)}<form data-form="migration"><label>Source path<input name="source_path" value="/var/lib/alderpointdns/alderpointdns.db"></label><button>Detect source</button></form><div id="migration-result"></div></div></section>
      </div>`);
  }

  function backupTable(backups) {
    if (!backups.length) return `<div class="empty">No encrypted secret backups.</div>`;
    return `<div class="table-wrap" style="margin-top:12px"><table><thead><tr><th>Name</th><th>Created</th><th>Size</th><th>Restore</th></tr></thead><tbody>${backups.map((b) => `<tr><td class="mono">${esc(b.name)}</td><td>${esc(b.created_at)}</td><td>${esc(b.size_bytes)}</td><td><button data-validate-backup="${esc(b.name)}">Validate</button><form data-form="restore" data-backup-name="${esc(b.name)}" class="field-row"><input name="confirmation" placeholder="type exact file name"><select name="overwrite" data-bool="1"><option value="false">no overwrite</option><option value="true">overwrite</option></select><button class="danger">Restore</button></form></td></tr>`).join("")}</tbody></table></div>`;
  }

  function restoreJobs(jobs) {
    if (!jobs.length) return `<div class="muted" style="margin-top:12px">No restore jobs recorded.</div>`;
    return `<div style="margin-top:12px"><h3>Restore Status</h3>${tableFromRows(jobs, 20)}</div>`;
  }

  async function settings() {
    const [tls, notifications] = await Promise.all([api("/api/tls/status"), api("/api/notifications")]);
    return page("HTTPS / Notifications", "Certificate replacement uses stage, validate, promote. Provider secrets are write-only and redacted.", "", `
      <div class="grid two">
        <section class="panel"><div class="panel__head"><h2>HTTPS Certificate</h2><span class="badge ${tls.is_self_signed ? "warn" : "ok"}">${tls.active ? (tls.is_self_signed ? "self-signed" : "active") : "missing"}</span></div><div class="panel__body">${tableFromRows([tls], 1)}${tlsForm()}</div></section>
        <section class="panel"><div class="panel__head"><h2>Notifications</h2></div><div class="panel__body">${tableFromRows(notifications.providers || [], 50)}${notificationForm()}</div></section>
      </div>`);
  }

  function tlsForm() {
    return `<form data-form="tls"><label>Certificate PEM<textarea name="certificate_pem" required></textarea></label><label>Private key PEM<textarea name="private_key_pem" required></textarea></label><button class="primary">Validate and promote certificate</button></form>`;
  }

  function notificationForm() {
    return `<form data-form="notification"><div class="form-grid"><label>Provider ID<input name="provider_id" required></label><label>Kind<input name="kind" value="webhook"></label><label>Display name<input name="display_name" required></label><label>Endpoint<input name="endpoint" required></label></div><label>Secret value<input name="secret_value" type="password" autocomplete="new-password"></label><button>Create provider</button></form>`;
  }

  async function health() {
    const [h, s, n, d] = await Promise.all([api("/api/health"), api("/api/system/status"), api("/api/node-identity"), api("/api/discovery/status")]);
    return page("System / Health", "Operational status separates DNS/runtime health from optional subsystem degradation.", `<button data-refresh>Refresh</button>`, `
      <div class="strip"><div class="metric"><strong>${esc(h.status)}</strong><span>Overall</span></div><div class="metric"><strong>${esc(s.version)}</strong><span>Version</span></div><div class="metric"><strong>${s.compiled_runtime_present ? "yes" : "no"}</strong><span>Compiled runtime</span></div><div class="metric"><strong>${esc(d.observed_count ?? 0)}</strong><span>Observed clients</span></div></div>
      <div class="grid two"><section class="panel"><div class="panel__head"><h2>Components</h2></div><div class="panel__body">${componentList(h.components || {})}</div></section><section class="panel"><div class="panel__head"><h2>Node Identity</h2></div><div class="panel__body">${tableFromRows([n], 1)}</div></section></div>`);
  }

  const renderers = { dashboard, analytics, clients, policies, filtering, upstreams, localdns, replication, backup, settings, health };

  async function loadPage(id) {
    state.route = id || "dashboard";
    document.querySelectorAll("[data-route]").forEach((b) => b.classList.toggle("active", b.dataset.route === state.route));
    const target = document.getElementById("page");
    target.innerHTML = page("Loading", "Fetching live appliance state.", "", `<div class="empty">Loading...</div>`);
    try {
      target.innerHTML = await renderers[state.route]();
      history.replaceState(null, "", `/ui/${state.route}`);
    } catch (err) {
      if (err.status === 401) return boot();
      target.innerHTML = page("Page unavailable", "The backend rejected or failed this request.", `<button data-refresh>Retry</button>`, `<div class="alert bad">${esc(err.message)}</div>`);
    }
  }

  function authScreen(setupRequired) {
    return `<main class="auth"><section class="auth-card"><div class="mark">A</div><h1>${setupRequired ? "Create first administrator" : "Sign in"}</h1><p>${setupRequired ? "Use the bootstrap setup token from the installed appliance state directory." : "Use your Alderpoint DNS administrator account."}</p>
      <form data-auth="${setupRequired ? "setup" : "login"}">
        ${setupRequired ? `<label>Setup token<input name="setup_token" required autocomplete="one-time-code"></label>` : ""}
        <label>Username<input name="username" required autocomplete="username"></label>
        <label>Password<input name="password" type="password" required minlength="${setupRequired ? 12 : 1}" autocomplete="${setupRequired ? "new-password" : "current-password"}"></label>
        <button class="primary">${setupRequired ? "Create administrator" : "Sign in"}</button>
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
      app.innerHTML = shell();
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
    document.querySelector("[data-auth]").addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const form = ev.currentTarget;
      await submitOnce(form, async () => {
        const body = jsonForm(form);
        if (form.dataset.auth === "setup") {
          await api("/api/setup", { method: "POST", body: JSON.stringify(body) });
        }
        const login = await api("/api/login", { method: "POST", body: JSON.stringify({ username: body.username, password: body.password }) });
        state.csrf = login.csrf;
        await boot();
      });
    });
  }

  function wire() {
    document.body.addEventListener("click", async (ev) => {
      const route = ev.target.closest("[data-route]");
      if (route) { document.body.classList.remove("nav-open"); await loadPage(route.dataset.route); return; }
      if (ev.target.closest("[data-action='menu']")) { document.body.classList.toggle("nav-open"); return; }
      if (ev.target.closest("[data-action='theme']")) { setTheme(state.theme === "dark" ? "light" : "dark"); document.getElementById("app").innerHTML = shell(); await loadPage(state.route); return; }
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
          await loadPage("clients");
        }
        return;
      }
      const forget = ev.target.closest("[data-forget]");
      if (forget && confirm(`Forget observed client ${forget.dataset.forget}?`)) {
        await api(`/api/discovery/observed-clients/${encodeURIComponent(forget.dataset.forget)}`, { method: "DELETE" });
        toast("Observed client forgotten", "ok");
        await loadPage("clients");
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
        toast(`Encrypted backup created for ${res.secret_count} secrets`, "ok");
        await loadPage("backup");
        return;
      }
      const validate = ev.target.closest("[data-validate-backup]");
      if (validate) {
        const name = validate.dataset.validateBackup;
        const res = await api(`/api/backup/secrets/${encodeURIComponent(name)}/validate`, { method: "POST" });
        toast(`Backup ${res.backup_name} is valid (${res.secret_count} secrets)`, "ok");
        await loadPage("backup");
        return;
      }
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
      const q = new URLSearchParams({ client_id: body.client_id });
      if (body.client_ip) q.set("client_ip", body.client_ip);
      const res = await api(`/api/policy/explain?${q}`);
      document.getElementById("explain-result").innerHTML = `<pre class="mono">${esc(JSON.stringify(res, null, 2))}</pre>`;
      return;
    } else if (type === "querylog") {
      const q = new URLSearchParams();
      for (const [k, v] of Object.entries(body)) {
        if (v === "" || v === null || v === undefined) continue;
        q.set(k, String(v));
      }
      const res = await api(`/api/analytics/query-log?${q}`);
      document.getElementById("query-active").innerHTML = activeFilters(res.filters || {});
      document.getElementById("query-results").innerHTML = tableFromRows(res.rows || [], Number(body.limit || 100));
      return;
    } else if (type === "service") {
      await api("/api/services", { method: "POST", body: JSON.stringify({ service_id: body.service_id, display_name: body.display_name, category: body.category || "", domains: body.domain ? [{ match_kind: body.match_kind, domain: body.domain }] : [] }) });
    } else if (type === "ruleset") {
      const selected = Array.from(form.elements.service_ids.selectedOptions).map((o) => o.value);
      await api("/api/service-rulesets", { method: "POST", body: JSON.stringify({ ruleset_id: body.ruleset_id, service_ids: selected }) });
    } else if (type === "schedule") {
      await api("/api/schedules", { method: "POST", body: JSON.stringify({ schedule_id: body.schedule_id, timezone: body.timezone || "UTC", windows: [{ start: body.start, end: body.end, weekdays: String(body.weekdays || "").split(",").map((x) => Number(x.trim())).filter((x) => Number.isInteger(x)) }] }) });
    } else if (type === "upstream") {
      await api("/api/upstreams", { method: "POST", body: JSON.stringify({ upstream_profile_id: body.upstream_profile_id, name: body.name, transport: body.transport, strategy: body.strategy, endpoints: [{ address: body.address, tls_hostname: body.tls_hostname || null, doh_path: body.doh_path || null }] }) });
    } else if (type === "route") {
      await api("/api/domain-routing", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "localdns") {
      await api("/api/local-dns", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "peer") {
      await api(`/api/replication/peers/${encodeURIComponent(body.peer_node_id)}`, { method: "PUT", body: JSON.stringify(Object.assign({ authorized: true }, body)) });
    } else if (type === "migration") {
      const res = await api(`/api/migration/detect?source_path=${encodeURIComponent(body.source_path)}`);
      document.getElementById("migration-result").innerHTML = tableFromRows([res], 1);
      return;
    } else if (type === "restore") {
      const name = form.dataset.backupName;
      await api(`/api/backup/secrets/${encodeURIComponent(name)}/restore`, { method: "POST", body: JSON.stringify(body) });
    } else if (type === "tls") {
      await api("/api/tls/replace", { method: "POST", body: JSON.stringify(body) });
    } else if (type === "notification") {
      await api("/api/notifications", { method: "POST", body: JSON.stringify(body) });
    }
  }

  boot();
}());
