<script lang="ts">
  // Audit Log (Advanced > Operations). Real data, GET
  // /api/administration/audit-log/all -> internal/auditlog.Service.ListAll,
  // every administrator's recorded activity, most recent first -- not the
  // smaller per-admin summary Administration's own "Recent Administrative
  // Activity" card links out to this page for.
  //
  // Disclosed scope gap against the full spec: admin_audit_log
  // (schema/migrations/0023) has exactly six columns -- at/username/
  // action/success/ip/detail. There is no Resource column, no
  // correlation/deployment-job-id, and no before/after diff anywhere in
  // this appliance's audit trail yet, so this page doesn't invent any of
  // those; "Details" below is the one real free-text field a given action
  // recorded (often empty -- see internal/httpapi's audited() wrapper and
  // per-call-site Record() calls for which actions write a detail string).
  import { onMount } from "svelte";
  import { api, type AuditLogEntry } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref, timestampSortKey } from "../timestamp.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import Modal from "./ui/Modal.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  let entries = $state<AuditLogEntry[] | null>(null);
  let error = $state("");
  let loading = $state(false);

  let search = $state("");
  let resultFilter = $state<"all" | "success" | "failure">("all");
  let adminFilter = $state("all");
  let rangeHours = $state<24 | 168 | 720 | 0>(168); // 24h / 7d / 30d / all

  async function load() {
    loading = true;
    error = "";
    try {
      entries = (await api.listAuditLogAll(500, router.signal())).entries;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      error = err instanceof Error ? err.message : String(err);
    } finally {
      loading = false;
    }
  }

  onMount(load);

  const administrators = $derived.by(() => {
    const names = new Set((entries ?? []).map((e) => e.username || "unknown"));
    return ["all", ...Array.from(names).sort()];
  });

  const filtered = $derived.by(() => {
    if (!entries) return [];
    const q = search.trim().toLowerCase();
    const cutoff = rangeHours ? Date.now() - rangeHours * 3600_000 : 0;
    return entries.filter((e) => {
      if (resultFilter === "success" && !e.success) return false;
      if (resultFilter === "failure" && e.success) return false;
      if (adminFilter !== "all" && (e.username || "unknown") !== adminFilter) return false;
      if (cutoff && timestampSortKey(e.at) < cutoff) return false;
      if (q) {
        const hay = `${e.action} ${e.detail} ${e.ip} ${e.username ?? ""}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  });

  function clearFilters() {
    search = "";
    resultFilter = "all";
    adminFilter = "all";
    rangeHours = 168;
  }

  function exportCsv() {
    const header = ["Time", "Administrator", "Action", "Result", "Source IP", "Detail"];
    const rows = filtered.map((e) => [
      e.at,
      e.username ?? "",
      e.action,
      e.success ? "success" : "failure",
      e.ip,
      e.detail,
    ]);
    const esc = (v: string) => `"${v.replace(/"/g, '""')}"`;
    const csv = [header, ...rows].map((r) => r.map((c) => esc(String(c))).join(",")).join("\n");
    const blob = new Blob([csv], { type: "text/csv" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `alderpoint-audit-log-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
  }

  const columns: Column<AuditLogEntry>[] = [
    { key: "at", label: "Time", sortValue: (r) => timestampSortKey(r.at), minWidth: 20 },
    { key: "username", label: "Administrator", sortValue: (r) => r.username ?? "", minWidth: 12 },
    { key: "action", label: "Action", sortValue: (r) => r.action, minWidth: 16 },
    { key: "result", label: "Result", sortValue: (r) => (r.success ? 1 : 0), minWidth: 8 },
    { key: "ip", label: "Source IP", sortValue: (r) => r.ip, minWidth: 12 },
    { key: "detail", label: "Details", minWidth: 20 },
  ];

  let selected = $state<AuditLogEntry | null>(null);
</script>

<PageHeader headingId="audit-log-heading" title="Audit Log" description="Every recorded administrative action across all administrators on this appliance, most recent first.">
  {#snippet actions()}
    <button type="button" class="secondary" onclick={load} disabled={loading}>{loading ? "Refreshing…" : "Refresh"}</button>
    <button type="button" class="secondary" onclick={exportCsv} disabled={filtered.length === 0}>Export CSV</button>
  {/snippet}
</PageHeader>

<div class="filter-bar">
  <input type="search" placeholder="Search action, detail, IP, administrator…" bind:value={search} aria-label="Search audit log" />
  <select bind:value={adminFilter} aria-label="Administrator">
    {#each administrators as a (a)}
      <option value={a}>{a === "all" ? "All administrators" : a}</option>
    {/each}
  </select>
  <select bind:value={resultFilter} aria-label="Result">
    <option value="all">All results</option>
    <option value="success">Success only</option>
    <option value="failure">Failure only</option>
  </select>
  <select bind:value={rangeHours} aria-label="Time range">
    <option value={24}>Last 24 hours</option>
    <option value={168}>Last 7 days</option>
    <option value={720}>Last 30 days</option>
    <option value={0}>All time</option>
  </select>
  <button type="button" class="secondary" onclick={clearFilters}>Clear Filters</button>
</div>

{#if error}
  <p class="error" role="alert">{error}</p>
{:else if !entries}
  <p class="hint">Loading…</p>
{:else}
  <p class="hint count-line">{filtered.length} of {entries.length} recorded entries.</p>
  <!-- rowKey uses the real admin_audit_log.id (2026-09-03) -- a real
       live defect this closed: the previous synthetic at+action+ip key
       genuinely collided (Svelte's own "each_key_duplicate" runtime
       error, caught live) whenever two entries shared a timestamp,
       action, and source IP -- an ordinary occurrence for any session
       performing the same audited action more than once in one second,
       not a rare edge case. -->
  <DataGrid gridId="audit-log" {columns} rows={filtered} rowKey={(r) => r.id} emptyMessage="No audit entries match these filters.">
    {#snippet cell(row, colKey)}
      {#if colKey === "at"}
        <span class="mono">{timestampPref.format(row.at)}</span>
      {:else if colKey === "username"}
        {row.username || "unknown"}
      {:else if colKey === "action"}
        <button type="button" class="link" onclick={() => (selected = row)}>{row.action}</button>
      {:else if colKey === "result"}
        <StatusBadge label={row.success ? "Success" : "Failed"} tone={row.success ? "healthy" : "danger"} />
      {:else if colKey === "ip"}
        <span class="mono">{row.ip}</span>
      {:else}
        <span class="detail-cell">{row.detail || "—"}</span>
      {/if}
    {/snippet}
  </DataGrid>
{/if}

{#if selected}
  <Modal title="Audit entry" onClose={() => (selected = null)}>
    <dl class="detail-list">
      <dt>Time</dt><dd>{timestampPref.format(selected.at)}</dd>
      <dt>Administrator</dt><dd>{selected.username || "unknown"}</dd>
      <dt>Action</dt><dd>{selected.action}</dd>
      <dt>Result</dt><dd><StatusBadge label={selected.success ? "Success" : "Failed"} tone={selected.success ? "healthy" : "danger"} /></dd>
      <dt>Source IP</dt><dd class="mono">{selected.ip}</dd>
      <dt>Detail</dt><dd>{selected.detail || "No additional detail was recorded for this action."}</dd>
    </dl>
    <p class="hint">
      This appliance's audit trail does not yet record a resource identifier, a related deployment/job
      id, or a before/after change summary for every action -- only what's shown above is real.
    </p>
  </Modal>
{/if}

<style>
  .filter-bar { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 1rem; }
  .filter-bar input[type="search"] { flex: 1 1 16rem; }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .count-line { margin: 0 0 0.6rem; }
  .mono { font-family: monospace; font-size: 0.85rem; }
  .link { background: transparent; color: var(--accent); border: none; padding: 0; font: inherit; cursor: pointer; text-decoration: underline; }
  .detail-cell { display: inline-block; max-width: 32rem; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; vertical-align: bottom; }
  .detail-list { display: grid; grid-template-columns: auto 1fr; gap: 0.5rem 1rem; margin: 0 0 1rem; }
  .detail-list dt { font-weight: 600; opacity: 0.75; font-size: 0.85rem; }
  .detail-list dd { margin: 0; }
  .error { color: var(--danger); }
</style>
