<script lang="ts">
  import { onMount } from "svelte";
  import { api, type BlockedServiceCatalogEntry, type BlockedServicesSettings, type DNSRuntimeApplyResult } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";
  import PageHeader from "./ui/PageHeader.svelte";
  import Modal from "./ui/Modal.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import DnsRuntimeBadge from "./DnsRuntimeBadge.svelte";

  // Blocked Services: a fixed catalog (internal/blockedservices.Catalog)
  // an owner toggles on/off, compiled into one reserved Service Blocking
  // Ruleset assigned to the GLOBAL policy layer -- a real, live-enforced
  // effect (see internal/dnsruntime's own fix making a global
  // service_blocking_ruleset_id actually compile, previously inert).
  // Distinct from Advanced > Policy Profiles > Service Blocking
  // Rulesets, which lets an owner define their own arbitrary-domain
  // rulesets instead of picking from this fixed catalog.

  let catalog = $state<BlockedServiceCatalogEntry[]>([]);
  let settings = $state<BlockedServicesSettings | null>(null);
  let loadError = $state("");
  let dnsRuntimeResult = $state<DNSRuntimeApplyResult | null>(null);
  let toggleBusy = $state<Set<string>>(new Set());

  let search = $state("");
  let categoryFilter = $state("all");
  let showFilter = $state<"all" | "blocked" | "unblocked">("all");

  async function load() {
    loadError = "";
    try {
      const [c, s] = await Promise.all([api.listBlockedServicesCatalog(router.signal()), api.getBlockedServicesSettings(router.signal())]);
      catalog = c.services;
      settings = s;
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof Error ? err.message : String(err);
    }
  }
  onMount(load);

  const categories = $derived(["all", ...Array.from(new Set(catalog.map((c) => c.category))).sort()]);
  const enabledSet = $derived(new Set(settings?.enabled_service_ids ?? []));

  const filtered = $derived(
    catalog.filter((c) => {
      if (categoryFilter !== "all" && c.category !== categoryFilter) return false;
      if (showFilter === "blocked" && !enabledSet.has(c.id)) return false;
      if (showFilter === "unblocked" && enabledSet.has(c.id)) return false;
      if (search.trim() && !c.name.toLowerCase().includes(search.trim().toLowerCase())) return false;
      return true;
    }),
  );

  async function toggle(id: string) {
    if (!settings) return;
    toggleBusy = new Set(toggleBusy).add(id);
    const next = new Set(settings.enabled_service_ids);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    try {
      const resp = await api.setBlockedServicesEnabled([...next]);
      settings = resp.settings;
      dnsRuntimeResult = resp.dns_runtime ?? null;
    } catch (err) {
      loadError = err instanceof Error ? err.message : String(err);
    } finally {
      const nb = new Set(toggleBusy);
      nb.delete(id);
      toggleBusy = nb;
    }
  }

  // --- Schedule dialog ---
  let scheduleOpen = $state(false);
  let schedEnabled = $state(false);
  let schedDays = $state<Set<string>>(new Set());
  let schedStart = $state("00:00");
  let schedEnd = $state("23:59");
  let schedAllDay = $state(false);
  let scheduleBusy = $state(false);
  let scheduleError = $state("");

  const DAY_LABELS: { key: string; label: string }[] = [
    { key: "sun", label: "Sun" }, { key: "mon", label: "Mon" }, { key: "tue", label: "Tue" }, { key: "wed", label: "Wed" },
    { key: "thu", label: "Thu" }, { key: "fri", label: "Fri" }, { key: "sat", label: "Sat" },
  ];

  function openSchedule() {
    if (!settings) return;
    schedEnabled = settings.schedule_enabled;
    schedDays = new Set(settings.schedule_days);
    schedStart = settings.schedule_start;
    schedEnd = settings.schedule_end;
    schedAllDay = settings.schedule_all_day;
    scheduleError = "";
    scheduleOpen = true;
  }

  function toggleDay(key: string) {
    const next = new Set(schedDays);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    schedDays = next;
  }

  async function saveSchedule(e: Event) {
    e.preventDefault();
    scheduleBusy = true;
    scheduleError = "";
    try {
      const resp = await api.setBlockedServicesSchedule({ enabled: schedEnabled, days: [...schedDays], start: schedStart, end: schedEnd, all_day: schedAllDay });
      settings = resp.settings;
      dnsRuntimeResult = resp.dns_runtime ?? null;
      scheduleOpen = false;
    } catch (err) {
      scheduleError = err instanceof Error ? err.message : String(err);
    } finally {
      scheduleBusy = false;
    }
  }

  function initials(name: string): string {
    return name.slice(0, 2).toUpperCase();
  }
  // A small, fixed palette of avatar background hues, assigned by a
  // stable hash of the service id -- visually distinct without a real
  // per-service brand logo (none are bundled; see this file's own doc
  // comment for why: no logo assets exist for any catalog entry).
  const AVATAR_HUES = [200, 160, 20, 280, 340, 40, 250, 100];
  function avatarHue(id: string): number {
    let h = 0;
    for (let i = 0; i < id.length; i++) h = (h * 31 + id.charCodeAt(i)) >>> 0;
    return AVATAR_HUES[h % AVATAR_HUES.length];
  }
</script>

<PageHeader
  headingId="blocked-services-heading"
  title="Blocked Services"
  description="Toggle well-known services on or off for every client, appliance-wide. For a client- or group-specific policy instead, use Scope Policies."
>
  {#snippet actions()}
    <button type="button" class="secondary" onclick={openSchedule} disabled={!settings}>Edit Schedule</button>
  {/snippet}
</PageHeader>

{#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
<DnsRuntimeBadge result={dnsRuntimeResult} />

{#if settings}
  <div class="schedule-summary">
    {#if settings.schedule_enabled}
      <StatusBadge label={settings.schedule_active_now ? "Schedule: active now" : "Schedule: inactive now"} tone={settings.schedule_active_now ? "healthy" : "neutral"} />
      {#if settings.next_activation}<span class="hint">Next activation: {timestampPref.format(settings.next_activation)}</span>{/if}
    {:else}
      <StatusBadge label="No schedule -- always on when toggled" tone="neutral" />
    {/if}
  </div>
{/if}

<div class="toolbar">
  <input class="search-input" placeholder="Search services…" bind:value={search} aria-label="Search services" />
  <select bind:value={categoryFilter} aria-label="Category">
    {#each categories as c (c)}<option value={c}>{c === "all" ? "All categories" : c}</option>{/each}
  </select>
  <select bind:value={showFilter} aria-label="Show">
    <option value="all">Show all</option>
    <option value="blocked">Blocked only</option>
    <option value="unblocked">Unblocked only</option>
  </select>
</div>

{#if !settings}
  <p class="hint">Loading…</p>
{:else}
  <div class="grid">
    {#each filtered as svc (svc.id)}
      {@const on = enabledSet.has(svc.id)}
      <div class="service-card" class:blocked={on}>
        <span class="avatar" style="background: hsl({avatarHue(svc.id)} 55% 38%)">{initials(svc.name)}</span>
        <div class="service-body">
          <span class="service-name">{svc.name}</span>
          <span class="service-category">{svc.category}</span>
        </div>
        <button type="button" class="toggle" class:on onclick={() => toggle(svc.id)} disabled={toggleBusy.has(svc.id)} aria-pressed={on}>
          {on ? "Blocked" : "Allowed"}
        </button>
      </div>
    {:else}
      <p class="hint empty">No services match these filters.</p>
    {/each}
  </div>
{/if}

{#if scheduleOpen}
  <Modal title="Blocked Services Schedule" onClose={() => (scheduleOpen = false)}>
    <form onsubmit={saveSchedule} class="modal-form">
      <label class="checkbox-label"><input type="checkbox" bind:checked={schedEnabled} /> Enable a schedule (otherwise, toggled services are blocked at all times)</label>
      {#if schedEnabled}
        <div class="day-row" role="group" aria-label="Active days">
          {#each DAY_LABELS as d (d.key)}
            <button type="button" class="day-btn" class:active={schedDays.has(d.key)} onclick={() => toggleDay(d.key)}>{d.label}</button>
          {/each}
        </div>
        <label class="checkbox-label"><input type="checkbox" bind:checked={schedAllDay} /> All day on the selected days</label>
        {#if !schedAllDay}
          <div class="time-row">
            <label>Start <input type="time" bind:value={schedStart} /></label>
            <label>End <input type="time" bind:value={schedEnd} /></label>
          </div>
        {/if}
        <p class="hint">Times are this appliance's own local time. Affected scope: appliance-wide (every client). No days selected means every day.</p>
      {/if}
      <div class="form-actions">
        <button type="submit" disabled={scheduleBusy}>{scheduleBusy ? "Saving…" : "Save Schedule"}</button>
        <button type="button" class="secondary" onclick={() => (scheduleOpen = false)}>Cancel</button>
      </div>
      {#if scheduleError}<p class="error" role="alert">{scheduleError}</p>{/if}
    </form>
  </Modal>
{/if}

<style>
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .error { color: var(--danger); }
  .schedule-summary { display: flex; align-items: center; gap: 0.75rem; margin-bottom: 0.75rem; }
  .toolbar { display: flex; flex-wrap: wrap; gap: 0.6rem; margin-bottom: 1rem; }
  .search-input { min-width: 14rem; flex: 1 1 14rem; }

  .grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(15rem, 1fr)); gap: 0.85rem; }
  .empty { grid-column: 1 / -1; text-align: center; padding: 2rem; }
  .service-card {
    display: flex; align-items: center; gap: 0.7rem; padding: 0.75rem 0.9rem;
    border: 1px solid var(--border); border-radius: 8px; background: var(--card-bg);
  }
  .service-card.blocked { border-color: var(--danger); }
  .avatar {
    flex-shrink: 0; width: 2.2rem; height: 2.2rem; border-radius: 8px; color: #fff; font-weight: 700; font-size: 0.8rem;
    display: flex; align-items: center; justify-content: center;
  }
  .service-body { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  .service-name { font-weight: 600; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .service-category { font-size: 0.78rem; opacity: 0.7; }
  .toggle {
    flex-shrink: 0; min-height: auto; padding: 0.35rem 0.7rem; font-size: 0.78rem;
    background: var(--panel-elevated); color: var(--fg); border: 1px solid var(--border-strong);
  }
  .toggle.on { background: var(--badge-danger-bg); color: var(--badge-danger-fg); border-color: transparent; }

  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .checkbox-label { display: flex; align-items: center; gap: 0.5rem; font-size: 0.9rem; }
  .day-row { display: flex; gap: 0.3rem; flex-wrap: wrap; }
  .day-btn { min-height: auto; padding: 0.35rem 0.6rem; font-size: 0.8rem; background: var(--panel-elevated); color: var(--fg); border: 1px solid var(--border-strong); }
  .day-btn.active { background: var(--accent); color: var(--accent-fg); border-color: var(--accent); }
  .time-row { display: flex; gap: 1rem; }
  .time-row label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .form-actions { display: flex; gap: 0.5rem; }
</style>
