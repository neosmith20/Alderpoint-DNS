<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type NotificationProvider } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Notifications. Real native-Go storage for provider metadata
  // (internal/notifications), matching app/v2/notification_store.py's
  // notification_providers table field-for-field for the non-secret
  // columns. No secret/credential storage: this control plane has no
  // Go-native secrets store yet (same disclosed gap as internal/
  // upstreams's endpoint secret_ref and Encryption's DNSCrypt identity)
  // -- a created provider is real, listable, editable metadata, not yet
  // a working notification channel.

  let providers = $state<NotificationProvider[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let kind = $state<NotificationProvider["kind"]>("webhook");
  let displayName = $state("");
  let endpoint = $state("");
  let createError = $state("");
  let createBusy = $state(false);

  async function refresh() {
    const token = guard.start();
    try {
      const resp = await api.listNotificationProviders(router.signal());
      if (!guard.isCurrent(token)) return;
      providers = resp.providers;
      loadError = "";
    } catch (err) {
      if (!guard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function createProvider(e: Event) {
    e.preventDefault();
    createError = "";
    createBusy = true;
    try {
      await api.createNotificationProvider(kind, displayName, endpoint);
      displayName = "";
      endpoint = "";
      await refresh();
    } catch (err) {
      createError = err instanceof ApiError ? err.message : String(err);
    } finally {
      createBusy = false;
    }
  }

  async function toggle(p: NotificationProvider) {
    await api.toggleNotificationProvider(p.provider_id, !p.enabled);
    await refresh();
  }

  async function remove(p: NotificationProvider) {
    await api.deleteNotificationProvider(p.provider_id);
    await refresh();
  }

  const columns: Column<NotificationProvider>[] = [
    { key: "display_name", label: "Name", sortValue: (p) => p.display_name, minWidth: 16 },
    { key: "kind", label: "Kind", sortValue: (p) => p.kind, minWidth: 10 },
    { key: "endpoint", label: "Endpoint", sortValue: (p) => p.endpoint, minWidth: 20 },
    { key: "enabled", label: "Enabled", sortValue: (p) => (p.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 14 },
  ];
</script>

<section aria-labelledby="notifications-heading" class="notifications">
  <h2 id="notifications-heading">Notifications</h2>
  <p class="scope-note">
    Provider metadata is real native storage. Credentials/secrets are not stored -- this control
    plane has no secrets store yet, so a created provider cannot actually send a notification. See
    the parity matrix.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <form class="add-form" onsubmit={createProvider}>
    <select bind:value={kind}>
      <option value="webhook">Webhook</option>
      <option value="email_smtp">Email (SMTP)</option>
      <option value="pushover">Pushover</option>
      <option value="slack">Slack</option>
    </select>
    <input placeholder="Display name" bind:value={displayName} aria-label="Display name" required />
    <input placeholder="Endpoint (URL or address)" bind:value={endpoint} aria-label="Endpoint" />
    <button type="submit" disabled={createBusy}>{createBusy ? "Adding…" : "Add provider"}</button>
  </form>
  {#if createError}<p class="error" role="alert">{createError}</p>{/if}

  <DataGrid gridId="notification-providers" {columns} rows={providers} rowKey={(p) => p.provider_id} emptyMessage="No notification providers yet.">
    {#snippet cell(p, colKey)}
      {#if colKey === "display_name"}
        {p.display_name}
      {:else if colKey === "kind"}
        {p.kind}
      {:else if colKey === "endpoint"}
        {p.endpoint}
      {:else if colKey === "enabled"}
        {p.enabled ? "Yes" : "No"}
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => toggle(p)}>{p.enabled ? "Disable" : "Enable"}</button>
          <button onclick={() => remove(p)}>Delete</button>
        </div>
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .notifications { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .add-form { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
  .add-form input { flex: 1; min-width: 10rem; }
  .actions { display: flex; gap: 0.4rem; }
  .error { color: var(--badge-danger-fg); }
</style>
