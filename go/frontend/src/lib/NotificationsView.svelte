<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type NotificationProvider } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";

  // Notifications. Real native-Go storage for provider metadata
  // (internal/notifications). Credentials are real too (2026-08-28):
  // a webhook/Slack URL, a Pushover "user_key:app_token" pair, or an
  // SMTP password is sealed via the native Go secrets subsystem
  // (internal/secretstore + apdns-hostagent's AES-256-GCM engine) --
  // this page can set/replace/revoke/test a secret, but a saved secret
  // is never displayed back in plaintext (has_secret is the only thing
  // this page ever knows about it). "Send Test" performs a real send
  // using the stored credential, entirely inside apdns-hostagent.
  //
  // Not built in this pass, disclosed rather than hidden: the
  // event-driven dispatch engine (subscriptions, severity/cooldown
  // rules, automatic sends on a real condition) -- see the parity
  // matrix. A provider configured here can genuinely receive a message
  // today via Send Test; nothing yet decides WHEN to notify on its own.

  let providers = $state<NotificationProvider[]>([]);
  let loadError = $state("");
  const guard = new StaleGuard();

  let kind = $state<NotificationProvider["kind"]>("webhook");
  let displayName = $state("");
  let secretValue = $state("");
  let smtpHost = $state("");
  let smtpPort = $state(587);
  let smtpFrom = $state("");
  let smtpTo = $state("");
  let smtpUsername = $state("");
  let createError = $state("");
  let createBusy = $state(false);

  let rowBusy = $state<Record<string, boolean>>({});
  let rowStatus = $state<Record<string, string>>({});

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

  const secretLabel: Record<string, string> = {
    webhook: "Webhook URL",
    slack: "Slack incoming webhook URL",
    pushover: "Pushover user_key:app_token",
    email_smtp: "SMTP password",
  };

  async function createProvider(e: Event) {
    e.preventDefault();
    createError = "";
    createBusy = true;
    try {
      const config =
        kind === "email_smtp" ? { host: smtpHost, port: Number(smtpPort), from_addr: smtpFrom, to_addr: smtpTo, username: smtpUsername } : {};
      const p = await api.createNotificationProvider(kind, displayName, config);
      if (secretValue.trim()) {
        await api.setNotificationSecret(p.provider_id, secretValue);
      }
      displayName = "";
      secretValue = "";
      smtpHost = smtpFrom = smtpTo = smtpUsername = "";
      smtpPort = 587;
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

  let replaceTarget = $state<string | null>(null);
  let replaceValue = $state("");

  async function submitReplaceSecret(providerId: string) {
    rowBusy = { ...rowBusy, [providerId]: true };
    rowStatus = { ...rowStatus, [providerId]: "" };
    try {
      await api.setNotificationSecret(providerId, replaceValue);
      replaceTarget = null;
      replaceValue = "";
      await refresh();
    } catch (err) {
      rowStatus = { ...rowStatus, [providerId]: err instanceof ApiError ? err.message : String(err) };
    } finally {
      rowBusy = { ...rowBusy, [providerId]: false };
    }
  }

  async function revokeSecret(p: NotificationProvider) {
    rowBusy = { ...rowBusy, [p.provider_id]: true };
    try {
      await api.revokeNotificationSecret(p.provider_id);
      await refresh();
    } finally {
      rowBusy = { ...rowBusy, [p.provider_id]: false };
    }
  }

  async function sendTest(p: NotificationProvider) {
    rowBusy = { ...rowBusy, [p.provider_id]: true };
    rowStatus = { ...rowStatus, [p.provider_id]: "" };
    try {
      const result = await api.testNotificationProvider(p.provider_id);
      rowStatus = { ...rowStatus, [p.provider_id]: result.ok ? "Test sent successfully." : `Test failed: ${result.detail}` };
    } catch (err) {
      rowStatus = { ...rowStatus, [p.provider_id]: err instanceof ApiError ? err.message : String(err) };
    } finally {
      rowBusy = { ...rowBusy, [p.provider_id]: false };
    }
  }

  const columns: Column<NotificationProvider>[] = [
    { key: "display_name", label: "Name", sortValue: (p) => p.display_name, minWidth: 16 },
    { key: "kind", label: "Kind", sortValue: (p) => p.kind, minWidth: 10 },
    { key: "has_secret", label: "Credential", sortValue: (p) => (p.has_secret ? 1 : 0), minWidth: 12 },
    { key: "enabled", label: "Enabled", sortValue: (p) => (p.enabled ? 1 : 0), minWidth: 8 },
    { key: "actions", label: "Actions", minWidth: 28 },
  ];
</script>

<section aria-labelledby="notifications-heading" class="notifications">
  <h2 id="notifications-heading">Notifications</h2>
  <p class="scope-note">
    Provider metadata and credentials are both real: a saved credential is sealed with this
    appliance's own native Go secrets subsystem and never displayed back. Send Test performs a
    real send. Automatic event-triggered dispatch is not built yet -- see the parity matrix.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <form class="add-form" onsubmit={createProvider}>
    <div class="add-form-row">
      <select bind:value={kind}>
        <option value="webhook">Webhook</option>
        <option value="email_smtp">Email (SMTP)</option>
        <option value="pushover">Pushover</option>
        <option value="slack">Slack</option>
      </select>
      <input placeholder="Display name" bind:value={displayName} aria-label="Display name" required />
    </div>
    {#if kind === "email_smtp"}
      <div class="add-form-row">
        <input placeholder="SMTP host" bind:value={smtpHost} aria-label="SMTP host" required />
        <input type="number" placeholder="Port" bind:value={smtpPort} aria-label="SMTP port" min="1" max="65535" required />
        <input placeholder="From address" bind:value={smtpFrom} aria-label="From address" required />
        <input placeholder="To address" bind:value={smtpTo} aria-label="To address" required />
        <input placeholder="Username (optional)" bind:value={smtpUsername} aria-label="SMTP username" />
      </div>
    {/if}
    <div class="add-form-row">
      <input placeholder={secretLabel[kind]} bind:value={secretValue} aria-label={secretLabel[kind]} data-secret-input />
      <button type="submit" disabled={createBusy}>{createBusy ? "Adding…" : "Add provider"}</button>
    </div>
  </form>
  {#if createError}<p class="error" role="alert">{createError}</p>{/if}

  <DataGrid gridId="notification-providers" {columns} rows={providers} rowKey={(p) => p.provider_id} emptyMessage="No notification providers yet.">
    {#snippet cell(p, colKey)}
      {#if colKey === "display_name"}
        {p.display_name}
      {:else if colKey === "kind"}
        {p.kind}
      {:else if colKey === "has_secret"}
        {p.has_secret ? "Configured" : "Not set"}
      {:else if colKey === "enabled"}
        {p.enabled ? "Yes" : "No"}
      {:else if colKey === "actions"}
        <div class="actions">
          <button onclick={() => toggle(p)} disabled={rowBusy[p.provider_id]}>{p.enabled ? "Disable" : "Enable"}</button>
          {#if replaceTarget === p.provider_id}
            <input placeholder={secretLabel[p.kind]} bind:value={replaceValue} aria-label="Replace credential" data-replace-secret-input />
            <button onclick={() => submitReplaceSecret(p.provider_id)} disabled={rowBusy[p.provider_id]}>Save</button>
            <button onclick={() => (replaceTarget = null)}>Cancel</button>
          {:else}
            <button
              onclick={() => {
                replaceTarget = p.provider_id;
                replaceValue = "";
              }}>{p.has_secret ? "Replace" : "Set"} credential</button
            >
            {#if p.has_secret}<button onclick={() => revokeSecret(p)} disabled={rowBusy[p.provider_id]}>Revoke</button>{/if}
          {/if}
          <button onclick={() => sendTest(p)} disabled={rowBusy[p.provider_id] || !p.has_secret} data-send-test>Send Test</button>
          <button onclick={() => remove(p)}>Delete</button>
        </div>
        {#if rowStatus[p.provider_id]}<p class="row-status" data-test-result>{rowStatus[p.provider_id]}</p>{/if}
      {/if}
    {/snippet}
  </DataGrid>
</section>

<style>
  .notifications { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .add-form { display: flex; flex-direction: column; gap: 0.5rem; }
  .add-form-row { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
  .add-form input { flex: 1; min-width: 10rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; }
  .row-status { font-size: 0.8rem; opacity: 0.8; margin: 0.25rem 0 0; }
  .error { color: var(--badge-danger-fg); }
</style>
