<script lang="ts">
  import { onMount } from "svelte";
  import {
    api,
    ApiError,
    type NotificationProvider,
    type NotificationEventCategory,
    type NotificationSubscription,
    type NotificationHistoryEntry,
  } from "../api";
  import { StaleGuard } from "../staleGuard";
  import { router } from "../router.svelte";
  import DataGrid from "./DataGrid.svelte";
  import type { Column } from "./datagrid";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";
  import Modal from "./ui/Modal.svelte";

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
  // Event Subscriptions/Delivery History (2026-08-28): the real
  // dispatch engine (internal/notifications' Dispatch) -- a subscribed
  // provider now genuinely receives a message when a real condition
  // fires (blocklist_update_failure, deploy_failure today; see each
  // category's own "wired" flag below for exactly which are real vs.
  // available-to-subscribe-to-but-not-yet-triggered).

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
  let addProviderOpen = $state(false);

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

  // Event Subscriptions
  let eventCategories = $state<NotificationEventCategory[]>([]);
  let subscriptions = $state<NotificationSubscription[]>([]);
  let subsLoadError = $state("");
  const subsGuard = new StaleGuard();

  let subProviderId = $state("");
  let subEventCategory = $state("");
  let subMinSeverity = $state<"info" | "warning" | "critical">("warning");
  let subCooldown = $state<number | "">("");
  let addSubError = $state("");
  let addSubBusy = $state(false);

  async function refreshSubscriptions() {
    const token = subsGuard.start();
    try {
      const [cats, subs] = await Promise.all([api.listEventCategories(router.signal()), api.listNotificationSubscriptions(router.signal())]);
      if (!subsGuard.isCurrent(token)) return;
      eventCategories = cats.categories;
      subscriptions = subs.subscriptions;
      if (!subEventCategory && eventCategories.length > 0) subEventCategory = eventCategories[0].key;
      subsLoadError = "";
    } catch (err) {
      if (!subsGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      subsLoadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function addSubscription(e: Event) {
    e.preventDefault();
    if (!subProviderId || !subEventCategory) return;
    addSubError = "";
    addSubBusy = true;
    try {
      await api.createNotificationSubscription(subProviderId, subEventCategory, subMinSeverity, true, subCooldown === "" ? null : Number(subCooldown));
      subCooldown = "";
      await refreshSubscriptions();
    } catch (err) {
      addSubError = err instanceof ApiError ? err.message : String(err);
    } finally {
      addSubBusy = false;
    }
  }

  let confirmRemoveSubscription = $state<NotificationSubscription | null>(null);

  function removeSubscription(sub: NotificationSubscription) {
    confirmRemoveSubscription = sub;
  }

  async function runRemoveSubscription() {
    const sub = confirmRemoveSubscription;
    confirmRemoveSubscription = null;
    if (!sub) return;
    await api.deleteNotificationSubscription(sub.id);
    await refreshSubscriptions();
  }

  function categoryLabel(key: string): string {
    return eventCategories.find((c) => c.key === key)?.label ?? key;
  }
  function categoryWired(key: string): boolean {
    return eventCategories.find((c) => c.key === key)?.wired ?? false;
  }

  // Delivery History
  let history = $state<NotificationHistoryEntry[]>([]);
  let historyLoadError = $state("");
  const enabledProviderCount = $derived(providers.filter((p) => p.enabled).length);
  const failedDeliveryCount = $derived(history.filter((h) => h.status === "failed").length);
  const historyGuard = new StaleGuard();

  async function refreshHistory() {
    const token = historyGuard.start();
    try {
      const resp = await api.listNotificationHistory(100, router.signal());
      if (!historyGuard.isCurrent(token)) return;
      history = resp.history;
      historyLoadError = "";
    } catch (err) {
      if (!historyGuard.isCurrent(token)) return;
      if (err instanceof DOMException && err.name === "AbortError") return;
      historyLoadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
    refreshSubscriptions();
    refreshHistory();
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
      // A real, previously-undisclosed "UI Truth" gap: this is two
      // separate API calls (the provider row itself, then a follow-up
      // credential seal that runs entirely inside apdns-hostagent, see
      // this file's own doc comment) inside one try/catch. If the
      // credential call failed for ANY reason -- hostagent transiently
      // unreachable, a bad secret value -- the provider row that
      // genuinely, already exists server-side never reached refresh(),
      // so the grid kept showing the pre-creation list while the error
      // banner implied nothing happened at all. Refresh unconditionally
      // once the provider itself is confirmed created, then surface the
      // secret failure (if any) separately -- the real row is real
      // regardless of whether its credential attempt also succeeded.
      displayName = "";
      smtpHost = smtpFrom = smtpTo = smtpUsername = "";
      smtpPort = 587;
      let secretErr: unknown = null;
      if (secretValue.trim()) {
        try {
          await api.setNotificationSecret(p.provider_id, secretValue);
        } catch (err) {
          secretErr = err;
        }
      }
      secretValue = "";
      await refresh();
      if (secretErr) {
        createError = `Provider "${p.display_name}" was created, but setting its credential failed: ${secretErr instanceof ApiError ? secretErr.message : String(secretErr)}`;
      } else {
        addProviderOpen = false;
      }
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

  let confirmRemoveProvider = $state<NotificationProvider | null>(null);

  function remove(p: NotificationProvider) {
    confirmRemoveProvider = p;
  }

  async function runRemoveProvider() {
    const p = confirmRemoveProvider;
    confirmRemoveProvider = null;
    if (!p) return;
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
    real send. Event Subscriptions below trigger a real automatic send when a subscribed
    condition actually fires -- see each category's own "wired" state for what's real today.
  </p>

  <div class="status-summary">
    <span>Notification system: <strong>{enabledProviderCount > 0 ? `${enabledProviderCount} destination${enabledProviderCount === 1 ? "" : "s"} enabled` : "no destinations enabled"}</strong></span>
    <span>Last sent: <strong>{history[0] ? history[0].at : "never"}</strong></span>
    <span>Failed deliveries (recent history): <strong class={failedDeliveryCount > 0 ? "attention" : ""}>{failedDeliveryCount}</strong></span>
  </div>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="section-head">
    <h3>Destinations</h3>
    <button type="button" onclick={() => (addProviderOpen = true)}>Add Destination</button>
  </div>

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

  <h3>Event Subscriptions</h3>
  <p class="scope-note">
    A subscribed provider is sent a message when the event actually fires. Categories marked "not wired yet" can be subscribed to now, but won't trigger a notification until that event type is implemented.
  </p>
  {#if subsLoadError}<p class="error" role="alert">{subsLoadError}</p>{/if}
  <form class="add-form-row" onsubmit={addSubscription}>
    <select bind:value={subProviderId} aria-label="Provider" required disabled={providers.length === 0}>
      <option value="" disabled>Choose a provider…</option>
      {#each providers as p}
        <option value={p.provider_id}>{p.display_name}</option>
      {/each}
    </select>
    <select bind:value={subEventCategory} aria-label="Event category">
      {#each eventCategories as c}
        <option value={c.key}>{c.label}{c.wired ? "" : " (not wired yet)"}</option>
      {/each}
    </select>
    <select bind:value={subMinSeverity} aria-label="Minimum severity">
      <option value="info">Info and above</option>
      <option value="warning">Warning and above</option>
      <option value="critical">Critical only</option>
    </select>
    <input type="number" min="0" placeholder="Cooldown (min, default 30)" bind:value={subCooldown} aria-label="Cooldown minutes" style="max-width:11rem" />
    <button type="submit" disabled={addSubBusy || providers.length === 0}>{addSubBusy ? "Adding…" : "Subscribe"}</button>
  </form>
  {#if addSubError}<p class="error" role="alert">{addSubError}</p>{/if}
  {#if providers.length === 0}
    <p class="hint">Add a notification provider above before creating a subscription.</p>
  {:else if subscriptions.length === 0}
    <p class="hint">No event subscriptions yet.</p>
  {:else}
    <ul class="sub-list">
      {#each subscriptions as sub (sub.id)}
        <li class="sub-row">
          <strong>{sub.provider_name}</strong>
          <span>{categoryLabel(sub.event_category)}</span>
          {#if !categoryWired(sub.event_category)}<span class="badge-neutral">not wired yet</span>{/if}
          <span class="hint">{sub.min_severity}+, cooldown {sub.cooldown_minutes ?? 30}m</span>
          <button type="button" class="secondary small" onclick={() => removeSubscription(sub)}>Remove</button>
        </li>
      {/each}
    </ul>
  {/if}

  <h3>Delivery History</h3>
  {#if historyLoadError}<p class="error" role="alert">{historyLoadError}</p>{/if}
  {#if history.length === 0 && !historyLoadError}
    <p class="hint">No deliveries recorded yet.</p>
  {:else}
    <div class="table-wrap">
      <table class="history-table">
        <thead><tr><th>At</th><th>Event</th><th>Severity</th><th>Provider</th><th>Status</th><th>Message</th></tr></thead>
        <tbody>
          {#each history as h (h.id)}
            <tr>
              <td class="mono">{h.at}</td>
              <td>{categoryLabel(h.event_category)}</td>
              <td>{h.severity}</td>
              <td>{h.provider_name}</td>
              <td><span class="status-{h.status}">{h.status}</span>{#if h.error} <span class="hint">({h.error})</span>{/if}</td>
              <td>{h.message}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

{#if confirmRemoveProvider}
  <ConfirmDialog
    title="Delete provider"
    message={`Delete the "${confirmRemoveProvider.display_name}" provider? Any saved secret is discarded and subscriptions using it stop delivering.`}
    confirmLabel="Delete"
    onConfirm={runRemoveProvider}
    onCancel={() => (confirmRemoveProvider = null)}
  />
{/if}

{#if confirmRemoveSubscription}
  <ConfirmDialog
    title="Remove subscription"
    message={`Remove the "${categoryLabel(confirmRemoveSubscription.event_category)}" notification via ${confirmRemoveSubscription.provider_name}?`}
    confirmLabel="Remove"
    onConfirm={runRemoveSubscription}
    onCancel={() => (confirmRemoveSubscription = null)}
  />
{/if}

{#if addProviderOpen}
  <Modal title="Add Destination" onClose={() => (addProviderOpen = false)}>
    <form class="modal-form" onsubmit={createProvider}>
      <label>
        Kind
        <select bind:value={kind}>
          <option value="webhook">Webhook</option>
          <option value="email_smtp">Email (SMTP)</option>
          <option value="pushover">Pushover</option>
          <option value="slack">Slack</option>
        </select>
      </label>
      <label>Display name <input required aria-label="Display name" bind:value={displayName} placeholder="e.g. Ops Slack channel" /></label>
      {#if kind === "email_smtp"}
        <label>SMTP host <input required bind:value={smtpHost} placeholder="smtp.example.com" /></label>
        <label>SMTP port <input required type="number" bind:value={smtpPort} /></label>
        <label>From address <input required bind:value={smtpFrom} placeholder="alerts@example.com" /></label>
        <label>To address <input required bind:value={smtpTo} placeholder="oncall@example.com" /></label>
        <label>Username <input bind:value={smtpUsername} placeholder="optional" /></label>
      {/if}
      <label>{secretLabel[kind]} <input data-secret-input bind:value={secretValue} placeholder={secretLabel[kind]} /></label>
      <div class="form-actions">
        <button type="submit" disabled={createBusy}>{createBusy ? "Adding…" : "Add Destination"}</button>
        <button type="button" class="secondary" onclick={() => (addProviderOpen = false)}>Cancel</button>
      </div>
      {#if createError}<p class="error" role="alert">{createError}</p>{/if}
    </form>
  </Modal>
{/if}

<style>
  .notifications { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .status-summary {
    display: flex; flex-wrap: wrap; gap: 0.75rem 1.5rem; font-size: 0.85rem; margin: 0.5rem 0 1rem;
    padding: 0.75rem 1rem; border: 1px solid var(--border); border-radius: 8px; background: var(--panel-elevated);
  }
  .status-summary .attention { color: var(--warning); }
  .section-head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-top: 0.5rem; }
  .section-head h3 { margin: 0; }
  .add-form-row { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
  .add-form-row input { flex: 1; min-width: 10rem; }
  .modal-form { display: flex; flex-direction: column; gap: 0.75rem; }
  .modal-form label { display: flex; flex-direction: column; gap: 0.25rem; font-size: 0.85rem; }
  .form-actions { display: flex; gap: 0.5rem; }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; align-items: center; }
  .row-status { font-size: 0.8rem; opacity: 0.8; margin: 0.25rem 0 0; }
  .error { color: var(--badge-danger-fg); }
  .hint { font-size: 0.85rem; opacity: 0.75; }
  .sub-list { list-style: none; margin: 0.5rem 0; padding: 0; display: flex; flex-direction: column; gap: 0.4rem; }
  .sub-row { display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap; }
  .badge-neutral { background: var(--nav-hover-bg); padding: 0.1rem 0.5rem; border-radius: 999px; font-size: 0.72rem; opacity: 0.85; }
  button.secondary.small { min-height: auto; padding: 0.3rem 0.6rem; font-size: 0.8rem; }
  .table-wrap { overflow-x: auto; }
  .history-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  .history-table th, .history-table td { text-align: left; padding: 0.35rem 0.6rem; border-bottom: 1px solid var(--border); white-space: nowrap; }
  .history-table td:last-child { white-space: normal; }
  .mono { font-family: monospace; font-size: 0.8rem; }
  .status-sent { color: var(--success); }
  .status-failed { color: var(--badge-danger-fg); }
  .status-suppressed { opacity: 0.7; }
</style>
