<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type ReplicationStatusResponse } from "../api";
  import { timestampPref } from "../timestamp.svelte";
  import ConfirmDialog from "./ui/ConfirmDialog.svelte";

  // Replication (rebuilt 2026-08-29, real Go-native): one-way primary-
  // to-replica configuration sync over mutual TLS, rebuilt against
  // V1.1.1's actual owner-facing workflow (app/replication.py, read
  // directly) -- node identity, token-based enrollment, numbered
  // content-hashed generations, drift detection. See internal/
  // replication's own doc comment for the exact replicable-table
  // allowlist and the two deliberate differences from V1.1.1 (the
  // table allowlist is translated to this Go-native schema; the CA
  // private key is sealed via this control plane's own Go-native
  // secrets subsystem, apdns-hostagent's AES-256-GCM engine, instead of
  // Python's SecretStore). Manual promotion (replica -> primary) is
  // still a deliberate, documented, non-automated action -- no
  // automatic bidirectional failover, matching V1.1.1's own choice.

  let status = $state<ReplicationStatusResponse | null>(null);
  let loadError = $state("");
  let busy = $state(false);
  let actionError = $state("");
  let actionResult = $state("");

  let roleChoice = $state<"standalone" | "primary" | "replica">("standalone");
  let newNodeName = $state("");
  let issuedToken = $state<{ token: string; node_name: string; expires_at: string } | null>(null);
  let connectHost = $state("");
  let connectPort = $state(8843);
  let connectToken = $state("");

  async function refresh() {
    loadError = "";
    try {
      status = await api.replicationStatus();
      roleChoice = status.settings.role;
    } catch (err) {
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function run<T>(action: () => Promise<T>, successMessage: string) {
    busy = true;
    actionError = "";
    actionResult = "";
    try {
      await action();
      actionResult = successMessage;
      await refresh();
    } catch (err) {
      actionError = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  // Shared ConfirmDialog for every destructive/impactful replication
  // action on this page, replacing four separate native window.confirm()
  // call sites -- same pattern as Clients & Access's own pendingConfirm.
  let pendingConfirm = $state<{ title: string; message: string; confirmLabel: string; run: () => void } | null>(null);

  function askConfirm(title: string, message: string, confirmLabel: string, doRun: () => void) {
    pendingConfirm = { title, message, confirmLabel, run: doRun };
  }

  function runPendingConfirm() {
    if (!pendingConfirm) return;
    const { run: doRun } = pendingConfirm;
    pendingConfirm = null;
    doRun();
  }

  function saveRole(e: Event) {
    e.preventDefault();
    askConfirm(
      "Change replication role",
      "Change this node's replication role? Switching away from a role stops its listener/sync activity, but never interrupts DNS service.",
      "Change role",
      () => run(() => api.replicationSetRole(roleChoice), "Role updated."),
    );
  }

  function generateToken(e: Event) {
    e.preventDefault();
    issuedToken = null;
    run(async () => {
      issuedToken = await api.replicationGenerateToken(newNodeName);
      newNodeName = "";
    }, "Enrollment token generated -- copy it now, it is shown once.");
  }

  function revokeEnrollment(id: number) {
    askConfirm("Revoke enrollment token", "Revoke this enrollment token before it is used?", "Revoke", () =>
      run(() => api.replicationRevokeEnrollment(id), "Enrollment revoked."),
    );
  }

  function setReplicaStatus(id: number, newStatus: string) {
    if (newStatus === "revoked") {
      askConfirm(
        "Revoke replica",
        "Revoke this replica? Its certificate will no longer be accepted even though it remains cryptographically valid.",
        "Revoke",
        () => run(() => api.replicationSetReplicaStatus(id, newStatus), `Replica ${newStatus}.`),
      );
      return;
    }
    run(() => api.replicationSetReplicaStatus(id, newStatus), `Replica ${newStatus}.`);
  }

  function publishGeneration() {
    run(() => api.replicationPublishGeneration(), "New generation published.");
  }

  function connect(e: Event) {
    e.preventDefault();
    askConfirm(
      "Connect and enroll",
      "Connect to this primary and enroll? This installs a client certificate and starts syncing.",
      "Connect",
      () =>
        run(async () => {
          await api.replicationConnect(connectHost, connectPort, connectToken);
          connectHost = connectToken = "";
        }, "Enrolled. Sync will begin shortly."),
    );
  }

  function syncNow() {
    run(() => api.replicationSyncNow(), "Sync requested.");
  }

  function driftCheck() {
    run(() => api.replicationDriftCheck(), "Drift check complete.");
  }

  function togglePause() {
    if (!status) return;
    run(() => api.replicationPause(!status!.settings.paused), status.settings.paused ? "Sync resumed." : "Sync paused.");
  }

  let listenHost = $state("0.0.0.0");
  let listenPort = $state(8843);
  let pollIntervalSeconds = $state(60);
  let includeEncryptionSettings = $state(false);

  $effect(() => {
    if (!status) return;
    listenHost = status.settings.listen_host;
    listenPort = status.settings.listen_port;
    pollIntervalSeconds = status.settings.poll_interval_seconds;
    includeEncryptionSettings = status.settings.include_encryption_settings;
  });

  function saveSettings(e: Event) {
    e.preventDefault();
    run(() => api.replicationSettings({ listen_host: listenHost, listen_port: listenPort, poll_interval_seconds: pollIntervalSeconds, include_encryption_settings: includeEncryptionSettings }), "Settings saved.");
  }

  function resultBadgeClass(result: string): string {
    if (result === "success" || result === "up_to_date") return "badge-ok";
    if (result === "failed" || result === "error") return "badge-danger";
    return "badge-neutral";
  }
</script>

<section aria-labelledby="replication-heading" class="replication">
  <h2 id="replication-heading">Replication</h2>
  <p class="scope-note">
    One-way primary-to-replica configuration sync over mutual TLS. Node identity, token-based
    enrollment, numbered content-hashed generations, and drift detection are all real. Manual
    promotion (replica &rarr; primary) is a deliberate, documented action -- there is no automatic
    failover.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  {#if actionResult}<p class="success" role="status">{actionResult}</p>{/if}
  {#if actionError}<p class="error" role="alert">{actionError}</p>{/if}

  {#if status}
    <section class="grid">
      <article class="card">
        <h3>Role</h3>
        <p class="value">{status.settings.role}</p>
        <p class="hint mono">node id: {status.settings.node_id}</p>
      </article>
      {#if status.settings.role === "primary"}
        <article class="card">
          <h3>Listener</h3>
          <p class="value">{status.listener_running ? "Running" : "Stopped"}</p>
          <p class="hint mono">{status.settings.listen_host}:{status.settings.listen_port}</p>
        </article>
        <article class="card">
          <h3>Latest Generation</h3>
          {#if status.latest_generation}
            <p class="value mono">#{status.latest_generation.generation_number}</p>
            <p class="hint mono wrap-anywhere">{status.latest_generation.content_hash}</p>
          {:else}
            <p class="hint">No generation published yet.</p>
          {/if}
        </article>
        <article class="card">
          <h3>Replicas</h3>
          <p class="value">{status.replicas?.length ?? 0} enrolled</p>
        </article>
      {:else if status.settings.role === "replica"}
        <article class="card">
          <h3>Primary</h3>
          <p class="value">{status.settings.paused ? "Paused" : "Active"}</p>
          <p class="hint mono">{status.settings.primary_address || "not connected"}</p>
        </article>
        <article class="card">
          <h3>Last Applied</h3>
          <p class="value mono">generation #{status.settings.last_applied_generation}</p>
          <p class="hint">{status.settings.last_sync_status || "never synced"}</p>
        </article>
        <article class="card">
          <h3>Drift</h3>
          <p class="value">{status.settings.drift_detected ? "Drifted" : "In sync"}</p>
          <p class="hint mono">{status.settings.drift_checked_at || "not checked yet"}</p>
        </article>
      {/if}
    </section>

    <div class="card">
      <h3>Node Role</h3>
      <form onsubmit={saveRole} class="row-form">
        <label>
          Role
          <select bind:value={roleChoice}>
            <option value="standalone">Standalone</option>
            <option value="primary">Primary</option>
            <option value="replica">Replica</option>
          </select>
        </label>
        <button type="submit" disabled={busy}>Save role</button>
      </form>
    </div>

    {#if status.settings.role === "primary"}
      <div class="grid">
        <form class="card" onsubmit={generateToken}>
          <h3>Clone to Replica</h3>
          <label>New replica name <input bind:value={newNodeName} placeholder="replica-1" required /></label>
          <p class="hint">Generates a one-time, single-use enrollment token, valid for 15 minutes.</p>
          <button type="submit" disabled={busy || !newNodeName.trim()}>Generate enrollment token</button>
        </form>
        {#if issuedToken}
          <div class="card">
            <h3>Enrollment Token</h3>
            <p class="hint">This token is shown once. Copy it now.</p>
            <p class="mono wrap-anywhere">{issuedToken.token}</p>
            <p class="hint">For <span class="mono">{issuedToken.node_name}</span>, expires {issuedToken.expires_at}.</p>
            <p class="hint">Give the replica this primary's reachable address (not <span class="mono">0.0.0.0</span>) and port <span class="mono">{status.settings.listen_port}</span> along with the token above.</p>
          </div>
        {/if}
      </div>

      <div class="card">
        <div class="section-header"><h3>Pending Enrollments</h3></div>
        {#if status.enrollments && status.enrollments.length > 0}
          <table>
            <thead><tr><th>Name</th><th>Created</th><th>Expires</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {#each status.enrollments as e (e.id)}
                <tr>
                  <td>{e.node_name}</td>
                  <td class="mono">{timestampPref.format(e.created_at)}</td>
                  <td class="mono">{timestampPref.format(e.expires_at)}</td>
                  <td><span class="badge {e.status === 'consumed' ? 'badge-ok' : e.status === 'pending' ? 'badge-neutral' : 'badge-danger'}">{e.status}</span></td>
                  <td>
                    {#if e.status === "pending"}
                      <button onclick={() => revokeEnrollment(e.id)} disabled={busy}>Revoke</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="hint">No enrollments yet.</p>
        {/if}
      </div>

      <div class="card">
        <div class="section-header"><h3>Replica Health</h3></div>
        {#if status.replicas && status.replicas.length > 0}
          <table>
            <thead><tr><th>Name</th><th>Status</th><th>Last seen</th><th>Last generation acked</th><th>Last result</th><th>Actions</th></tr></thead>
            <tbody>
              {#each status.replicas as r (r.id)}
                <tr>
                  <td>{r.display_name}</td>
                  <td><span class="badge {r.status === 'active' ? 'badge-ok' : r.status === 'revoked' ? 'badge-danger' : 'badge-neutral'}">{r.status}</span></td>
                  <td class="mono">{r.last_seen_at ? timestampPref.format(r.last_seen_at) : "never"}</td>
                  <td class="mono">{r.last_generation_acked}</td>
                  <td>{r.last_result || "—"}</td>
                  <td class="actions">
                    {#if r.status !== "paused"}
                      <button onclick={() => setReplicaStatus(r.id, "paused")} disabled={busy}>Pause</button>
                    {:else}
                      <button onclick={() => setReplicaStatus(r.id, "active")} disabled={busy}>Resume</button>
                    {/if}
                    {#if r.status !== "revoked"}
                      <button class="danger" onclick={() => setReplicaStatus(r.id, "revoked")} disabled={busy}>Revoke</button>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="hint">No replicas enrolled yet.</p>
        {/if}
      </div>

      <div class="card">
        <h3>Publish</h3>
        <p class="hint">
          Publish this node's current replicable state as a new generation, so enrolled replicas
          can pick it up on their next sync.
        </p>
        <button onclick={publishGeneration} disabled={busy}>Publish generation now</button>
      </div>

      <form class="card" onsubmit={saveSettings}>
        <h3>Primary Settings</h3>
        <div class="grid compact">
          <label>Listen address <input bind:value={listenHost} /></label>
          <label>Listen port <input type="number" min="1" max="65535" bind:value={listenPort} /></label>
          <label class="row"><input type="checkbox" bind:checked={includeEncryptionSettings} /> Include Encryption Settings in generations</label>
        </div>
        <button type="submit" disabled={busy}>Save settings</button>
      </form>
    {/if}

    {#if status.settings.role === "replica"}
      <div class="grid">
        <form class="card" onsubmit={connect}>
          <h3>Connect to Primary</h3>
          <label>Primary address <input bind:value={connectHost} placeholder="192.168.1.10" required /></label>
          <label>Primary port <input type="number" min="1" max="65535" bind:value={connectPort} /></label>
          <label>Enrollment token <input bind:value={connectToken} required /></label>
          <button type="submit" disabled={busy}>Enroll</button>
        </form>
        <div class="card">
          <h3>Sync Controls</h3>
          <div class="actions">
            <button onclick={syncNow} disabled={busy}>Sync now</button>
            <button onclick={driftCheck} disabled={busy}>Check drift</button>
            <button onclick={togglePause} disabled={busy}>{status.settings.paused ? "Resume sync" : "Pause sync"}</button>
          </div>
        </div>
      </div>

      <div class="card">
        <div class="section-header"><h3>Sync History</h3></div>
        {#if status.sync_history && status.sync_history.length > 0}
          <table>
            <thead><tr><th>Attempted</th><th>Generation</th><th>Result</th><th>Message</th></tr></thead>
            <tbody>
              {#each status.sync_history as h, i (i)}
                <tr>
                  <td class="mono">{timestampPref.format(h.attempted_at)}</td>
                  <td class="mono">{h.generation_number ?? "—"}</td>
                  <td><span class="badge {resultBadgeClass(h.result)}">{h.result}</span></td>
                  <td>{h.message}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {:else}
          <p class="hint">No sync attempts yet.</p>
        {/if}
      </div>

      <form class="card" onsubmit={saveSettings}>
        <h3>Poll Settings</h3>
        <label>Poll interval (seconds) <input type="number" min="5" max="3600" bind:value={pollIntervalSeconds} /></label>
        <button type="submit" disabled={busy}>Save settings</button>
      </form>
    {/if}

    <div class="card">
      <h3>Manual Promotion</h3>
      <p class="hint">
        Promoting a replica to primary is a manual, deliberate action, not an automated failover --
        automatic bidirectional sync is intentionally not implemented.
      </p>
    </div>
  {:else if !loadError}
    <p class="hint">Loading…</p>
  {/if}
</section>

{#if pendingConfirm}
  <ConfirmDialog
    title={pendingConfirm.title}
    message={pendingConfirm.message}
    confirmLabel={pendingConfirm.confirmLabel}
    onConfirm={runPendingConfirm}
    onCancel={() => (pendingConfirm = null)}
  />
{/if}

<style>
  .replication { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(14rem, 1fr)); gap: 1rem; }
  .grid.compact { grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.6rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  .card .value { font-size: 1.1rem; font-weight: 600; margin: 0; }
  .card label { display: flex; flex-direction: column; gap: 0.2rem; font-size: 0.85rem; }
  .card label.row { flex-direction: row; align-items: center; gap: 0.4rem; }
  .row-form { display: flex; align-items: flex-end; gap: 0.75rem; }
  .section-header { display: flex; justify-content: space-between; align-items: center; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .mono { font-family: monospace; }
  .wrap-anywhere { overflow-wrap: anywhere; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .success { color: #16a34a; }
  .error { color: var(--badge-danger-fg); }
  .actions { display: flex; gap: 0.4rem; flex-wrap: wrap; }
  .badge { padding: 0.15rem 0.5rem; border-radius: 999px; font-size: 0.78rem; }
  .badge-ok { background: var(--badge-ok-bg); color: var(--badge-ok-fg); }
  .badge-danger { background: var(--badge-danger-bg); color: var(--badge-danger-fg); }
  .badge-neutral { background: var(--border); color: var(--text); }
  button.danger { color: var(--badge-danger-fg); border-color: var(--badge-danger-fg); }
</style>
