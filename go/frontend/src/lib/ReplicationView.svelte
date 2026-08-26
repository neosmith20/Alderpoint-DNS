<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type ReplicationStatusResponse } from "../api";
  import { router } from "../router.svelte";
  import { timestampPref } from "../timestamp.svelte";

  // Replication. Real, via apdns-hostagent's narrow, read-only,
  // redacted read of Python's own control.db (never a raw mount into
  // this web process -- see internal/hostagentd/ops_replication.go's
  // doc comment). Peer credentials (ca_pem/client_cert_pem/
  // client_key_pem) are never selected by that reader at all, so they
  // can never reach this page even by accident.
  //
  // Sync is a real, bounded HTTPS connectivity check against the peer's
  // configured URL (validated against its configured CA) -- not
  // Python's own bespoke mTLS push/pull state-sync protocol, which is
  // out of scope for this pass and disclosed as such rather than
  // half-implemented.

  let status = $state<ReplicationStatusResponse | null>(null);
  let loadError = $state("");
  let syncBusy = $state<string | null>(null);
  let syncResult = $state("");

  async function refresh() {
    loadError = "";
    try {
      status = await api.replicationStatus(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
  });

  async function sync(peerNodeId: string) {
    syncBusy = peerNodeId;
    syncResult = "";
    try {
      const result = await api.replicationSync(peerNodeId);
      syncResult = result.ok ? `Reachable: ${result.detail} (${result.elapsed_ms}ms)` : `Unreachable: ${result.detail}`;
      await refresh();
    } catch (err) {
      syncResult = err instanceof ApiError ? err.message : String(err);
    } finally {
      syncBusy = null;
    }
  }
</script>

<section aria-labelledby="replication-heading" class="replication">
  <h2 id="replication-heading">Replication</h2>
  <p class="scope-note">
    Peer metadata is a real, redacted read of Python's own control.db (no credentials ever leave that
    read). Sync is a real connectivity check against each peer's configured URL, not a full state
    push/pull -- see the parity matrix.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}
  {#if syncResult}<p class="hint" role="status">{syncResult}</p>{/if}

  <div class="card">
    <h3>Node Identity</h3>
    {#if status?.node_identity}
      <p><code>{status.node_identity.node_id}</code></p>
      <p class="hint">Created {timestampPref.format(status.node_identity.created_at)}</p>
    {:else if status}
      <p class="hint">No node identity found.</p>
    {:else}
      <p class="hint">Loading…</p>
    {/if}
  </div>

  <div class="card">
    <h3>Peers</h3>
    {#if !status}
      <p class="hint">Loading…</p>
    {:else if status.peers.length === 0}
      <p class="hint">No replication peers configured.</p>
    {:else}
      <table>
        <thead><tr><th>Peer</th><th>URL</th><th>Direction</th><th>Last success</th><th>Lag</th><th>Actions</th></tr></thead>
        <tbody>
          {#each status.peers as peer (peer.peer_node_id)}
            <tr>
              <td>{peer.display_name}</td>
              <td>{peer.url}</td>
              <td>{peer.direction}</td>
              <td>{peer.last_success_at ? timestampPref.format(peer.last_success_at) : "never"}</td>
              <td>{peer.lag}</td>
              <td>
                <button onclick={() => sync(peer.peer_node_id)} disabled={syncBusy === peer.peer_node_id}>
                  {syncBusy === peer.peer_node_id ? "Checking…" : "Check connectivity"}
                </button>
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    {/if}
  </div>
</section>

<style>
  .replication { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
  th, td { text-align: left; padding: 0.3rem 0.6rem; border-bottom: 1px solid var(--border); }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .error { color: var(--badge-danger-fg); }
</style>
