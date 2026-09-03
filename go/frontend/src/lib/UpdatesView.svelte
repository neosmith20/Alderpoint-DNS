<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type UpdateCheckResponse, type UpdateChannel } from "../api";
  import { router } from "../router.svelte";
  import StatusBadge from "./ui/StatusBadge.svelte";
  import PageHeader from "./ui/PageHeader.svelte";

  // Software Updates. Real, for this control plane's own Go binary --
  // deliberately not Python's apt/dpkg package (see the parity matrix:
  // installing an arbitrary uploaded .deb is real root package
  // management and stays out of scope). Real checksum + self-reported-
  // version verification before a candidate is ever trusted, and a real
  // health-check-gated rollback if a newly applied version doesn't come
  // back up healthy -- see internal/hostagentd/ops_update.go, proven
  // end-to-end against real compiled binaries in its own test suite.
  //
  // Update channel (internal/softwareupdates): a real GitHub Releases
  // feed, owner-confirmed real coordinates -- "Check for updates" hits
  // it live; "Download & Stage" fetches the checksum-verified .deb and
  // feeds it into the exact same stage/apply pipeline manual upload
  // already uses below.

  let status = $state<UpdateCheckResponse | null>(null);
  let loadError = $state("");
  let channel = $state<UpdateChannel | null>(null);
  let channelError = $state("");

  let channelOwner = $state("");
  let channelRepo = $state("");
  let channelToken = $state("");
  let channelBusy = $state(false);
  let channelSaveResult = $state("");

  let checkBusy = $state(false);
  let checkError = $state("");

  let downloadBusy = $state(false);
  let downloadError = $state("");
  let downloadResult = $state("");

  let file: FileList | undefined = $state();
  let claimedVersion = $state("");
  let stageBusy = $state(false);
  let stageError = $state("");
  let stageResult = $state("");

  let applyBusy = $state(false);
  let applyError = $state("");
  let applyResult = $state("");

  async function refresh() {
    loadError = "";
    try {
      status = await api.updateCheck(router.signal());
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      loadError = err instanceof ApiError ? err.message : String(err);
    }
  }

  async function refreshChannel() {
    channelError = "";
    try {
      channel = await api.getUpdateChannel(router.signal());
      if (channel) {
        channelOwner = channel.repo_owner;
        channelRepo = channel.repo_name;
      }
    } catch (err) {
      if (err instanceof DOMException && err.name === "AbortError") return;
      channelError = err instanceof ApiError ? err.message : String(err);
    }
  }

  onMount(() => {
    refresh();
    refreshChannel();
  });

  async function saveChannel(e: Event) {
    e.preventDefault();
    channelBusy = true;
    channelSaveResult = "";
    channelError = "";
    try {
      await api.setUpdateChannel({ repo_owner: channelOwner.trim(), repo_name: channelRepo.trim(), token: channelToken.trim() || undefined });
      channelToken = "";
      channelSaveResult = "Saved.";
      await refreshChannel();
    } catch (err) {
      channelError = err instanceof ApiError ? err.message : String(err);
    } finally {
      channelBusy = false;
    }
  }

  async function checkNow() {
    checkBusy = true;
    checkError = "";
    try {
      const resp = await api.checkForUpdate();
      channel = resp.channel;
      if (resp.error) checkError = resp.error;
    } catch (err) {
      checkError = err instanceof ApiError ? err.message : String(err);
    } finally {
      checkBusy = false;
    }
  }

  async function downloadAndStage() {
    downloadBusy = true;
    downloadError = "";
    downloadResult = "";
    try {
      const result = await api.updateDownloadAndStage();
      downloadResult = `Downloaded, verified, and staged: version ${result.version}.`;
      await refresh();
    } catch (err) {
      downloadError = err instanceof ApiError ? err.message : String(err);
    } finally {
      downloadBusy = false;
    }
  }

  let updateAvailable = $derived(
    !!channel?.latest_version && !!status?.current_version && channel.latest_version !== status.current_version,
  );

  async function sha256Hex(data: ArrayBuffer): Promise<string> {
    const digest = await crypto.subtle.digest("SHA-256", data);
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  function arrayBufferToBase64(buf: ArrayBuffer): string {
    let binary = "";
    const bytes = new Uint8Array(buf);
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary);
  }

  async function stage(e: Event) {
    e.preventDefault();
    const f = file?.[0];
    if (!f || !claimedVersion.trim()) return;
    stageBusy = true;
    stageError = "";
    stageResult = "";
    try {
      const data = await f.arrayBuffer();
      const sha256 = await sha256Hex(data);
      const dataBase64 = arrayBufferToBase64(data);
      const result = await api.updateStage(claimedVersion.trim(), sha256, dataBase64);
      stageResult = `Staged and verified: version ${result.version}.`;
      await refresh();
    } catch (err) {
      stageError = err instanceof ApiError ? err.message : String(err);
    } finally {
      stageBusy = false;
    }
  }

  async function apply() {
    applyBusy = true;
    applyError = "";
    applyResult = "";
    try {
      const result = await api.updateApply();
      applyResult = `Applied and healthy: version ${result.version}.`;
      await refresh();
    } catch (err) {
      applyError = err instanceof ApiError ? err.message : String(err);
    } finally {
      applyBusy = false;
    }
  }
</script>

<PageHeader
  headingId="updates-heading"
  title="Software Updates"
  description="Stage and apply updates to this appliance's own software -- its Go binary directly, checksum- and version-verified, not an arbitrary uploaded .deb/apt package."
/>

<div class="updates">

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <section class="status-grid">
    <div class="card">
      <h3>Current Version</h3>
      {#if loadError}
        <p class="hint error">Unavailable</p>
      {:else}
        <p class="mono">{status?.current_version ?? "…"}</p>
      {/if}
    </div>
    <div class="card">
      <h3>Update Status</h3>
      {#if status?.staged}
        <StatusBadge label="Candidate staged, ready to apply" tone="warning" />
      {:else if updateAvailable}
        <StatusBadge label={`Update available: ${channel?.latest_version}`} tone="warning" />
      {:else}
        <StatusBadge label="No candidate staged" tone="healthy" />
      {/if}
    </div>
  </section>

  <div class="grid-2col">
  <div class="card">
    <h3>Update Channel</h3>
    <p class="hint">
      Checks this real GitHub repository's own published Releases for the latest version. Optional
      token is only needed for a private repo or to avoid GitHub's anonymous rate limit.
    </p>
    {#if channelError}<p class="error" role="alert">{channelError}</p>{/if}
    <form onsubmit={saveChannel} class="channel-form">
      <input placeholder="Repo owner" bind:value={channelOwner} aria-label="Repo owner" />
      <input placeholder="Repo name" bind:value={channelRepo} aria-label="Repo name" />
      <input
        placeholder={channel?.has_token ? "Token set (leave blank to keep)" : "Token (optional)"}
        type="password"
        bind:value={channelToken}
        aria-label="Access token"
      />
      <button type="submit" disabled={channelBusy || !channelOwner.trim() || !channelRepo.trim()}>{channelBusy ? "Saving…" : "Save Channel"}</button>
      {#if channelSaveResult}<span class="success" role="status">{channelSaveResult}</span>{/if}
    </form>
    <div class="row">
      <button onclick={checkNow} disabled={checkBusy || !!loadError}>{checkBusy ? "Checking…" : "Check for Updates"}</button>
      {#if channel?.last_checked_at}
        <span class="hint">
          Last checked {new Date(channel.last_checked_at).toLocaleString()} --
          {#if channel.last_check_status === "ok"}
            latest published version: <strong class="mono">{channel.latest_version || "unknown"}</strong>
          {:else}
            <span class="error">{channel.last_check_error}</span>
          {/if}
        </span>
      {/if}
    </div>
    {#if checkError}<p class="error" role="alert">{checkError}</p>{/if}
    {#if updateAvailable}
      <div class="row">
        <button onclick={downloadAndStage} disabled={downloadBusy || !!loadError}>{downloadBusy ? "Downloading…" : `Download & Stage v${channel?.latest_version}`}</button>
      </div>
      {#if downloadError}<p class="error" role="alert">{downloadError}</p>{/if}
      {#if downloadResult}<p class="success" role="status">{downloadResult}</p>{/if}
    {/if}
  </div>

  <form class="card" onsubmit={stage}>
    <h3>Manual Update</h3>
    <p class="hint">Upload a new Alderpoint DNS build directly -- fed into the same checksum/version-verification and mandatory-backup pipeline as any other update.</p>
    <input type="file" bind:files={file} aria-label="Candidate binary file" />
    <input placeholder="Claimed version (must match the binary's own report)" bind:value={claimedVersion} aria-label="Claimed version" />
    <button type="submit" disabled={stageBusy || !file?.[0] || !claimedVersion.trim() || !!loadError}>{stageBusy ? "Staging…" : "Validate & Stage"}</button>
    {#if stageError}<p class="error" role="alert">{stageError}</p>{/if}
    {#if stageResult}<p class="success" role="status">{stageResult}</p>{/if}
  </form>
  </div>

  {#if status?.staged}
    <div class="card pending">
      <h3>Staged candidate</h3>
      <p>Version <strong>{status.staged.version}</strong></p>
      <button onclick={apply} disabled={applyBusy}>{applyBusy ? "Applying…" : "Apply"}</button>
      {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
      {#if applyResult}<p class="success" role="status">{applyResult}</p>{/if}
    </div>
  {/if}

  <div class="card">
    <h3>Update Safety</h3>
    <p class="hint">
      A real backup is always taken immediately before Apply -- if that backup fails, the update
      is aborted and nothing changes. The new version must pass a health check after applying;
      a failed health check rolls back automatically. Expect a brief DNS-serving interruption
      during the restart, not an extended outage.
    </p>
  </div>

  <div class="card">
    <h3>Update History</h3>
    <p class="hint">
      Not persisted anywhere yet -- there is no owner-facing log of past update attempts (time,
      from/to version, result, backup used). Only the current version and the most recent staged
      candidate (above) are tracked. This is a disclosed gap, not a hidden feature.
    </p>
  </div>
</div>

<style>
  .updates { display: flex; flex-direction: column; gap: 1rem; }
  .status-grid { display: flex; flex-wrap: wrap; gap: 1rem; }
  .status-grid .card { flex: 1 1 14rem; }
  /* Two responsive columns on desktop/tablet, one on mobile -- Update
     Channel and Manual Update previously each had a fixed max-width and
     stacked full-width one above the other with no shared container. */
  .grid-2col { display: grid; grid-template-columns: repeat(auto-fit, minmax(20rem, 1fr)); gap: 1rem; align-items: start; }
  .hint { font-size: 0.85rem; opacity: 0.75; margin: 0; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); box-shadow: var(--shadow); display: flex; flex-direction: column; gap: 0.6rem; }
  .card h3 { margin: 0; }
  .pending { background: var(--attention-bg); }
  .success { color: var(--success); }
  .error { color: var(--badge-danger-fg); }
  .channel-form { display: flex; flex-wrap: wrap; gap: 0.5rem; align-items: center; }
  .channel-form input { flex: 1 1 10rem; }
  .row { display: flex; flex-wrap: wrap; gap: 0.6rem; align-items: center; }
  .mono { font-family: monospace; }
</style>
