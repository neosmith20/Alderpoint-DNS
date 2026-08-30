<script lang="ts">
  import { onMount } from "svelte";
  import { api, ApiError, type UpdateCheckResponse } from "../api";
  import { router } from "../router.svelte";

  // Software Updates. Real, for this control plane's own Go binary --
  // deliberately not Python's apt/dpkg package (see the parity matrix:
  // installing an arbitrary uploaded .deb is real root package
  // management and stays out of scope). Real checksum + self-reported-
  // version verification before a candidate is ever trusted, and a real
  // health-check-gated rollback if a newly applied version doesn't come
  // back up healthy -- see internal/hostagentd/ops_update.go, proven
  // end-to-end against real compiled binaries in its own test suite.

  let status = $state<UpdateCheckResponse | null>(null);
  let loadError = $state("");

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

  onMount(() => {
    refresh();
  });

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

<section aria-labelledby="updates-heading" class="updates">
  <h2 id="updates-heading">Software Updates</h2>
  <p class="scope-note">
    Check for, stage, and apply updates to this appliance. A staged candidate's checksum and
    version are verified before it's trusted; applying is gated on a health check, with automatic
    rollback if the new version doesn't come up healthy.
  </p>

  {#if loadError}<p class="error" role="alert">{loadError}</p>{/if}

  <div class="card">
    <h3>Current version</h3>
    <p>{status?.current_version ?? "…"}</p>
  </div>

  <form class="card" onsubmit={stage}>
    <h3>Stage a candidate</h3>
    <input type="file" bind:files={file} aria-label="Candidate binary file" />
    <input placeholder="Claimed version (must match the binary's own report)" bind:value={claimedVersion} aria-label="Claimed version" />
    <button type="submit" disabled={stageBusy || !file?.[0] || !claimedVersion.trim()}>{stageBusy ? "Staging…" : "Stage"}</button>
    {#if stageError}<p class="error" role="alert">{stageError}</p>{/if}
    {#if stageResult}<p class="success" role="status">{stageResult}</p>{/if}
  </form>

  {#if status?.staged}
    <div class="card pending">
      <h3>Staged candidate</h3>
      <p>Version <strong>{status.staged.version}</strong></p>
      <button onclick={apply} disabled={applyBusy}>{applyBusy ? "Applying…" : "Apply"}</button>
      {#if applyError}<p class="error" role="alert">{applyError}</p>{/if}
      {#if applyResult}<p class="success" role="status">{applyResult}</p>{/if}
    </div>
  {/if}
</section>

<style>
  .updates { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 32rem; }
  .card h3 { margin: 0; }
  .pending { background: var(--attention-bg); }
  .success { color: #16a34a; }
  .error { color: var(--badge-danger-fg); }
</style>
