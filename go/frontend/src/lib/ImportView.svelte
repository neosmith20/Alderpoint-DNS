<script lang="ts">
  import { api, ApiError, type ImportHostsResult } from "../api";

  // Import. One real, native source type: a hosts file, parsed and
  // written directly into internal/localdns (see internal/importer's
  // doc comment). The other five source types the Import page lists
  // (AdGuard YAML/live API, Pi-hole paste, BIND zone, Alderpoint
  // CSV/XLSX/JSON) are real, substantial format-specific parsers
  // (app/importer.py is ~1,200 lines covering all of them plus a
  // migration-plan/preview system with per-item selection) -- not
  // built here, disclosed rather than silently assumed equivalent.

  let hostsText = $state("");
  let result = $state<ImportHostsResult | null>(null);
  let error = $state("");
  let busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    error = "";
    result = null;
    busy = true;
    try {
      result = await api.importHosts(hostsText);
      if (result.imported > 0) hostsText = "";
    } catch (err) {
      error = err instanceof ApiError ? err.message : String(err);
    } finally {
      busy = false;
    }
  }
</script>

<section aria-labelledby="importexport-heading" class="import-view">
  <h2 id="importexport-heading">Import</h2>
  <p class="scope-note">
    Only the hosts-file source type is built (writes real records into Local DNS). AdGuard YAML/live
    API, Pi-hole paste, BIND zone, and Alderpoint CSV/XLSX/JSON are not built yet -- see the parity
    matrix.
  </p>

  <form class="card" onsubmit={submit}>
    <h3>Import a hosts file</h3>
    <textarea
      bind:value={hostsText}
      placeholder={"127.0.0.1 localhost\n10.0.0.5 nas nas.lan"}
      aria-label="Hosts file contents"
      rows="8"
    ></textarea>
    <div class="actions">
      <button type="submit" disabled={busy || !hostsText.trim()}>{busy ? "Importing…" : "Import"}</button>
    </div>
  </form>

  {#if error}<p class="error" role="alert">{error}</p>{/if}
  {#if result}
    <div class="card result">
      <p><strong>{result.imported}</strong> record{result.imported === 1 ? "" : "s"} imported, <strong>{result.skipped}</strong> skipped.</p>
      {#if result.errors.length > 0}
        <ul class="errors">
          {#each result.errors as e (e)}
            <li>{e}</li>
          {/each}
        </ul>
      {/if}
    </div>
  {/if}
</section>

<style>
  .import-view { display: flex; flex-direction: column; gap: 1rem; }
  .scope-note { font-size: 0.85rem; opacity: 0.75; max-width: 50rem; }
  .card { border: 1px solid var(--border); border-radius: 8px; padding: 1rem 1.25rem; background: var(--card-bg); display: flex; flex-direction: column; gap: 0.6rem; max-width: 40rem; }
  .card h3 { margin: 0; }
  textarea { font-family: monospace; font-size: 0.85rem; resize: vertical; }
  .actions { display: flex; gap: 0.6rem; }
  .error { color: var(--badge-danger-fg); }
  .result .errors { font-size: 0.8rem; opacity: 0.85; max-height: 12rem; overflow-y: auto; margin: 0; padding-left: 1.2rem; }
</style>
