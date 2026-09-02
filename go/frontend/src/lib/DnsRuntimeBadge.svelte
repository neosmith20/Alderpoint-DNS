<script lang="ts">
  import type { DNSRuntimeApplyResult } from "../api";

  // Shared, consistent feedback for every resolver-affecting mutation:
  // Local DNS/Custom Rules/Blocklists/DNS Settings/DNS Transports all
  // auto-apply their change through the same real DNS runtime compiler
  // (see internal/dnsruntime), and this is the one place that result is
  // ever rendered, so the UX is identical everywhere it appears rather
  // than each page inventing its own wording. `result` is undefined
  // before any mutation has happened yet (renders nothing) or when this
  // deployment has no DNS runtime configured at all (result.attempted
  // === false, also renders nothing -- silently requiring a runtime
  // that may not exist in this deployment would be noise, not signal).
  let { result }: { result?: DNSRuntimeApplyResult | null } = $props();
</script>

{#if result?.attempted}
  {#if result.promoted}
    <p class="dns-runtime-badge ok" role="status">DNS runtime updated.</p>
  {:else if result.rolled_back}
    <p class="dns-runtime-badge warn" role="alert">
      DNS runtime change rejected at stage "{result.stage}" -- previous runtime kept. {result.detail}
    </p>
  {:else}
    <p class="dns-runtime-badge warn" role="alert">DNS runtime update failed: {result.error}</p>
  {/if}
  {#if result.timings}
    {@const t = result.timings}
    <!-- Real, measured timing breakdown for this apply -- see the
         owner-reported "20-30 second apply, no visibility into where"
         defect this answers. reload_ms/health_check_ms are usually the
         dominant cost: dnsdist cannot hot-reload its config, so a full
         stop/start cycle plus real dig-query health verification is
         genuinely unavoidable, not a bug -- this is what shows that
         honestly instead of leaving the wait unexplained. -->
    <details class="dns-runtime-timings">
      <summary>Applied in {(t.total_ms / 1000).toFixed(1)}s -- where did the time go?</summary>
      <ul>
        <li>Gathering settings: {t.build_ms} ms</li>
        <li>Compiling config: {t.web_compile_ms + t.compile_ms} ms</li>
        {#if t.validate_ms}<li>Validating config: {t.validate_ms} ms</li>{/if}
        {#if t.promote_ms}<li>Writing live config: {t.promote_ms} ms</li>{/if}
        {#if t.reload_ms}<li>Restarting the resolver (BIND + dnsdist): {t.reload_ms} ms</li>{/if}
        {#if t.health_check_ms}<li>Verifying DNS is answering: {t.health_check_ms} ms</li>{/if}
      </ul>
    </details>
  {/if}
{/if}

<style>
  .dns-runtime-badge { font-size: 0.8rem; margin: 0.3rem 0 0; }
  .dns-runtime-badge.ok { color: var(--success, #16a34a); }
  .dns-runtime-badge.warn { color: var(--badge-danger-fg); }
  .dns-runtime-timings { font-size: 0.78rem; opacity: 0.8; margin-top: 0.2rem; }
  .dns-runtime-timings summary { cursor: pointer; }
  .dns-runtime-timings ul { margin: 0.3rem 0 0; padding-left: 1.2rem; }
</style>
