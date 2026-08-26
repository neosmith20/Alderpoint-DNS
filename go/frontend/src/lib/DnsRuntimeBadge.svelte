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
{/if}

<style>
  .dns-runtime-badge { font-size: 0.8rem; margin: 0.3rem 0 0; }
  .dns-runtime-badge.ok { color: #16a34a; }
  .dns-runtime-badge.warn { color: var(--badge-danger-fg); }
</style>
