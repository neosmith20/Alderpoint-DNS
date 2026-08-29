<script lang="ts">
  // Route-level code splitting + honest incomplete-route state: dynamically
  // imports the page component for the current route id. A short delay
  // before showing a skeleton avoids a loading flash on fast (already
  // cached) navigations -- "immediate navigation feedback without blanking
  // the page" without lying about instant data. Routes with no `load`
  // (see nav.ts) show a plain "not yet available" panel: an honest,
  // non-interactive state, not a fake working page.
  import { findItem } from "../nav";
  import { router } from "../router.svelte";
  import { perfLog } from "../perfLog.svelte";
  import Icon from "./Icon.svelte";
  import type { Component } from "svelte";

  let { routeId }: { routeId: string } = $props();

  let comp = $state<Component | null>(null);
  let showSkeleton = $state(false);
  let loadError = $state("");

  $effect(() => {
    const id = routeId;
    const item = findItem(id);
    comp = null;
    loadError = "";
    showSkeleton = false;

    if (!item?.load) {
      // Still a real, final render state (the "not yet available" panel)
      // worth timing -- it's what the operator actually sees land.
      perfLog.record(id, performance.now() - router.navStartedAt);
      return;
    }

    let cancelled = false;
    const skeletonTimer = setTimeout(() => {
      if (!cancelled) showSkeleton = true;
    }, 150);

    item
      .load()
      .then((mod) => {
        if (cancelled) return;
        comp = mod.default;
        perfLog.record(id, performance.now() - router.navStartedAt);
      })
      .catch((err) => {
        if (cancelled) return;
        loadError = err instanceof Error ? err.message : String(err);
      })
      .finally(() => {
        clearTimeout(skeletonTimer);
        if (!cancelled) showSkeleton = false;
      });

    return () => {
      cancelled = true;
      clearTimeout(skeletonTimer);
    };
  });

  const item = $derived(findItem(routeId));
</script>

{#if !item}
  <div class="panel unavailable">
    <p>Unknown route.</p>
  </div>
{:else if !item.load}
  <div class="panel unavailable">
    <h2>{item.label}</h2>
    <p>This page is not built yet. See <code>go/PARITY_MATRIX.md</code> for status.</p>
  </div>
{:else if loadError}
  <div class="panel error">
    <p role="alert">Failed to load this page: {loadError}</p>
  </div>
{:else if showSkeleton && !comp}
  <div class="skeleton" aria-busy="true" aria-label="Loading">
    <Icon name="spinner" size={22} spin />
  </div>
{:else if comp}
  {@const Comp = comp}
  <Comp />
{/if}

<style>
  .panel {
    padding: 2rem 1rem;
    max-width: 32rem;
  }
  .panel.unavailable {
    opacity: 0.75;
  }
  .panel.error p {
    color: #dc2626;
  }
  .skeleton {
    display: flex;
    justify-content: center;
    padding: 3rem 0;
    opacity: 0.6;
  }
</style>
