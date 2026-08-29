<script lang="ts">
  // Shared Alderpoint page header -- title + one-line description +
  // optional right-aligned actions -- ported from V1.1.1's
  // `ui.page_header()` macro (web/templates/components.html) so every
  // rebuilt page shares one real heading treatment instead of each view
  // rolling its own bare <h2>. First consumer: ClientsView.svelte.
  import type { Snippet } from "svelte";

  let { title, description, headingId, actions }: { title: string; description?: string; headingId?: string; actions?: Snippet } = $props();
</script>

<div class="page-header">
  <div>
    <h1 id={headingId}>{title}</h1>
    {#if description}<p>{description}</p>{/if}
  </div>
  {#if actions}
    <div class="page-header__actions">{@render actions()}</div>
  {/if}
</div>

<style>
  .page-header { display: flex; justify-content: space-between; gap: 1rem; align-items: flex-end; margin: 0.25rem 0 1.25rem; flex-wrap: wrap; }
  .page-header h1 { margin: 0; font-size: clamp(1.5rem, 2.4vw, 2rem); line-height: 1.1; }
  .page-header p { margin: 0.5rem 0 0; color: var(--muted); max-width: 72ch; }
  .page-header__actions { display: flex; flex-wrap: wrap; align-items: center; gap: 0.6rem; }
</style>
