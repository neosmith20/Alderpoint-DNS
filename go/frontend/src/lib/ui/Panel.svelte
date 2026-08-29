<script lang="ts">
  // Shared Alderpoint panel/card -- ported from V1.1.1's `.panel`/
  // `.panel__head` classes (web/static/app.css, read directly). Every
  // page section (a table, a form, a summary block) sits inside one of
  // these instead of bare, unstyled markup.
  import type { Snippet } from "svelte";

  let { heading, actions, children }: { heading?: string; actions?: Snippet; children: Snippet } = $props();
</script>

<section class="panel">
  {#if heading || actions}
    <div class="panel__head">
      {#if heading}<h2>{heading}</h2>{/if}
      {#if actions}<div class="panel__actions">{@render actions()}</div>{/if}
    </div>
  {/if}
  {@render children()}
</section>

<style>
  .panel {
    min-width: 0; overflow: hidden; border: 1px solid var(--border); border-radius: var(--radius, 12px);
    background: linear-gradient(180deg, rgba(255, 255, 255, 0.025), transparent), var(--card-bg);
    box-shadow: var(--shadow, 0 18px 44px rgba(0, 0, 0, 0.22)); padding: 1rem;
  }
  .panel__head { display: flex; align-items: center; justify-content: space-between; gap: 0.75rem; margin-bottom: 0.9rem; flex-wrap: wrap; row-gap: 0.4rem; }
  .panel__head h2 { margin: 0; font-size: 1rem; }
  .panel__actions { display: flex; flex-wrap: wrap; gap: 0.5rem; }
</style>
