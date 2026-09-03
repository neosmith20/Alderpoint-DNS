<script lang="ts">
  // Shared restrained overflow menu for page headers -- secondary actions
  // that don't belong crowding the primary action row (spec: "Secondary
  // actions in a restrained overflow menu... Do not place six unrelated
  // buttons across the header"). Closes on outside click, Escape, or
  // after any menu item is activated.
  import type { Snippet } from "svelte";

  let { label = "More actions", children }: { label?: string; children: Snippet<[() => void]> } = $props();
  let open = $state(false);
  let el: HTMLElement | undefined;

  function close() {
    open = false;
  }
  function onWindowClick(e: MouseEvent) {
    if (open && el && !el.contains(e.target as Node)) close();
  }
  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") close();
  }
</script>

<svelte:window onclick={onWindowClick} onkeydown={onKeydown} />

<div class="overflow-menu" bind:this={el}>
  <button type="button" class="secondary trigger" onclick={() => (open = !open)} aria-haspopup="menu" aria-expanded={open} aria-label={label} title={label}>
    <svg viewBox="0 0 24 24" width="18" height="18" fill="currentColor"><circle cx="5" cy="12" r="1.8" /><circle cx="12" cy="12" r="1.8" /><circle cx="19" cy="12" r="1.8" /></svg>
  </button>
  {#if open}
    <div class="menu" role="menu">
      {@render children(close)}
    </div>
  {/if}
</div>

<style>
  .overflow-menu { position: relative; display: inline-flex; }
  .trigger { padding: 0.5rem 0.65rem; }
  .menu {
    position: absolute; right: 0; top: calc(100% + 0.3rem); z-index: 50;
    min-width: 12rem; background: var(--card-bg); border: 1px solid var(--border);
    border-radius: 8px; box-shadow: var(--shadow); padding: 0.3rem; display: flex; flex-direction: column; gap: 0.1rem;
  }
  .menu :global(button) {
    width: 100%; text-align: left; background: transparent; color: var(--fg); border: none;
    padding: 0.5rem 0.6rem; min-height: auto; border-radius: 6px; font-size: 0.85rem; font-weight: 500;
  }
  .menu :global(button:hover:not(:disabled)) { background: var(--nav-hover-bg); }
  .menu :global(button:disabled) { opacity: 0.5; cursor: default; }
  .menu :global(button.danger) { background: transparent; color: var(--danger); border: none; }
  .menu :global(button.danger:hover) { background: var(--badge-danger-bg); }
</style>
