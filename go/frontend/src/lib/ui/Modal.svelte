<script lang="ts">
  // Shared Alderpoint modal -- replaces a permanent on-page "Add X" form
  // with a real dialog, opened from a toolbar action. Closes on
  // backdrop click, the X button, or Escape.
  import type { Snippet } from "svelte";

  let { title, onClose, children }: { title: string; onClose: () => void; children: Snippet } = $props();

  function onKeydown(e: KeyboardEvent) {
    if (e.key === "Escape") onClose();
  }
</script>

<svelte:window onkeydown={onKeydown} />

<div class="modal-backdrop" role="presentation" onclick={onClose} onkeydown={onKeydown}>
  <div class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title" tabindex="-1" onclick={(e) => e.stopPropagation()} onkeydown={(e) => e.stopPropagation()}>
    <div class="modal__head">
      <h2 id="modal-title">{title}</h2>
      <button type="button" class="secondary modal__close" onclick={onClose} aria-label="Close">×</button>
    </div>
    <div class="modal__body">{@render children()}</div>
  </div>
</div>

<style>
  .modal-backdrop {
    position: fixed; inset: 0; background: rgba(0, 0, 0, 0.55); display: flex;
    align-items: center; justify-content: center; padding: 1rem; z-index: 100;
  }
  .modal {
    width: 100%; max-width: 32rem; max-height: 90vh; overflow-y: auto; border: 1px solid var(--border);
    border-radius: var(--radius, 12px); background: var(--card-bg); box-shadow: var(--shadow, 0 18px 44px rgba(0, 0, 0, 0.4));
    padding: 1.25rem;
  }
  .modal__head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1rem; }
  .modal__head h2 { margin: 0; font-size: 1.05rem; }
  .modal__close { min-height: auto; padding: 0.25rem 0.6rem; font-size: 1.1rem; line-height: 1; }
</style>
