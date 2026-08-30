<script lang="ts">
  // Renders the shared toast queue (../../toast.svelte.ts) -- mounted
  // exactly once, in App.svelte, so any page can call toast.success()/
  // .error()/.info() without owning its own overlay markup.
  import { toast } from "../../toast.svelte";
</script>

<div class="toast-host" role="status" aria-live="polite">
  {#each toast.entries as entry (entry.id)}
    <div class="toast toast--{entry.kind}">
      <span class="toast__message">{entry.message}</span>
      <button type="button" class="toast__close" onclick={() => toast.dismiss(entry.id)} aria-label="Dismiss">×</button>
    </div>
  {/each}
</div>

<style>
  .toast-host {
    position: fixed;
    bottom: 1.25rem;
    right: 1.25rem;
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
    z-index: 200;
    max-width: 24rem;
  }
  .toast {
    display: flex;
    align-items: flex-start;
    gap: 0.6rem;
    padding: 0.65rem 0.8rem;
    border-radius: 8px;
    border: 1px solid var(--border);
    background: var(--card-bg);
    box-shadow: var(--shadow, 0 8px 24px rgba(0, 0, 0, 0.25));
    font-size: 0.88rem;
    animation: toast-in 0.15s ease-out;
  }
  .toast--success { border-left: 4px solid var(--badge-ok-fg, #2e7d32); }
  .toast--error { border-left: 4px solid var(--badge-danger-fg, #c62828); }
  .toast--info { border-left: 4px solid var(--accent); }
  .toast__message { flex: 1; word-break: break-word; }
  .toast__close {
    background: transparent; border: none; color: inherit; cursor: pointer;
    font-size: 1rem; line-height: 1; padding: 0; min-height: auto; opacity: 0.6;
  }
  .toast__close:hover { opacity: 1; }
  @keyframes toast-in {
    from { opacity: 0; transform: translateY(6px); }
    to { opacity: 1; transform: translateY(0); }
  }
</style>
