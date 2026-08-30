<script lang="ts">
  // Shared destructive-action confirmation dialog -- the design-system
  // unification's own real replacement for this app's own native
  // window.confirm() call sites (delete a client, revoke/regenerate a
  // Strong ClientID identifier). A native confirm() blocks the whole
  // renderer's main thread and cannot be styled, and -- a real bug this
  // very inconsistency caused live in this session's own Chromium
  // suite work -- a test harness has to special-case it with its own
  // dialog handler rather than treating it like every other real
  // element on the page. This dialog is built on the same shared
  // Modal.svelte every other real dialog in this app already uses
  // (ClientsView's Add Client/Add Group), not a second, parallel
  // pattern.
  import Modal from "./Modal.svelte";

  let {
    title,
    message,
    confirmLabel = "Confirm",
    danger = true,
    onConfirm,
    onCancel,
  }: {
    title: string;
    message: string;
    confirmLabel?: string;
    danger?: boolean;
    onConfirm: () => void;
    onCancel: () => void;
  } = $props();
</script>

<Modal {title} onClose={onCancel}>
  <p class="confirm-message">{message}</p>
  <div class="confirm-actions">
    <button type="button" onclick={onCancel}>Cancel</button>
    <button type="button" class={danger ? "danger" : ""} onclick={onConfirm}>{confirmLabel}</button>
  </div>
</Modal>

<style>
  .confirm-message { margin: 0 0 1rem; }
  .confirm-actions { display: flex; justify-content: flex-end; gap: 0.6rem; }
</style>
