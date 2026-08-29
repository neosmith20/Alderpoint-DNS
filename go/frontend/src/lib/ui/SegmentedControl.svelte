<script lang="ts" generics="T extends string">
  // Shared Alderpoint time-range/mode selector -- ported from V1.1.1's
  // `.segment-control` class + `aria-current` pattern
  // (web/templates/clients.html's range nav, read directly).
  let {
    options,
    value,
    onChange,
    label,
  }: { options: { key: T; label: string }[]; value: T; onChange: (v: T) => void; label: string } = $props();
</script>

<nav class="segment-control" aria-label={label}>
  {#each options as opt (opt.key)}
    <button
      type="button"
      aria-current={value === opt.key ? "true" : "false"}
      onclick={() => onChange(opt.key)}
    >
      {opt.label}
    </button>
  {/each}
</nav>

<style>
  .segment-control {
    display: inline-flex; flex-wrap: wrap; gap: 0.25rem; border: 1px solid var(--border);
    border-radius: 999px; padding: 0.25rem; background: var(--bg-soft, var(--card-bg));
  }
  .segment-control button {
    border-radius: 999px; color: var(--muted); padding: 0.4rem 0.7rem; white-space: nowrap;
    background: transparent; border: none; min-height: auto; font-weight: 600; font-size: 0.85rem;
  }
  .segment-control button[aria-current="true"] { background: #0e6f68; color: var(--fg); }
</style>
