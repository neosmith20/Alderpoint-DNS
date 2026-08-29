<script lang="ts">
  // Shared Alderpoint status/health badge -- ported from V1.1.1's
  // `.status-badge`/`.status-badge--*` classes and `ui.status_badge()`
  // macro (web/static/app.css + web/templates/components.html, read
  // directly): a colored dot + label, not a filled pill.
  let { label, tone = "neutral" }: { label: string; tone?: "healthy" | "warning" | "danger" | "accent" | "neutral" } = $props();
</script>

<span class="status-badge status-badge--{tone}">{label}</span>

<style>
  .status-badge {
    display: inline-flex; align-items: center; gap: 0.4rem; max-width: 100%;
    border: 1px solid var(--border-strong, var(--border)); border-radius: 999px; padding: 0.25rem 0.6rem;
    color: var(--fg); background: var(--panel-elevated, var(--card-bg)); font-size: 0.78rem; font-weight: 650; white-space: nowrap;
  }
  .status-badge::before { content: ""; width: 7px; height: 7px; border-radius: 999px; background: var(--faint, var(--muted)); flex: 0 0 auto; }
  .status-badge--healthy::before { background: var(--success, #36d399); }
  .status-badge--warning::before { background: var(--warning, #fbbf24); }
  .status-badge--danger::before { background: var(--danger, #f87171); }
  .status-badge--accent::before { background: var(--accent, #20d6b5); }
</style>
