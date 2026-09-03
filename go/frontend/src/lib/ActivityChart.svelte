<script lang="ts">
  // Responsive SVG line chart for DNS Activity (queries + blocked), no
  // charting library -- matches app.js's own approach (regenerate at the
  // exact container pixel width via ResizeObserver) so it resizes with
  // the sidebar collapse/expand and never overflows its card.
  import { timestampPref } from "../timestamp.svelte";

  export interface ChartPoint {
    x: number; // epoch seconds
    total: number;
    blocked: number;
  }

  let { points, height = 220 }: { points: ChartPoint[]; height?: number } = $props();

  let containerEl: HTMLDivElement | undefined = $state();
  let width = $state(600);

  $effect(() => {
    if (!containerEl) return;
    const ro = new ResizeObserver((entries) => {
      const w = entries[0]?.contentRect.width;
      if (w && w > 0) width = w;
    });
    ro.observe(containerEl);
    return () => ro.disconnect();
  });

  const PAD_LEFT = 42;
  const PAD_RIGHT = 12;
  const PAD_TOP = 12;
  const PAD_BOTTOM = 28;

  const maxTotal = $derived(Math.max(1, ...points.map((p) => p.total)));
  const plotW = $derived(Math.max(10, width - PAD_LEFT - PAD_RIGHT));
  const plotH = $derived(Math.max(10, height - PAD_TOP - PAD_BOTTOM));

  function xFor(i: number): number {
    if (points.length <= 1) return PAD_LEFT;
    return PAD_LEFT + (i / (points.length - 1)) * plotW;
  }
  function yFor(v: number): number {
    return PAD_TOP + plotH - (v / maxTotal) * plotH;
  }

  const totalPath = $derived(points.map((p, i) => `${i === 0 ? "M" : "L"}${xFor(i)},${yFor(p.total)}`).join(" "));
  const blockedPath = $derived(points.map((p, i) => `${i === 0 ? "M" : "L"}${xFor(i)},${yFor(p.blocked)}`).join(" "));

  const yTicks = $derived.by(() => {
    const steps = 4;
    return Array.from({ length: steps + 1 }, (_, i) => Math.round((maxTotal / steps) * i));
  });

  // X-axis labels: at most 6, evenly spaced across the actual points.
  const xLabelIdx = $derived.by(() => {
    if (points.length === 0) return [];
    const count = Math.min(6, points.length);
    if (count <= 1) return [0];
    return Array.from({ length: count }, (_, i) => Math.round((i / (count - 1)) * (points.length - 1)));
  });

  let hoverIdx = $state<number | null>(null);
  const hoverPoint = $derived(hoverIdx !== null ? points[hoverIdx] : null);

  function onMove(e: MouseEvent) {
    if (points.length === 0) return;
    const rect = (e.currentTarget as SVGElement).getBoundingClientRect();
    const relX = e.clientX - rect.left - PAD_LEFT;
    const frac = Math.max(0, Math.min(1, relX / plotW));
    hoverIdx = Math.round(frac * (points.length - 1));
  }
  function onLeave() {
    hoverIdx = null;
  }
</script>

<div class="chart-wrap" bind:this={containerEl}>
  {#if points.length === 0}
    <p class="empty">No activity data in this window.</p>
  {:else}
    <svg
      {width}
      {height}
      role="img"
      aria-label="DNS query activity over time: total queries and blocked queries"
      onmousemove={onMove}
      onmouseleave={onLeave}
      onfocus={() => {}}
    >
      {#each yTicks as tick}
        <line x1={PAD_LEFT} x2={width - PAD_RIGHT} y1={yFor(tick)} y2={yFor(tick)} class="gridline" />
        <text x={PAD_LEFT - 6} y={yFor(tick)} class="axis-label y">{tick}</text>
      {/each}
      {#each xLabelIdx as idx}
        <text x={xFor(idx)} y={height - 8} class="axis-label x">
          {timestampPref.format(points[idx].x * 1000).split(",")[0]}
        </text>
      {/each}
      <path d={totalPath} class="line line-total" fill="none" />
      <path d={blockedPath} class="line line-blocked" fill="none" />
      {#if hoverPoint}
        <line x1={xFor(hoverIdx!)} x2={xFor(hoverIdx!)} y1={PAD_TOP} y2={PAD_TOP + plotH} class="hover-line" />
        <circle cx={xFor(hoverIdx!)} cy={yFor(hoverPoint.total)} r="3.5" class="hover-dot total" />
        <circle cx={xFor(hoverIdx!)} cy={yFor(hoverPoint.blocked)} r="3.5" class="hover-dot blocked" />
      {/if}
    </svg>
    <div class="legend">
      <span class="legend-item"><span class="swatch total"></span>Queries</span>
      <span class="legend-item"><span class="swatch blocked"></span>Blocked</span>
      {#if hoverPoint}
        <span class="tooltip" role="status">
          {timestampPref.format(hoverPoint.x * 1000)} -- {hoverPoint.total} queries, {hoverPoint.blocked} blocked
        </span>
      {/if}
    </div>
  {/if}
</div>

<style>
  .chart-wrap {
    width: 100%;
  }
  svg {
    display: block;
    max-width: 100%;
  }
  .empty {
    padding: 2rem 0;
    text-align: center;
    opacity: 0.6;
    font-size: 0.85rem;
  }
  .gridline {
    stroke: var(--border);
    stroke-width: 1;
  }
  .axis-label {
    font-size: 9px;
    fill: var(--fg);
    opacity: 0.65;
  }
  .axis-label.y {
    text-anchor: end;
    dominant-baseline: middle;
  }
  .axis-label.x {
    text-anchor: middle;
  }
  .line {
    stroke-width: 2;
  }
  .line-total {
    stroke: var(--accent);
  }
  .line-blocked {
    stroke: var(--danger);
  }
  .hover-line {
    stroke: var(--border);
    stroke-dasharray: 3 3;
  }
  .hover-dot.total {
    fill: var(--accent);
  }
  .hover-dot.blocked {
    fill: var(--danger);
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 1rem;
    align-items: center;
    margin-top: 0.4rem;
    font-size: 0.78rem;
  }
  .legend-item {
    display: inline-flex;
    align-items: center;
    gap: 0.35rem;
  }
  .swatch {
    width: 0.7rem;
    height: 0.7rem;
    border-radius: 2px;
    display: inline-block;
  }
  .swatch.total {
    background: var(--accent);
  }
  .swatch.blocked {
    background: var(--danger);
  }
  .tooltip {
    opacity: 0.8;
  }
</style>
