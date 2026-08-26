<script lang="ts" generics="T">
  // Shared sortable/resizable data grid -- the Go/Svelte equivalent of
  // app/v2/ui/data-grid.js, used by every page's tables (see
  // PARITY_MATRIX.md's "Shared data grid" cross-cutting row). Behavior
  // matched deliberately: click header sorts ascending, click again
  // descending, sort state has a visual indicator; columns are
  // drag-resizable with a persisted width (per gridId, like the Python
  // version's localStorage-per-grid-id scheme); a capped row count shows
  // an overflow notice instead of silently truncating; the whole table
  // sits in its own horizontal-scroll container so overflow never breaks
  // the page layout; sorting is keyboard-accessible because headers are
  // real <button> elements.
  import { onMount, type Snippet } from "svelte";
  import Icon from "./Icon.svelte";
  import type { Column } from "./datagrid";

  let {
    gridId,
    columns,
    rows,
    rowKey,
    maxRows,
    cell,
    emptyMessage = "No data.",
    rowClass,
  }: {
    gridId: string;
    columns: Column<T>[];
    rows: T[];
    rowKey: (row: T) => string | number;
    maxRows?: number;
    cell: Snippet<[T, string]>;
    emptyMessage?: string;
    rowClass?: (row: T) => string;
  } = $props();

  function widthKey(id: string): string {
    return `apdns-go-grid-widths:${id}`;
  }

  function loadWidths(id: string): Record<string, number> {
    try {
      const raw = localStorage.getItem(widthKey(id));
      if (raw) return JSON.parse(raw);
    } catch {
      /* fall through to defaults */
    }
    return {};
  }

  let widths = $state<Record<string, number>>({});
  let sortKey = $state<string | null>(null);
  let sortDir = $state<"asc" | "desc">("asc");

  onMount(() => {
    widths = loadWidths(gridId);
  });

  function persistWidths() {
    try {
      localStorage.setItem(widthKey(gridId), JSON.stringify(widths));
    } catch {
      /* best-effort persistence only */
    }
  }

  function toggleSort(col: Column<T>) {
    if (!col.sortValue) return;
    if (sortKey === col.key) {
      sortDir = sortDir === "asc" ? "desc" : "asc";
    } else {
      sortKey = col.key;
      sortDir = "asc";
    }
  }

  function compareValues(a: string | number, b: string | number): number {
    if (typeof a === "number" && typeof b === "number") return a - b;
    return String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: "base" });
  }

  // Defense-in-depth: a backend bug (a nil Go slice marshals to JSON
  // `null`, not `[]`) has actually shipped `rows` as null before -- see
  // internal/clients's regression test for the real story. That's fixed
  // at the source now, but this component degrades to "no rows" instead
  // of crashing if it ever happens again, here or in a future page.
  const safeRows = $derived(rows ?? []);

  const sortedRows = $derived.by(() => {
    if (!sortKey) return safeRows;
    const col = columns.find((c) => c.key === sortKey);
    if (!col?.sortValue) return safeRows;
    const withKeys = safeRows.map((r) => ({ r, v: col.sortValue!(r) }));
    withKeys.sort((a, b) => compareValues(a.v, b.v) * (sortDir === "asc" ? 1 : -1));
    return withKeys.map((x) => x.r);
  });

  const visibleRows = $derived(maxRows ? sortedRows.slice(0, maxRows) : sortedRows);
  const hiddenCount = $derived(maxRows && sortedRows.length > maxRows ? sortedRows.length - maxRows : 0);

  // Drag-resize: pointer-based, one active resize at a time.
  let resizing: { key: string; startX: number; startWidth: number } | null = null;

  function startResize(e: PointerEvent, col: Column<T>) {
    const th = (e.currentTarget as HTMLElement).closest("th");
    const currentWidth = widths[col.key] ?? th?.getBoundingClientRect().width ?? col.minWidth ?? 8 * 10;
    resizing = { key: col.key, startX: e.clientX, startWidth: currentWidth };
    (e.target as HTMLElement).setPointerCapture(e.pointerId);
    e.preventDefault();
  }

  function onResizeMove(e: PointerEvent) {
    if (!resizing) return;
    const col = columns.find((c) => c.key === resizing!.key);
    const min = (col?.minWidth ?? 6) * 9; // rough ch->px
    const next = Math.max(min, resizing.startWidth + (e.clientX - resizing.startX));
    widths = { ...widths, [resizing.key]: next };
  }

  function endResize() {
    if (resizing) persistWidths();
    resizing = null;
  }
</script>

<svelte:window onpointermove={onResizeMove} onpointerup={endResize} />

<div class="grid-scroll">
  <table class="data-grid">
    <thead>
      <tr>
        {#each columns as col (col.key)}
          <th style={widths[col.key] ? `width:${widths[col.key]}px` : col.minWidth ? `min-width:${col.minWidth}ch` : undefined}>
            <div class="th-inner">
              {#if col.sortValue}
                <button class="sort-btn" onclick={() => toggleSort(col)} aria-label={`Sort by ${col.label}`}>
                  <span>{col.label}</span>
                  <span class="sort-indicator" class:active={sortKey === col.key}>
                    {#if sortKey === col.key}
                      <Icon name="chevron" size={12} spin={false} />
                    {/if}
                  </span>
                </button>
              {:else}
                <span class="th-label">{col.label}</span>
              {/if}
            </div>
            <span
              class="resize-handle"
              role="separator"
              aria-orientation="vertical"
              onpointerdown={(e) => startResize(e, col)}
            ></span>
          </th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#if visibleRows.length === 0}
        <tr class="empty-row"><td colspan={columns.length}>{emptyMessage}</td></tr>
      {:else}
        {#each visibleRows as row (rowKey(row))}
          <tr class={rowClass?.(row)}>
            {#each columns as col (col.key)}
              <td>{@render cell(row, col.key)}</td>
            {/each}
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
  {#if hiddenCount > 0}
    <p class="overflow-note">{hiddenCount} additional row{hiddenCount === 1 ? "" : "s"} not shown.</p>
  {/if}
</div>

<style>
  .grid-scroll {
    overflow-x: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  .data-grid {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.85rem;
  }
  .data-grid th,
  .data-grid td {
    padding: 0.5rem 0.65rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
    white-space: nowrap;
  }
  .data-grid thead th {
    position: relative;
    background: var(--nav-hover-bg);
    font-weight: 600;
    user-select: none;
  }
  .th-inner {
    display: flex;
    align-items: center;
  }
  .th-label {
    padding: 0.15rem 0;
  }
  .sort-btn {
    display: flex;
    align-items: center;
    gap: 0.3rem;
    background: transparent;
    color: inherit;
    border: none;
    padding: 0.15rem 0;
    font: inherit;
    font-weight: 600;
    cursor: pointer;
  }
  .sort-indicator {
    display: inline-flex;
    width: 12px;
    opacity: 0;
  }
  .sort-indicator.active {
    opacity: 1;
  }
  tr:has(td):hover {
    background: var(--nav-hover-bg);
  }
  /* Generic per-row state modifiers -- reusable across every page's grid,
     not redefined per page. */
  tr.row-pending {
    opacity: 0.5;
  }
  tr.row-attention {
    background: var(--attention-bg);
  }
  .empty-row td {
    opacity: 0.65;
    text-align: center;
    padding: 1.25rem;
  }
  .resize-handle {
    position: absolute;
    top: 0;
    right: 0;
    width: 6px;
    height: 100%;
    cursor: col-resize;
    touch-action: none;
  }
  .resize-handle:hover {
    background: var(--accent);
    opacity: 0.4;
  }
  .overflow-note {
    margin: 0;
    padding: 0.5rem 0.65rem;
    font-size: 0.78rem;
    opacity: 0.7;
    border-top: 1px solid var(--border);
  }
</style>
