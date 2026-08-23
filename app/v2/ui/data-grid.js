(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.AlderpointDataGrid = factory();
  }
}(typeof self !== "undefined" ? self : this, function () {
  "use strict";

  // Pure helpers (no DOM) so they're unit-testable from plain Node -- see
  // tests/js/test_data_grid_compare.mjs. Shared by every major table
  // (Blocklists, Clients, Upstreams, Local DNS, Filters, Notifications,
  // Query Log, ...) instead of each page hand-rolling its own sort/resize.

  function parseCellValue(text) {
    const raw = (text == null ? "" : String(text)).trim();
    if (raw === "") return { kind: "empty", value: "" };
    const numeric = raw.replace(/,/g, "").replace(/%$/, "");
    if (numeric !== "" && /^-?[\d.]+$/.test(numeric) && !Number.isNaN(Number(numeric))) {
      return { kind: "number", value: Number(numeric) };
    }
    return { kind: "string", value: raw.toLowerCase() };
  }

  function compareParsed(a, b) {
    if (a.kind === "empty" && b.kind === "empty") return 0;
    if (a.kind === "empty") return 1;
    if (b.kind === "empty") return -1;
    if (a.kind === "number" && b.kind === "number") return a.value - b.value;
    const sa = a.kind === "number" ? String(a.value) : a.value;
    const sb = b.kind === "number" ? String(b.value) : b.value;
    if (sa < sb) return -1;
    if (sa > sb) return 1;
    return 0;
  }

  function compareCells(textA, textB) {
    return compareParsed(parseCellValue(textA), parseCellValue(textB));
  }

  const hasDom = typeof document !== "undefined";
  if (!hasDom) {
    return { parseCellValue: parseCellValue, compareCells: compareCells };
  }

  // --- DOM wiring. Every table this app renders is produced fresh as an
  // HTML string and dropped in via `target.innerHTML = ...` from many
  // call sites (loadPage, and several sub-panel refreshers -- see
  // app.js). Rather than re-wire listeners at each of those call sites,
  // this module attaches ONE set of delegated listeners to `document`
  // (matching app.js's own `wire()` pattern for clicks) plus a
  // MutationObserver that notices new `table[data-grid]` nodes wherever
  // they appear and applies persisted sort/width state to them. No
  // per-render integration code is required elsewhere.

  const MIN_COLUMN_WIDTH = 64;
  const SORT_KEY_PREFIX = "alderpointdnsGridSort:";
  const WIDTH_KEY_PREFIX = "alderpointdnsGridWidths:";
  const gridState = new WeakMap();

  function readStorage(key) {
    try { return window.localStorage.getItem(key); } catch (e) { return null; }
  }
  function writeStorage(key, value) {
    try { window.localStorage.setItem(key, value); } catch (e) {}
  }

  function isSortableHeader(th) {
    return th && th.tagName === "TH" && !("noSort" in th.dataset) && th.closest("table[data-grid]") && th.closest("thead");
  }

  function headerIndex(th) {
    return Array.from(th.parentNode.children).indexOf(th);
  }

  function applySortIndicators(table, columnIndex, direction) {
    Array.from(table.querySelectorAll(":scope > thead > tr > th")).forEach((th, index) => {
      if (index === columnIndex) th.setAttribute("aria-sort", direction === "asc" ? "ascending" : "descending");
      else th.removeAttribute("aria-sort");
      th.classList.toggle("is-sorted", index === columnIndex);
      th.classList.toggle("is-sorted-desc", index === columnIndex && direction === "desc");
    });
  }

  function sortRows(table, columnIndex, direction) {
    const tbody = table.tBodies[0];
    if (!tbody) return;
    const rows = Array.from(tbody.rows);
    const factor = direction === "desc" ? -1 : 1;
    rows.sort((rowA, rowB) => {
      const cellA = rowA.children[columnIndex];
      const cellB = rowB.children[columnIndex];
      return compareCells(cellA ? cellA.textContent : "", cellB ? cellB.textContent : "") * factor;
    });
    rows.forEach((row) => tbody.appendChild(row));
  }

  function applySort(table, columnIndex, direction, persist) {
    gridState.set(table, { sortColumn: columnIndex, sortDirection: direction });
    applySortIndicators(table, columnIndex, direction);
    sortRows(table, columnIndex, direction);
    if (persist && table.dataset.gridId) {
      writeStorage(SORT_KEY_PREFIX + table.dataset.gridId, columnIndex + ":" + direction);
    }
  }

  function toggleSort(th) {
    const table = th.closest("table[data-grid]");
    if (!table) return;
    const columnIndex = headerIndex(th);
    const current = gridState.get(table) || {};
    const nextDirection = current.sortColumn === columnIndex && current.sortDirection === "asc" ? "desc" : "asc";
    applySort(table, columnIndex, nextDirection, true);
  }

  function restoreWidths(table) {
    if (!table.dataset.gridId || "noResize" in table.dataset) return;
    const stored = readStorage(WIDTH_KEY_PREFIX + table.dataset.gridId);
    if (!stored) return;
    let widths;
    try { widths = JSON.parse(stored); } catch (e) { return; }
    Array.from(table.querySelectorAll(":scope > thead > tr > th")).forEach((th, index) => {
      if (widths[index]) th.style.width = widths[index];
    });
  }

  function persistWidths(table) {
    if (!table.dataset.gridId) return;
    const widths = Array.from(table.querySelectorAll(":scope > thead > tr > th")).map((th) => th.style.width || "");
    writeStorage(WIDTH_KEY_PREFIX + table.dataset.gridId, JSON.stringify(widths));
  }

  function restoreSort(table) {
    if (!table.dataset.gridId) return;
    const stored = readStorage(SORT_KEY_PREFIX + table.dataset.gridId);
    if (!stored) return;
    const parts = stored.split(":");
    const columnIndex = Number(parts[0]);
    const direction = parts[1];
    const headers = Array.from(table.querySelectorAll(":scope > thead > tr > th"));
    if (Number.isNaN(columnIndex) || !headers[columnIndex]) return;
    if ("noSort" in headers[columnIndex].dataset) return;
    if (direction !== "asc" && direction !== "desc") return;
    applySort(table, columnIndex, direction, false);
  }

  function ensureScrollWrapper(table) {
    const parent = table.parentElement;
    if (parent && (parent.classList.contains("table-wrap") || parent.classList.contains("data-grid-scroll"))) {
      parent.classList.add("data-grid-scroll");
      return;
    }
    const wrap = document.createElement("div");
    wrap.className = "table-wrap data-grid-scroll";
    table.parentNode.insertBefore(wrap, table);
    wrap.appendChild(table);
  }

  function ensureGridId(table, seq) {
    if (!table.dataset.gridId) {
      table.dataset.gridId = "auto" + (location.hash || location.pathname).replace(/\W+/g, "-") + "-" + seq;
    }
  }

  let autoSeq = 0;
  function initTable(table) {
    ensureGridId(table, autoSeq++);
    ensureScrollWrapper(table);
    Array.from(table.querySelectorAll(":scope > thead > tr > th")).forEach((th) => {
      if ("noSort" in th.dataset) return;
      th.tabIndex = 0;
      th.classList.add("is-sortable");
    });
    if (!("noResize" in table.dataset)) {
      Array.from(table.querySelectorAll(":scope > thead > tr > th")).forEach((th, index, all) => {
        if (index === all.length - 1) return;
        if (th.querySelector(":scope > .grid-col-resizer")) return;
        const handle = document.createElement("span");
        handle.className = "grid-col-resizer";
        handle.setAttribute("aria-hidden", "true");
        th.appendChild(handle);
      });
      restoreWidths(table);
    }
    restoreSort(table);
  }

  function initAllIn(root) {
    (root.matches && root.matches("table[data-grid]") ? [root] : Array.from(root.querySelectorAll ? root.querySelectorAll("table[data-grid]") : [])).forEach((table) => {
      if (table.dataset.gridWired === "1") return;
      table.dataset.gridWired = "1";
      initTable(table);
    });
  }

  function initAll() {
    document.querySelectorAll("table[data-grid]").forEach((table) => {
      if (table.dataset.gridWired === "1") return;
      table.dataset.gridWired = "1";
      initTable(table);
    });
  }

  // Delegated interaction handlers -- attached once, survive every
  // innerHTML swap because they live on `document`, not on the table.
  document.addEventListener("click", (event) => {
    const resizer = event.target.closest(".grid-col-resizer");
    if (resizer) return; // handled by pointerdown drag below
    const th = event.target.closest("th");
    if (isSortableHeader(th)) toggleSort(th);
  });

  document.addEventListener("keydown", (event) => {
    if (event.key !== "Enter" && event.key !== " ") return;
    const th = document.activeElement && document.activeElement.closest && document.activeElement.closest("th");
    if (isSortableHeader(th) && document.activeElement === th) {
      event.preventDefault();
      toggleSort(th);
    }
  });

  let drag = null;
  document.addEventListener("pointerdown", (event) => {
    const handle = event.target.closest(".grid-col-resizer");
    if (!handle) return;
    const th = handle.closest("th");
    const table = handle.closest("table[data-grid]");
    if (!th || !table) return;
    drag = { th: th, table: table, startX: event.clientX, startWidth: th.offsetWidth };
    event.preventDefault();
  });
  document.addEventListener("pointermove", (event) => {
    if (!drag) return;
    const next = Math.max(MIN_COLUMN_WIDTH, drag.startWidth + (event.clientX - drag.startX));
    drag.th.style.width = next + "px";
  });
  document.addEventListener("pointerup", () => {
    if (!drag) return;
    persistWidths(drag.table);
    drag = null;
  });

  // New tables (route change, or a sub-panel refresh like blocklist
  // sources / query log results / log viewer) appear via innerHTML
  // assignment anywhere under #app; catch all of them from one place.
  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach((node) => {
        if (node.nodeType !== 1) return;
        initAllIn(node);
      });
    }
  });
  const startObserving = () => {
    const app = document.getElementById("app") || document.body;
    observer.observe(app, { childList: true, subtree: true });
    initAll();
  };
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", startObserving);
  } else {
    startObserving();
  }

  return {
    parseCellValue: parseCellValue,
    compareCells: compareCells,
    initAll: initAll,
  };
}));
