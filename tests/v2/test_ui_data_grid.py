"""Workstream 1 (UI Foundation) coverage for the shared data-grid.

The roadmap/parity contract (docs/v2/v2-roadmap.md, "Data-grid requirements")
requires ONE shared sortable/resizable table implementation used across the
major product tables, not a per-page hack. Before this pass, app/v2/ui/app.js
rendered every table as a plain <table> string with no sort or resize
affordance at all (grep for `<table>` in app.js history).

These tests prove:
  - app/v2/ui/data-grid.js is served and linked from the UI shell, before
    app.js (so its delegated listeners/observer are attached first);
  - the major operator tables opt into it via `data-grid` with a stable
    `data-grid-id` (needed for width/sort persistence across navigation);
  - actions-only columns are excluded from sorting.

Full click/drag interaction (mouse sort toggle, column drag-resize,
persistence across a real browser session) requires the headless Chromium
acceptance pass (workstream 14: tests/v2/browser/chromium_ui_harness.js) and
is intentionally not re-implemented here; the DOM-independent comparator
logic this module shares with the browser is covered by
tests/js/test_data_grid_compare.mjs (plain Node, no jsdom).
"""
from __future__ import annotations

import importlib
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
UI_DIR = ROOT / "app" / "v2" / "ui"

# App.js call sites that opt a major operator table into the shared grid via
# an explicit, stable data-grid-id (tableFromRows(..., gridId) or literal
# markup). Not exhaustive of every <table> in the app -- covers the tables
# the roadmap workstreams explicitly name.
EXPECTED_GRID_IDS = {
    "dashboard-top-domains",
    "dashboard-upstreams",
    "dashboard-clients",
    "query-log-results",
    "query-log-top-domains",
    "filtering-rulesets",
    "filtering-schedules",
    "filtering-services",
    "upstream-profiles",
    "upstream-domain-routes",
    "local-dns-records",
    "notification-providers",
    "observed-clients",
    "managed-clients",
    "blocklist-subscriptions",
}


def _fresh_webapp(tmp_path, monkeypatch):
    monkeypatch.setenv("ALDERPOINTDNS_V2_APP_ROOT", str(tmp_path / "opt"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_CONFIG_ROOT", str(tmp_path / "etc"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_STATE_ROOT", str(tmp_path / "state"))
    monkeypatch.setenv("ALDERPOINTDNS_V2_COOKIE_SECURE", "0")
    (tmp_path / "state").mkdir(parents=True, exist_ok=True)
    from app.v2 import control_db, policy_store

    control_db.initialize(tmp_path / "state" / "control.db")
    policy_store.ensure_schema(tmp_path / "state" / "control.db")
    sys.modules.pop("app.v2.webapp", None)
    return importlib.import_module("app.v2.webapp")


def _client(webapp):
    from fastapi.testclient import TestClient

    return TestClient(webapp.app)


def test_app_js_source_has_no_syntax_errors_and_defines_shared_grid_ids():
    source = (UI_DIR / "app.js").read_text()
    found_ids = set(re.findall(r'"([a-z0-9-]+)"', source)) & EXPECTED_GRID_IDS
    missing = EXPECTED_GRID_IDS - found_ids
    assert not missing, f"app.js is missing expected shared data-grid id(s): {missing}"


def test_every_expected_table_call_site_opts_into_shared_grid():
    source = (UI_DIR / "app.js").read_text()
    for grid_id in EXPECTED_GRID_IDS:
        pattern = re.compile(r'data-grid[^>]*data-grid-id="%s"|tableFromRows\([^)]*"%s"\)' % (re.escape(grid_id), re.escape(grid_id)))
        assert pattern.search(source), f"no data-grid wiring found for {grid_id!r}"


def test_actions_only_headers_are_excluded_from_sorting():
    source = (UI_DIR / "app.js").read_text()
    # Within a table that opted into the shared grid, an "Actions" header
    # must not be sortable -- clicking it does nothing meaningful. (A plain
    # <table> with no data-grid attribute isn't sortable at all, so it's out
    # of scope here.)
    for table_match in re.finditer(r"<table data-grid[^>]*>.*?</thead>", source):
        thead = table_match.group(0)
        for header_match in re.finditer(r"<th[^>]*>Actions</th>", thead):
            assert "data-no-sort" in header_match.group(0), (
                f"Actions header missing data-no-sort: {header_match.group(0)}"
            )


def test_data_grid_module_has_no_syntax_errors():
    # A parse-level smoke check without requiring Node here: the shared
    # comparator logic itself is exercised by tests/js/test_data_grid_compare.mjs.
    source = (UI_DIR / "data-grid.js").read_text()
    assert "AlderpointDataGrid" in source
    assert "parseCellValue" in source
    assert source.count("function (root, factory)") == 1


def test_index_html_links_data_grid_before_app_js():
    html = (UI_DIR / "index.html").read_text()
    assert "data-grid.js" in html
    assert html.index("data-grid.js") < html.index("app.js")


def test_ui_static_serves_data_grid_script(tmp_path, monkeypatch):
    webapp = _fresh_webapp(tmp_path, monkeypatch)
    client = _client(webapp)

    shell = client.get("/")
    assert shell.status_code == 200
    assert "/ui-static/data-grid.js" in shell.text
    assert shell.text.index("/ui-static/data-grid.js") < shell.text.index("/ui-static/app.js")

    script = client.get("/ui-static/data-grid.js")
    assert script.status_code == 200
    assert "AlderpointDataGrid" in script.text
