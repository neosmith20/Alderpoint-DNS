import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path
from urllib.request import urlopen

import pytest


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_http(url: str) -> None:
    last = None
    for _ in range(80):
        try:
            with urlopen(url, timeout=0.5) as res:
                if res.status < 500:
                    return
        except Exception as exc:  # pragma: no cover - diagnostic only
            last = exc
            time.sleep(0.25)
    raise AssertionError(f"service did not start at {url}: {last}")


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the Chromium DevTools harness")
@pytest.mark.skipif(shutil.which("chromium") is None, reason="chromium is required for the browser harness")
@pytest.mark.skipif(shutil.which("dnsdist") is None, reason="dnsdist is required for runtime-promoting UI flows")
def test_chromium_management_ui_harness(tmp_path):
    repo = Path(__file__).resolve().parents[2]
    state = tmp_path / "state"
    config = tmp_path / "etc"
    app_root = tmp_path / "opt"
    state.mkdir()
    config.mkdir()
    app_root.mkdir()

    from app.v2 import control_db, policy_store

    control_db.initialize(state / "control.db")
    policy_store.ensure_schema(state / "control.db")

    port = _free_port()
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(repo),
        "ALDERPOINTDNS_V2_APP_ROOT": str(app_root),
        "ALDERPOINTDNS_V2_CONFIG_ROOT": str(config),
        "ALDERPOINTDNS_V2_STATE_ROOT": str(state),
        "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
        "ALDERPOINTDNS_V2_FORCE_ANALYTICS_DEGRADED": "browser harness forced degraded state",
    })
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.v2.webapp:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_http(f"http://127.0.0.1:{port}/api/setup/status")
        harness_env = env.copy()
        harness_env.update({
            "APDNS_UI_BASE": f"http://127.0.0.1:{port}",
            "APDNS_CHROME_PORT": str(_free_port()),
            "APDNS_CHROME_PROFILE": str(tmp_path / "chrome-profile"),
        })
        result = subprocess.run(
            ["node", str(repo / "tests/v2/browser/chromium_ui_harness.js")],
            cwd=str(repo),
            env=harness_env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "setup-login" in result.stdout
        assert "backup-restore-workflow" in result.stdout
        assert "logout-session-invalidation" in result.stdout
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the Chromium DevTools harness")
@pytest.mark.skipif(shutil.which("chromium") is None, reason="chromium is required for the browser harness")
@pytest.mark.skipif(shutil.which("dnsdist") is None, reason="dnsdist is required for runtime-promoting UI flows")
@pytest.mark.parametrize(
    "browser_tz, appliance_tz",
    [
        ("America/Denver", "Etc/UTC"),  # owner's own worked example (also a DST date)
        ("Asia/Tokyo", "America/Denver"),
        ("America/New_York", "Europe/London"),
    ],
)
def test_timezone_display_modes(tmp_path, browser_tz, appliance_tz):
    """Real defect fixed this pass (owner-reported): raw UTC ISO
    timestamps were the default operator-facing presentation everywhere,
    and display must support real Browser Local / real Appliance Time /
    UTC modes -- never a hardcoded geographic timezone anywhere in
    production code. Runs with a real CDP browser-timezone override and
    a real (test-only, documented) server-side appliance-timezone
    override, deliberately mismatched from each other each parametrized
    run, so a passing run proves the two zones are never confused with
    one another -- see chromium_ui_harness.js's
    APDNS_ASSERT_TIMEZONE_DISPLAY block for exactly what's proven in the
    real rendered DOM (Browser Local, Appliance Time, UTC all correct;
    mode switch has no page reload; the preference survives a real
    reload; and chronological sort uses the real epoch value, never the
    locale-formatted display text).
    """
    repo = Path(__file__).resolve().parents[2]
    state = tmp_path / "state"
    config = tmp_path / "etc"
    app_root = tmp_path / "opt"
    state.mkdir()
    config.mkdir()
    app_root.mkdir()

    from app.v2 import control_db, policy_store

    control_db.initialize(state / "control.db")
    policy_store.ensure_schema(state / "control.db")

    port = _free_port()
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(repo),
        "ALDERPOINTDNS_V2_APP_ROOT": str(app_root),
        "ALDERPOINTDNS_V2_CONFIG_ROOT": str(config),
        "ALDERPOINTDNS_V2_STATE_ROOT": str(state),
        "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
        "ALDERPOINTDNS_V2_FORCE_APPLIANCE_TIMEZONE": appliance_tz,
    })
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.v2.webapp:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_http(f"http://127.0.0.1:{port}/api/setup/status")
        harness_env = env.copy()
        harness_env.update({
            "APDNS_UI_BASE": f"http://127.0.0.1:{port}",
            "APDNS_CHROME_PORT": str(_free_port()),
            "APDNS_CHROME_PROFILE": str(tmp_path / "chrome-profile"),
            "APDNS_CHROME_TIMEZONE": browser_tz,
            "APDNS_ASSERT_TIMEZONE_DISPLAY": "1",
            "APDNS_EXPECTED_BROWSER_TZ": browser_tz,
            "APDNS_EXPECTED_APPLIANCE_TZ": appliance_tz,
        })
        result = subprocess.run(
            ["node", str(repo / "tests/v2/browser/chromium_ui_harness.js")],
            cwd=str(repo),
            env=harness_env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "timestamp-browser-local-mode-correct" in result.stdout
        assert "timestamp-appliance-mode-correct" in result.stdout
        assert "timestamp-utc-mode-correct" in result.stdout
        assert "timestamp-preference-persists-across-reload" in result.stdout
        assert "timestamp-chronological-sort-uses-epoch-not-display-text" in result.stdout
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is required for the Chromium DevTools harness")
@pytest.mark.skipif(shutil.which("chromium") is None, reason="chromium is required for the browser harness")
@pytest.mark.skipif(shutil.which("dnsdist") is None, reason="dnsdist is required for runtime-promoting UI flows")
def test_dashboard_charts_render_real_data(tmp_path):
    """Real defect fixed this pass (owner-reported): Dashboard's "Top
    Domains" chart rendered anonymous bars with counts hidden in a
    `title` attribute -- no visible domain names, values, legend, or
    allowed/blocked distinction, and no time-series activity view
    existed at all. Unlike test_chromium_management_ui_harness above
    (deliberately forced degraded, to prove THAT state renders
    correctly), this run seeds real query-log/aggregate data first and
    runs with analytics genuinely live, so the new chart/table code
    renders against real backend output, not just a degraded banner --
    see chromium_ui_harness.js's APDNS_ASSERT_POPULATED_DASHBOARD block
    for exactly what's proven visible in the rendered DOM.
    """
    repo = Path(__file__).resolve().parents[2]
    state = tmp_path / "state"
    config = tmp_path / "etc"
    app_root = tmp_path / "opt"
    state.mkdir()
    config.mkdir()
    app_root.mkdir()
    (state / "analytics").mkdir()

    from app.v2 import aggregates_db, control_db, policy_store
    from app.v2.parquet_writer import ParquetSegmentWriter

    control_db.initialize(state / "control.db")
    policy_store.ensure_schema(state / "control.db")

    aggregates_path = state / "analytics" / "aggregates.db"
    parquet_root = state / "analytics" / "queries"
    aggregates_db.initialize(aggregates_path)

    seeded_domain = "chart-proof.example"
    now = time.time()

    def _record(ts, **overrides):
        base = dict(
            id=int(ts * 1000) % 1_000_000, ts=ts, client="10.0.0.1", client_name="",
            domain=seeded_domain, qtype="A", protocol="udp", rcode="NOERROR",
            latency_ms=5.0, blocked=False, block_reason="", upstream="default",
            cache_status="miss", cache_profile_id="p1",
        )
        base.update(overrides)
        return base

    records = [_record(now - i, blocked=(i % 4 == 0)) for i in range(30)]
    writer = ParquetSegmentWriter(root=parquet_root)
    writer.ingest(records)
    writer.flush()
    writer.close()
    aggregates_db.record_batch(aggregates_path, records)

    port = _free_port()
    env = os.environ.copy()
    env.update({
        "PYTHONPATH": str(repo),
        "ALDERPOINTDNS_V2_APP_ROOT": str(app_root),
        "ALDERPOINTDNS_V2_CONFIG_ROOT": str(config),
        "ALDERPOINTDNS_V2_STATE_ROOT": str(state),
        "ALDERPOINTDNS_V2_COOKIE_SECURE": "0",
    })
    server = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.v2.webapp:app", "--host", "127.0.0.1", "--port", str(port)],
        cwd=str(repo),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        _wait_http(f"http://127.0.0.1:{port}/api/setup/status")
        harness_env = env.copy()
        harness_env.update({
            "APDNS_UI_BASE": f"http://127.0.0.1:{port}",
            "APDNS_CHROME_PORT": str(_free_port()),
            "APDNS_CHROME_PROFILE": str(tmp_path / "chrome-profile"),
            "APDNS_ASSERT_POPULATED_DASHBOARD": "1",
            "APDNS_SEEDED_DOMAIN": seeded_domain,
        })
        result = subprocess.run(
            ["node", str(repo / "tests/v2/browser/chromium_ui_harness.js")],
            cwd=str(repo),
            env=harness_env,
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert "dashboard-charts-populated-and-accessible" in result.stdout
    finally:
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait(timeout=10)
