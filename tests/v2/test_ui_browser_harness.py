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
