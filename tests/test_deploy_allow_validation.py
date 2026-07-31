#!/usr/bin/env python3
"""Regression tests for the beta.3 release-blocker bug: post-deploy
allow-domain validation incorrectly required a live A record, and a later
filtering-postcheck failure left an already-applied cache-options change
active while still reporting the deployment as fully rolled back.

Covers: structured DNS classification, allow-domain validation against the
compiled policy (not live external-domain availability), the real-world
downloaded AdGuard `@@||ad.10010.com^` NODATA case, cache-options rollback on
a later postcheck failure, accurate rollback-failure reporting, and the CLI
no longer leaking a raw Python traceback into subprocess output that the web
UI renders. No live internet access is used anywhere -- all DNS results are
mocked as structured compiler.DNSResult values.
"""

from __future__ import annotations

import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
import warnings
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
warnings.simplefilter("ignore", ResourceWarning)

from app import alderpointdns_compiler as compiler  # noqa: E402
from app import custom_rules, dns_cache, local_dns  # noqa: E402


def dns_result(domain: str, **kwargs) -> compiler.DNSResult:
    return compiler.DNSResult(domain=domain, **kwargs)


class ClassifyDNSTests(unittest.TestCase):
    """classify_dns() must turn dig's raw text into a structured result that
    distinguishes every response shape an allow-listed real-world domain can
    legitimately produce."""

    def dig_output(self, status: str, answers: list[str]) -> str:
        lines = [
            ";; ->>HEADER<<- opcode: QUERY, status: %s, id: 1" % status,
            f";; flags: qr rd ra; QUERY: 1, ANSWER: {len(answers)}, AUTHORITY: 1, ADDITIONAL: 1",
            "",
            ";; ANSWER SECTION:",
        ]
        lines.extend(answers)
        return "\n".join(lines) + "\n"

    def run_classify(self, stdout: str, returncode: int = 0) -> compiler.DNSResult:
        with mock.patch.object(compiler, "run", return_value=subprocess.CompletedProcess(["dig"], returncode, stdout)):
            return compiler.classify_dns("example.test")

    def test_a_record(self) -> None:
        out = self.dig_output("NOERROR", ["example.test.\t300\tIN\tA\t192.0.2.1"])
        result = self.run_classify(out)
        self.assertTrue(result.resolved)
        self.assertEqual(result.a_records, ["192.0.2.1"])

    def test_aaaa_only(self) -> None:
        out = self.dig_output("NOERROR", ["example.test.\t300\tIN\tAAAA\t2001:db8::1"])
        result = self.run_classify(out)
        self.assertTrue(result.resolved)
        self.assertEqual(result.aaaa_records, ["2001:db8::1"])
        self.assertFalse(result.a_records)

    def test_cname_only(self) -> None:
        out = self.dig_output("NOERROR", ["example.test.\t300\tIN\tCNAME\ttarget.test."])
        result = self.run_classify(out)
        self.assertTrue(result.resolved)
        self.assertEqual(result.cname_records, ["target.test."])

    def test_nodata(self) -> None:
        out = self.dig_output("NOERROR", [])
        result = self.run_classify(out)
        self.assertFalse(result.resolved)
        self.assertTrue(result.is_nodata)

    def test_nxdomain(self) -> None:
        out = self.dig_output("NXDOMAIN", [])
        result = self.run_classify(out)
        self.assertFalse(result.resolved)
        self.assertTrue(result.is_nxdomain)

    def test_servfail(self) -> None:
        out = self.dig_output("SERVFAIL", [])
        result = self.run_classify(out)
        self.assertFalse(result.resolved)
        self.assertTrue(result.is_servfail)
        self.assertTrue(result.usable)

    def test_timeout(self) -> None:
        result = self.run_classify("\n;; connection timed out; no servers could be reached\n", returncode=9)
        self.assertTrue(result.timed_out)
        self.assertFalse(result.usable)
        self.assertFalse(result.resolved)


class ValidateAllowDomainsTests(unittest.TestCase):
    """validate_allow_domains() must never fail solely because a real-world
    allow-listed domain is currently unresolvable/NODATA/AAAA-only/etc, and
    must fail only on a genuine structural mismatch with the compiled policy."""

    def setUp(self) -> None:
        self.custom_active = custom_rules.ActiveRuleSet()
        self.rpz_text = "$TTL 2h\n"

    def test_downloaded_nodata_domain_is_non_fatal(self) -> None:
        # Reproduces the real reported case: a downloaded AdGuard exception
        # rule for ad.10010.com resolves NOERROR/NODATA (no A record).
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("ad.10010.com", status="NOERROR", answer_count=0)):
            result = compiler.validate_allow_domains({"ad.10010.com"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)
        self.assertIsNone(result.tested_domain)

    def test_aaaa_only_candidate_is_used_as_positive_evidence(self) -> None:
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("v6only.test", aaaa_records=["2001:db8::1"], status="NOERROR", answer_count=1)):
            result = compiler.validate_allow_domains({"v6only.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)
        self.assertEqual(result.tested_domain, "v6only.test")

    def test_nxdomain_candidate_is_non_fatal(self) -> None:
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("gone.test", status="NXDOMAIN")):
            result = compiler.validate_allow_domains({"gone.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)
        self.assertIsNone(result.tested_domain)

    def test_servfail_candidate_is_non_fatal(self) -> None:
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("broken.test", status="SERVFAIL")):
            result = compiler.validate_allow_domains({"broken.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)

    def test_timeout_candidate_is_non_fatal(self) -> None:
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("slow.test", timed_out=True, transport_ok=False)):
            result = compiler.validate_allow_domains({"slow.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)

    def test_multiple_unsuitable_candidates_then_one_usable(self) -> None:
        def fake_classify(domain: str, rtype: str = "A") -> compiler.DNSResult:
            if domain == "z-usable.test":
                return dns_result(domain, a_records=["192.0.2.5"], status="NOERROR", answer_count=1)
            return dns_result(domain, status="NXDOMAIN")

        domains = {"a-nx.test", "b-servfail.test", "z-usable.test"}
        with mock.patch.object(compiler, "classify_dns", side_effect=fake_classify):
            result = compiler.validate_allow_domains(domains, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)
        self.assertEqual(result.tested_domain, "z-usable.test")

    def test_no_usable_live_candidate_available_is_still_non_fatal(self) -> None:
        def fake_classify(domain: str, rtype: str = "A") -> compiler.DNSResult:
            return dns_result(domain, timed_out=True, transport_ok=False)

        with mock.patch.object(compiler, "classify_dns", side_effect=fake_classify):
            result = compiler.validate_allow_domains({"one.test", "two.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)
        self.assertIsNone(result.tested_domain)
        self.assertIn("non-fatal", result.message)

    def test_allow_domain_still_in_active_blocks_is_fatal(self) -> None:
        # A genuine bug: the allow rule failed to subtract the domain from
        # the compiled block set. This must fail loudly.
        result = compiler.validate_allow_domains({"broken-allow.test"}, {"broken-allow.test"}, self.custom_active, self.rpz_text)
        self.assertFalse(result.ok)
        self.assertIn("broken-allow.test", result.message)

    def test_custom_exact_allow_missing_passthru_is_fatal(self) -> None:
        self.custom_active.allows["custom-allow.test"] = {"exact": True, "subdomains": False, "priority": 0}
        result = compiler.validate_allow_domains({"custom-allow.test"}, set(), self.custom_active, self.rpz_text)
        self.assertFalse(result.ok)
        self.assertIn("rpz-passthru", result.message)

    def test_custom_exact_allow_with_passthru_present_passes_structural_check(self) -> None:
        self.custom_active.allows["custom-allow.test"] = {"exact": True, "subdomains": False, "priority": 0}
        rpz_text = self.rpz_text + "custom-allow.test CNAME rpz-passthru.\n"
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("custom-allow.test", status="NXDOMAIN")):
            result = compiler.validate_allow_domains({"custom-allow.test"}, set(), self.custom_active, rpz_text)
        self.assertTrue(result.ok)

    def test_custom_subdomain_allow_requires_wildcard_passthru(self) -> None:
        self.custom_active.allows["sub-allow.test"] = {"exact": False, "subdomains": True, "priority": 0}
        rpz_text = self.rpz_text + "sub-allow.test CNAME rpz-passthru.\n"  # missing the *. wildcard line
        result = compiler.validate_allow_domains({"sub-allow.test"}, set(), self.custom_active, rpz_text)
        self.assertFalse(result.ok)

    def test_overlapping_allow_and_external_blocklist_entry(self) -> None:
        # The allow rule for a domain that also appears on an external
        # blocklist must already be subtracted from active_blocks by the
        # time validation runs -- if it isn't, that's the fatal case above.
        with mock.patch.object(compiler, "classify_dns", return_value=dns_result("shared.test", status="NOERROR", answer_count=0)):
            result = compiler.validate_allow_domains({"shared.test"}, set(), self.custom_active, self.rpz_text)
        self.assertTrue(result.ok)


class DeployRollbackTestBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-deploy-rollback-test-"))
        self.old = {
            "c_DB_PATH": compiler.DB_PATH,
            "c_DOWNLOAD_DIR": compiler.DOWNLOAD_DIR,
            "c_COMPILED_RPZ": compiler.COMPILED_RPZ,
            "c_STAGING_DIR": compiler.STAGING_DIR,
            "c_BACKUP_DIR": compiler.BACKUP_DIR,
            "c_DEPLOY_LOCK": compiler.DEPLOY_LOCK,
            "l_DB_PATH": local_dns.DB_PATH,
            "dc_DB_PATH": dns_cache.DB_PATH,
            "dc_COMPILED_DIR": dns_cache.COMPILED_DIR,
            "dc_CACHE_OPTIONS_CONF": dns_cache.CACHE_OPTIONS_CONF,
            "dc_NAMED_OPTIONS_CONF": dns_cache.NAMED_OPTIONS_CONF,
            "dc_BACKUP_DIR": dns_cache.BACKUP_DIR,
            "dc_STAGING_DIR": dns_cache.STAGING_DIR,
            "cr_DB_PATH": custom_rules.DB_PATH,
            "cr_COMPILED_DNSDIST_DIR": custom_rules.COMPILED_DNSDIST_DIR,
            "cr_DNSDIST_CONF": custom_rules.DNSDIST_CONF,
            "cr_DNSDIST_PACKAGING_CONF": custom_rules.DNSDIST_PACKAGING_CONF,
            "cr_BACKUP_DIR": custom_rules.BACKUP_DIR,
            "cr_STAGING_DIR": custom_rules.STAGING_DIR,
        }
        db_path = self.tmp / "alderpointdns.db"
        compiler.DB_PATH = db_path
        compiler.DOWNLOAD_DIR = self.tmp / "downloads"
        compiler.COMPILED_RPZ = self.tmp / "compiled" / "bind" / "alderpointdns.rpz"
        compiler.STAGING_DIR = self.tmp / "staging"
        compiler.BACKUP_DIR = self.tmp / "backups"
        compiler.DEPLOY_LOCK = self.tmp / "staging" / "deploy.lock"
        local_dns.DB_PATH = db_path
        dns_cache.DB_PATH = db_path
        dns_cache.COMPILED_DIR = self.tmp / "compiled" / "bind"
        dns_cache.CACHE_OPTIONS_CONF = dns_cache.COMPILED_DIR / "cache-options.conf"
        dns_cache.NAMED_OPTIONS_CONF = self.tmp / "named.conf.options"
        dns_cache.BACKUP_DIR = self.tmp / "backups"
        dns_cache.STAGING_DIR = self.tmp / "staging"
        custom_rules.DB_PATH = db_path
        custom_rules.COMPILED_DNSDIST_DIR = self.tmp / "compiled" / "dnsdist"
        custom_rules.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        custom_rules.DNSDIST_PACKAGING_CONF = self.tmp / "packaging-dnsdist.conf"
        custom_rules.BACKUP_DIR = self.tmp / "backups"
        custom_rules.STAGING_DIR = self.tmp / "staging"
        compiler.STAGING_DIR.mkdir(parents=True)
        dns_cache.NAMED_OPTIONS_CONF.write_text('options {\n\tdirectory "/var/cache/bind";\n};\n')
        custom_rules.DNSDIST_CONF.write_text(
            '-- lab config\naddAction(AllRule(), PoolAction("alderpointdns_bind"))\n'
        )
        compiler.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            prefix, name = key.split("_", 1)
            module = {"c": compiler, "l": local_dns, "dc": dns_cache, "cr": custom_rules}[prefix]
            setattr(module, name, value)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(compiler.DB_PATH)
        conn.row_factory = sqlite3.Row
        return conn

    def fake_run_ok(self, command: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(command, 0, "ok\n")


class CacheRollbackTests(DeployRollbackTestBase):
    """Reproduces: cache settings deployed successfully, then a later
    filtering postcheck failed, and the deployment was recorded as fully
    rolled_back while the new cache-options.conf stayed active."""

    def deploy_with_real_cache_then_fail_postcheck(self) -> tuple[int, str]:
        dns_cache.CACHE_OPTIONS_CONF.parent.mkdir(parents=True, exist_ok=True)
        dns_cache.CACHE_OPTIONS_CONF.write_text("// before\nprefetch 0;\n")

        def real_cache_deploy(conn=None):
            dns_cache.CACHE_OPTIONS_CONF.write_text("// after\nprefetch 2 10;\n")
            return 1

        with mock.patch.object(compiler, "run", self.fake_run_ok), \
                mock.patch.object(custom_rules, "run", self.fake_run_ok), \
                mock.patch.object(compiler, "resolves", lambda domain: True), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", real_cache_deploy), \
                mock.patch.object(compiler.upstream_dns, "deploy_upstreams", lambda conn=None: 1), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            custom_rules.add_rule("||forced-block.example^")
            with self.assertRaises(RuntimeError):
                import os

                os.environ["ALDERPOINTDNS_TEST_FORCE_POSTCHECK_FAIL"] = "1"
                try:
                    compiler.deploy(download=False)
                finally:
                    del os.environ["ALDERPOINTDNS_TEST_FORCE_POSTCHECK_FAIL"]
        with self.connect() as conn:
            row = conn.execute("SELECT status, message FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        return row["status"], row["message"]

    def test_cache_options_are_restored_on_later_postcheck_failure(self) -> None:
        status, _message = self.deploy_with_real_cache_then_fail_postcheck()
        self.assertEqual(dns_cache.CACHE_OPTIONS_CONF.read_text(), "// before\nprefetch 0;\n")
        self.assertEqual(status, "rolled_back")

    def test_rollback_never_reported_while_cache_remains_active(self) -> None:
        # If cache rollback itself fails, status must say so -- never
        # "rolled_back" while the new cache config is still live.
        dns_cache.CACHE_OPTIONS_CONF.parent.mkdir(parents=True, exist_ok=True)
        dns_cache.CACHE_OPTIONS_CONF.write_text("// before\nprefetch 0;\n")

        def real_cache_deploy(conn=None):
            dns_cache.CACHE_OPTIONS_CONF.write_text("// after\nprefetch 2 10;\n")
            return 1

        real_write_text = Path.write_text
        call_count = {"n": 0}

        def flaky_write_text(self_path, *args, **kwargs):
            if self_path == dns_cache.CACHE_OPTIONS_CONF:
                call_count["n"] += 1
                if call_count["n"] > 1:
                    raise OSError("simulated disk failure during cache rollback")
            return real_write_text(self_path, *args, **kwargs)

        with mock.patch.object(compiler, "run", self.fake_run_ok), \
                mock.patch.object(custom_rules, "run", self.fake_run_ok), \
                mock.patch.object(compiler, "resolves", lambda domain: True), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", real_cache_deploy), \
                mock.patch.object(compiler.upstream_dns, "deploy_upstreams", lambda conn=None: 1), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None), \
                mock.patch.object(Path, "write_text", flaky_write_text):
            import os

            os.environ["ALDERPOINTDNS_TEST_FORCE_POSTCHECK_FAIL"] = "1"
            try:
                with self.assertRaises(RuntimeError):
                    compiler.deploy(download=False)
            finally:
                del os.environ["ALDERPOINTDNS_TEST_FORCE_POSTCHECK_FAIL"]
        with self.connect() as conn:
            row = conn.execute("SELECT status FROM deployments ORDER BY id DESC LIMIT 1").fetchone()
        self.assertEqual(row["status"], "rollback_failed")


class DownloadedAllowDomainDeployTests(DeployRollbackTestBase):
    """End-to-end reproduction of the real reported case using a source file
    exactly like the downloaded AdGuard DNS filter's exception rule."""

    def add_source_with_content(self, content: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sources(name, url, enabled) VALUES ('test-source', 'https://filters.example/test.txt', 1)"
            )
            conn.commit()
            source = conn.execute("SELECT * FROM sources WHERE name='test-source'").fetchone()
        current_path, _staging_path = compiler.source_paths(source)
        current_path.parent.mkdir(parents=True, exist_ok=True)
        current_path.write_text(content)

    def test_deploy_succeeds_with_nodata_downloaded_allow_domain(self) -> None:
        self.add_source_with_content("||blocked-example.test^\n@@||ad.10010.com^\n")

        def classify_side_effect(domain: str, rtype: str = "A") -> compiler.DNSResult:
            if domain == "ad.10010.com":
                return compiler.DNSResult(domain=domain, status="NOERROR", answer_count=0)
            return compiler.DNSResult(domain=domain, a_records=["192.0.2.1"], status="NOERROR", answer_count=1)

        with mock.patch.object(compiler, "run", self.fake_run_ok), \
                mock.patch.object(custom_rules, "run", self.fake_run_ok), \
                mock.patch.object(compiler, "resolves", lambda domain: True), \
                mock.patch.object(compiler, "is_blocked", lambda domain: True), \
                mock.patch.object(compiler, "classify_dns", side_effect=classify_side_effect), \
                mock.patch.object(compiler.local_dns, "deploy_zones", lambda conn=None: 1), \
                mock.patch.object(compiler.dns_cache, "deploy_cache_options", lambda conn=None: 1), \
                mock.patch.object(compiler.upstream_dns, "deploy_upstreams", lambda conn=None: 1), \
                mock.patch.object(compiler.replication, "on_deploy_success", lambda conn=None: None):
            deployment_id = compiler.deploy(download=False)
        with self.connect() as conn:
            row = conn.execute("SELECT status, allowed_test_domain, message FROM deployments WHERE id=?", (deployment_id,)).fetchone()
        self.assertEqual(row["status"], "deployed")
        self.assertNotIn("ad.10010.com", row["message"] or "")


class CLINoTracebackLeakTests(unittest.TestCase):
    """The CLI's main() must never let a raw Python traceback reach the
    process's stdout/stderr, since webapp.py's subprocess runners capture
    that output verbatim and some routes render it directly to the admin."""

    def test_unexpected_exception_produces_concise_message_not_traceback(self) -> None:
        def boom(_args) -> None:
            raise KeyError("unexpected internal state")

        with mock.patch.object(compiler, "_log_unexpected_failure") as log_mock:
            parser_patch = mock.patch.object(
                compiler.argparse.ArgumentParser,
                "parse_args",
                return_value=type("Args", (), {"func": staticmethod(boom)})(),
            )
            with parser_patch:
                import io
                import contextlib

                buf = io.StringIO()
                with contextlib.redirect_stderr(buf):
                    exit_code = compiler.main([])
        self.assertEqual(exit_code, 1)
        self.assertNotIn("Traceback", buf.getvalue())
        self.assertIn("unexpected internal state", buf.getvalue())
        log_mock.assert_called_once()

    def test_log_unexpected_failure_writes_full_traceback_to_dedicated_log(self) -> None:
        tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-cli-log-test-"))
        old_log = compiler.CLI_ERROR_LOG
        compiler.CLI_ERROR_LOG = tmp / "compiler-errors.log"
        try:
            try:
                raise ValueError("boom for traceback capture")
            except ValueError as exc:
                compiler._log_unexpected_failure(exc)
            content = compiler.CLI_ERROR_LOG.read_text()
            self.assertIn("Traceback", content)
            self.assertIn("boom for traceback capture", content)
            mode = compiler.CLI_ERROR_LOG.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600, f"CLI error log must be root-only 0600, got {oct(mode)}")
        finally:
            compiler.CLI_ERROR_LOG = old_log
            shutil.rmtree(tmp, ignore_errors=True)

    def test_log_unexpected_failure_stays_0600_across_repeated_appends(self) -> None:
        # A umask or an externally-widened file must not survive a second
        # append -- chmod is reasserted on every write, not just creation.
        tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-cli-log-test-"))
        old_log = compiler.CLI_ERROR_LOG
        compiler.CLI_ERROR_LOG = tmp / "compiler-errors.log"
        try:
            compiler.CLI_ERROR_LOG.write_text("pre-existing, wide-open\n")
            compiler.CLI_ERROR_LOG.chmod(0o644)
            try:
                raise ValueError("second failure")
            except ValueError as exc:
                compiler._log_unexpected_failure(exc)
            mode = compiler.CLI_ERROR_LOG.stat().st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            compiler.CLI_ERROR_LOG = old_log
            shutil.rmtree(tmp, ignore_errors=True)


class SudoersCacheDeployTests(unittest.TestCase):
    """The webapp's cache-only save path (cache_options_deploy_or_raise)
    calls `sudo alderpointdns_compiler.py cache-deploy`; the sudoers
    drop-in must actually allow that exact command or every Cache page
    settings save fails with a sudo permission error in production."""

    def test_sudoers_allows_cache_deploy(self) -> None:
        sudoers = (ROOT / "packaging" / "sudoers-alderpointdns").read_text()
        self.assertIn("alderpointdns_compiler.py cache-deploy", sudoers)


class CacheOnlySaveDecoupledTests(unittest.TestCase):
    """The Cache page's settings save must deploy only the cache-options
    component, not trigger a full blocklist/RPZ/dnsdist redeploy."""

    def test_dns_cache_settings_route_uses_cache_only_deploy(self) -> None:
        from app import webapp

        source = Path(webapp.__file__).read_text()
        route_start = source.index("def dns_cache_settings_post")
        route_end = source.index("\n@app.", route_start + 1)
        route_body = source[route_start:route_end]
        self.assertIn("cache_options_deploy_or_raise()", route_body)
        self.assertNotIn("deploy_no_download_or_raise()", route_body)

    def test_cache_options_deploy_invokes_cache_deploy_subcommand_not_full_deploy(self) -> None:
        from app import webapp

        with mock.patch.object(webapp, "run", return_value=(0, "ok")) as run_mock:
            webapp.cache_options_deploy_or_raise()
        run_mock.assert_called_once()
        command = run_mock.call_args[0][0]
        self.assertEqual(command, ["sudo", "/opt/alderpointdns/app/alderpointdns_compiler.py", "cache-deploy"])


if __name__ == "__main__":
    unittest.main()
