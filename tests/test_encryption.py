#!/usr/bin/env python3
from __future__ import annotations

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

from app import encryption  # noqa: E402


class EncryptionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-encryption-test-"))
        self.old = {
            "DB_PATH": encryption.DB_PATH,
            "CERT_DIR": encryption.CERT_DIR,
            "CERT_PATH_DEFAULT": encryption.CERT_PATH_DEFAULT,
            "KEY_PATH_DEFAULT": encryption.KEY_PATH_DEFAULT,
            "CA_CERT_PATH": encryption.CA_CERT_PATH,
            "CA_KEY_PATH": encryption.CA_KEY_PATH,
            "CA_SERIAL_PATH": encryption.CA_SERIAL_PATH,
            "UPLOADED_CERT_PATH": encryption.UPLOADED_CERT_PATH,
            "UPLOADED_KEY_PATH": encryption.UPLOADED_KEY_PATH,
            "PENDING_UPLOAD_CERT": encryption.PENDING_UPLOAD_CERT,
            "PENDING_UPLOAD_KEY": encryption.PENDING_UPLOAD_KEY,
            "DNSCRYPT_PROVIDER_PUBLIC": encryption.DNSCRYPT_PROVIDER_PUBLIC,
            "DNSCRYPT_PROVIDER_PRIVATE": encryption.DNSCRYPT_PROVIDER_PRIVATE,
            "DNSCRYPT_CERT": encryption.DNSCRYPT_CERT,
            "DNSCRYPT_KEY": encryption.DNSCRYPT_KEY,
            "DNSDIST_CONF": encryption.DNSDIST_CONF,
            "DNSDIST_ENV_OVERRIDE": encryption.DNSDIST_ENV_OVERRIDE,
            "BACKUP_DIR": encryption.BACKUP_DIR,
            "STAGING_DIR": encryption.STAGING_DIR,
        }
        encryption.DB_PATH = self.tmp / "alderpointdns.db"
        encryption.CERT_DIR = self.tmp / "certs"
        encryption.CERT_PATH_DEFAULT = encryption.CERT_DIR / "alderpointdns-lab.crt"
        encryption.KEY_PATH_DEFAULT = encryption.CERT_DIR / "alderpointdns-lab.key"
        encryption.CA_CERT_PATH = encryption.CERT_DIR / "alderpointdns-ca.crt"
        encryption.CA_KEY_PATH = encryption.CERT_DIR / "alderpointdns-ca.key"
        encryption.CA_SERIAL_PATH = encryption.CERT_DIR / "alderpointdns-ca.srl"
        encryption.UPLOADED_CERT_PATH = encryption.CERT_DIR / "alderpointdns-uploaded.crt"
        encryption.UPLOADED_KEY_PATH = encryption.CERT_DIR / "alderpointdns-uploaded.key"
        encryption.DNSCRYPT_PROVIDER_PUBLIC = encryption.CERT_DIR / "dnscrypt-provider.public"
        encryption.DNSCRYPT_PROVIDER_PRIVATE = encryption.CERT_DIR / "dnscrypt-provider.private"
        encryption.DNSCRYPT_CERT = encryption.CERT_DIR / "dnscrypt-resolver.cert"
        encryption.DNSCRYPT_KEY = encryption.CERT_DIR / "dnscrypt-resolver.key"
        encryption.DNSDIST_CONF = self.tmp / "dnsdist.conf"
        encryption.DNSDIST_ENV_OVERRIDE = self.tmp / "alderpointdns.conf"
        encryption.BACKUP_DIR = self.tmp / "backups"
        encryption.STAGING_DIR = self.tmp / "staging"
        encryption.PENDING_UPLOAD_CERT = encryption.STAGING_DIR / "pending-cert-upload.crt"
        encryption.PENDING_UPLOAD_KEY = encryption.STAGING_DIR / "pending-cert-upload.key"
        encryption.STAGING_DIR.mkdir(parents=True)
        encryption.CERT_DIR.mkdir(parents=True)
        encryption.init_db()

    def tearDown(self) -> None:
        for key, value in self.old.items():
            setattr(encryption, key, value)
        import shutil

        shutil.rmtree(self.tmp, ignore_errors=True)

    # A fully-featured dnsdist build (e.g. the official PowerDNS repository
    # package), so tests that don't specifically exercise capability
    # detection keep exercising every protocol as before it existed.
    FAKE_DNSDIST_VERSION_FULL = (
        "dnsdist 2.1.0 (Lua 5.1.4 [LuaJIT])\n"
        "Enabled features: dns-over-quic dns-over-http3 dns-over-tls(openssl) "
        "dns-over-https(nghttp2) dnscrypt protobuf systemd\n"
    )

    def fake_run_ok(self, command: list[str], check: bool = True, env=None, input_text=None) -> subprocess.CompletedProcess[str]:
        # Only fake the dnsdist/systemctl side effects that would otherwise
        # touch the live host; let openssl/named-style commands run for real
        # so certificate generation inside deploy_encryption stays honest.
        if command[:2] == ["dnsdist", "--version"]:
            return subprocess.CompletedProcess(command, 0, self.FAKE_DNSDIST_VERSION_FULL)
        if command[0] in ("systemctl", "dnsdist"):
            return subprocess.CompletedProcess(command, 0, "ok\n")
        return subprocess.run(command, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=check, env=env, input=input_text)

    # -- validation ------------------------------------------------------

    def test_validate_settings_rejects_bad_hostname(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "server_hostname": "not a hostname!"})

    def test_validate_settings_rejects_bad_port(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "doh_port": "70000"})

    def test_validate_settings_rejects_bad_listen_address(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "listen_ipv4": "::1"})
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "listen_ipv6": "127.0.0.1"})
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "listen_ipv4": "", "listen_ipv6": ""})

    def test_validate_settings_rejects_unknown_cert_mode(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "cert_mode": "bogus"})

    def test_validate_settings_existing_path_requires_both_paths(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.validate_settings({**encryption.DEFAULTS, "cert_mode": "existing_path", "cert_path": "/x.crt", "key_path": ""})

    def test_validate_settings_normalizes_doh_path(self) -> None:
        out = encryption.validate_settings({**encryption.DEFAULTS, "doh_path": "dns-query"})
        self.assertEqual(out["doh_path"], "/dns-query")

    def test_update_settings_persists(self) -> None:
        encryption.update_settings({**encryption.DEFAULTS, "server_hostname": "dns.example.com"})
        self.assertEqual(encryption.settings()["server_hostname"], "dns.example.com")

    # -- certificate generation and validation ----------------------------

    def test_generate_self_signed_creates_matching_pair(self) -> None:
        encryption.generate_self_signed("dns.example.com", ["192.168.1.101"], days=30)
        self.assertTrue(encryption.CERT_PATH_DEFAULT.exists())
        self.assertTrue(encryption.KEY_PATH_DEFAULT.exists())
        self.assertTrue(encryption.validate_cert_key_match(encryption.CERT_PATH_DEFAULT, encryption.KEY_PATH_DEFAULT))
        info = encryption.cert_info(encryption.CERT_PATH_DEFAULT)
        self.assertTrue(info["available"])
        self.assertTrue(info["self_signed"])
        self.assertIn("DNS:dns.example.com", info["sans"])
        self.assertFalse(info["expired"])

    def test_local_ca_issues_matching_leaf_cert(self) -> None:
        encryption.issue_from_local_ca("dns.example.com", days=30)
        self.assertTrue(encryption.CA_CERT_PATH.exists())
        self.assertTrue(encryption.validate_cert_key_match(encryption.CERT_PATH_DEFAULT, encryption.KEY_PATH_DEFAULT))
        info = encryption.cert_info(encryption.CERT_PATH_DEFAULT)
        self.assertFalse(info["self_signed"])
        self.assertEqual(info["issuer"], "CN=Alderpoint DNS Local CA")

    def test_local_ca_reused_across_multiple_leaf_certs(self) -> None:
        encryption.issue_from_local_ca("a.example.com", days=30)
        ca_bytes_first = encryption.CA_CERT_PATH.read_bytes()
        encryption.issue_from_local_ca("b.example.com", days=30)
        self.assertEqual(encryption.CA_CERT_PATH.read_bytes(), ca_bytes_first)

    def test_mismatched_cert_and_key_do_not_validate(self) -> None:
        encryption.generate_self_signed("a.example.com", days=30)
        cert_bytes = encryption.CERT_PATH_DEFAULT.read_bytes()
        encryption.generate_self_signed("b.example.com", days=30)
        encryption.CERT_PATH_DEFAULT.write_bytes(cert_bytes)
        self.assertFalse(encryption.validate_cert_key_match(encryption.CERT_PATH_DEFAULT, encryption.KEY_PATH_DEFAULT))

    def test_accept_uploaded_rejects_mismatched_pair(self) -> None:
        encryption.generate_self_signed("a.example.com", days=30)
        cert_bytes = encryption.CERT_PATH_DEFAULT.read_bytes()
        encryption.generate_self_signed("b.example.com", days=30)
        key_bytes = encryption.KEY_PATH_DEFAULT.read_bytes()
        with self.assertRaises(encryption.EncryptionError):
            encryption.accept_uploaded(cert_bytes, key_bytes)

    def test_accept_uploaded_accepts_matching_pair(self) -> None:
        encryption.generate_self_signed("upload.example.com", days=30)
        cert_bytes = encryption.CERT_PATH_DEFAULT.read_bytes()
        key_bytes = encryption.KEY_PATH_DEFAULT.read_bytes()
        encryption.accept_uploaded(cert_bytes, key_bytes)
        self.assertTrue(encryption.validate_cert_key_match(encryption.UPLOADED_CERT_PATH, encryption.UPLOADED_KEY_PATH))

    def test_pending_upload_roundtrip(self) -> None:
        encryption.generate_self_signed("staged.example.com", days=30)
        encryption.request_cert_upload(encryption.CERT_PATH_DEFAULT.read_bytes(), encryption.KEY_PATH_DEFAULT.read_bytes())
        self.assertTrue(encryption.accept_pending_upload())
        self.assertFalse(encryption.PENDING_UPLOAD_CERT.exists())
        self.assertTrue(encryption.UPLOADED_CERT_PATH.exists())
        self.assertFalse(encryption.accept_pending_upload())

    def test_resolve_active_cert_paths_by_mode(self) -> None:
        self.assertEqual(encryption.resolve_active_cert_paths({"cert_mode": "self_signed"}), (encryption.CERT_PATH_DEFAULT, encryption.KEY_PATH_DEFAULT))
        self.assertEqual(encryption.resolve_active_cert_paths({"cert_mode": "uploaded"}), (encryption.UPLOADED_CERT_PATH, encryption.UPLOADED_KEY_PATH))
        self.assertEqual(encryption.resolve_active_cert_paths({"cert_mode": "existing_path", "cert_path": "/x.crt", "key_path": "/x.key"}), (Path("/x.crt"), Path("/x.key")))

    def test_cert_info_expiring_soon_flag(self) -> None:
        encryption.generate_self_signed("soon.example.com", days=10)
        info = encryption.cert_info(encryption.CERT_PATH_DEFAULT)
        self.assertTrue(info["expiring_soon"])
        self.assertFalse(info["expired"])

    def test_cert_info_missing_file(self) -> None:
        info = encryption.cert_info(encryption.CERT_DIR / "does-not-exist.crt")
        self.assertFalse(info["available"])

    def test_cert_info_unreadable_path_degrades_instead_of_raising(self) -> None:
        """cert_mode "existing_path" lets an admin point at an arbitrary
        filesystem path; cert_info() is also called directly from the
        unprivileged web process (encryption_context()), which is not
        guaranteed read access to it -- a PermissionError here must not
        propagate as an unhandled exception (found live: it 500'd the
        encryption page's own failure-report render)."""
        with mock.patch("pathlib.Path.exists", side_effect=PermissionError("denied")):
            info = encryption.cert_info(Path("/root/unreadable-by-web-process.crt"))
        self.assertFalse(info["available"])

    # -- dnsdist.conf migration -------------------------------------------

    def test_ensure_dnsdist_conf_parameterized_preserves_secrets(self) -> None:
        template = self.tmp / "template.conf"
        template.write_text(
            '-- Encryption Settings (managed by app/encryption.py)\n'
            'local listenIPv4 = os.getenv("ALDERPOINTDNS_DNS_LISTEN_IPV4") or "0.0.0.0"\n'
            'setKey("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER")\n'
            'setWebserverConfig({password="ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", apiKey="ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER"})\n'
        )
        encryption.DNSDIST_CONF.write_text(
            'setKey("realconsolekey")\n'
            'setWebserverConfig({password="realpassword", apiKey="realapikey"})\n'
        )
        changed = encryption.ensure_dnsdist_conf_parameterized(template)
        self.assertTrue(changed)
        new_content = encryption.DNSDIST_CONF.read_text()
        self.assertIn('setKey("realconsolekey")', new_content)
        self.assertIn('password="realpassword"', new_content)
        self.assertIn('apiKey="realapikey"', new_content)
        self.assertIn("ALDERPOINTDNS_DNS_LISTEN_IPV4", new_content)
        self.assertIn(encryption.MIGRATION_MARKER, new_content)
        # Idempotent: second call is a no-op.
        self.assertFalse(encryption.ensure_dnsdist_conf_parameterized(template))

    def test_parameterized_conf_without_listen_vars_refreshes_from_template(self) -> None:
        template = self.tmp / "template.conf"
        template.write_text(
            '-- Encryption Settings (managed by app/encryption.py)\n'
            'local listenIPv4 = os.getenv("ALDERPOINTDNS_DNS_LISTEN_IPV4") or "0.0.0.0"\n'
            'setKey("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER")\n'
            'setWebserverConfig({password="ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", apiKey="ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER"})\n'
        )
        encryption.DNSDIST_CONF.write_text(
            '-- Encryption Settings (managed by app/encryption.py)\n'
            'setKey("realconsolekey")\n'
            'setWebserverConfig({password="realpassword", apiKey="realapikey"})\n'
        )
        self.assertTrue(encryption.ensure_dnsdist_conf_parameterized(template))
        self.assertIn("ALDERPOINTDNS_DNS_LISTEN_IPV4", encryption.DNSDIST_CONF.read_text())

    def test_ensure_dnsdist_conf_parameterized_requires_existing_secrets(self) -> None:
        template = self.tmp / "template.conf"
        template.write_text('setKey("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER")\n')
        encryption.DNSDIST_CONF.write_text("-- no secrets here\n")
        with self.assertRaises(encryption.EncryptionError):
            encryption.ensure_dnsdist_conf_parameterized(template)

    # -- env override rendering -------------------------------------------

    def test_render_env_override_reflects_toggles_and_paths(self) -> None:
        cfg = dict(encryption.DEFAULTS)
        cfg.update(doh_enabled="1", dot_enabled="0", doq_enabled="1", doh3_enabled="0", dnscrypt_enabled="0")
        text = encryption.render_env_override(cfg)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_PLAIN=1", text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_LISTEN_IPV4=0.0.0.0", text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_LISTEN_IPV6=::", text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_DOH=1", text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_DOT=0", text)
        # Not cfg['cert_path'] (DEFAULTS' own baked-in value): cert_mode
        # "self_signed" here means the *actually* active cert is whatever
        # resolve_active_cert_paths() resolves it to, which is what must end
        # up in the rendered env override -- see the next test for why this
        # distinction matters.
        self.assertIn(f"Environment=ALDERPOINTDNS_TLS_CERT={encryption.CERT_PATH_DEFAULT}", text)

    def test_render_env_override_ignores_stale_existing_path_fields_in_other_modes(self) -> None:
        """Regression, found live: cert_path/key_path are only meaningful
        while cert_mode == "existing_path" -- switching *back* to
        self_signed/local_ca/uploaded does not clear those two DB fields,
        so a naive `cfg['cert_path']` read here would keep pointing dnsdist
        at a stale, unrelated filesystem path from a previous existing-path
        configuration (observed live: dnsdist refused to start with "Fatal
        error: ... trying to load the TLS server certificate file" for a
        path that hadn't been in use for several deployments)."""
        cfg = dict(encryption.DEFAULTS)
        cfg.update(cert_mode="self_signed", cert_path="/no/such/stale/existing-path.crt", key_path="/no/such/stale/existing-path.key")
        text = encryption.render_env_override(cfg)
        self.assertNotIn("/no/such/stale/existing-path.crt", text)
        self.assertIn(f"Environment=ALDERPOINTDNS_TLS_CERT={encryption.CERT_PATH_DEFAULT}", text)

    # -- deploy staged/validate/backup/atomic/health/rollback -------------

    def _prepare_template_and_conf(self) -> Path:
        template = self.tmp / "template.conf"
        template.write_text(
            '-- Encryption Settings (managed by app/encryption.py)\n'
            'local listenIPv4 = os.getenv("ALDERPOINTDNS_DNS_LISTEN_IPV4") or "0.0.0.0"\n'
            'setKey("ALDERPOINTDNS_CONSOLE_KEY_PLACEHOLDER")\n'
            'setWebserverConfig({password="ALDERPOINTDNS_WEBSERVER_PASSWORD_PLACEHOLDER", apiKey="ALDERPOINTDNS_WEBSERVER_API_KEY_PLACEHOLDER"})\n'
        )
        encryption.DNSDIST_CONF.write_text(
            'setKey("realconsolekey")\n'
            'setWebserverConfig({password="realpassword", apiKey="realapikey"})\n'
        )
        return template

    def test_deploy_encryption_missing_certificate_fails_fast_without_writing_env(self) -> None:
        template = self._prepare_template_and_conf()
        with self.assertRaises(encryption.EncryptionError):
            with mock.patch.object(encryption, "run", self.fake_run_ok):
                encryption.deploy_encryption(template_path=template)
        self.assertFalse(encryption.DNSDIST_ENV_OVERRIDE.exists())

    def test_deploy_encryption_success_with_protocol_tests(self) -> None:
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "ok"}):
            did = encryption.deploy_encryption(template_path=template)
        self.assertGreater(did, 0)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "deployed")
        self.assertTrue(encryption.DNSDIST_ENV_OVERRIDE.exists())

    def test_deploy_encryption_rolls_back_on_failed_protocol_test(self) -> None:
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "ok"}):
            encryption.deploy_encryption(template_path=template)
        good_env = encryption.DNSDIST_ENV_OVERRIDE.read_text()

        encryption.update_settings({**encryption.settings(), "doh_port": "8443"})
        with self.assertRaises(RuntimeError):
            with mock.patch.object(encryption, "run", self.fake_run_ok), \
                 mock.patch.object(encryption, "_wait_active", return_value=True), \
                 mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "failed (timeout)"}):
                encryption.deploy_encryption(template_path=template)
        self.assertEqual(encryption.DNSDIST_ENV_OVERRIDE.read_text(), good_env)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "rolled_back")

    def test_deploy_encryption_dnscrypt_failure_does_not_block_other_protocols(self) -> None:
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        encryption.update_settings({**encryption.settings(), "dnscrypt_enabled": "1"})
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "issue_dnscrypt_certificate", side_effect=RuntimeError("no key material")), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "ok"}):
            encryption.deploy_encryption(template_path=template)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "deployed")
        self.assertIn("DNSCrypt certificate generation failed", deployment["message"])

    def test_deploy_encryption_preserves_previous_self_signed_cert_on_deploy_failure(self) -> None:
        """A regenerated self-signed cert that dnsdist can't actually serve
        (protocol test failure) must not leave the last known-good cert/key
        clobbered -- see deploy_encryption()'s cert_backup/cert_backup_target
        handling, which mirrors its existing env_backup rollback."""
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok"}):
            encryption.deploy_encryption(template_path=template)
        good_cert = encryption.CERT_PATH_DEFAULT.read_bytes()
        good_key = encryption.KEY_PATH_DEFAULT.read_bytes()

        encryption.request_cert_action("generate_self_signed")
        with self.assertRaises(RuntimeError):
            with mock.patch.object(encryption, "run", self.fake_run_ok), \
                 mock.patch.object(encryption, "_wait_active", return_value=True), \
                 mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "failed (timeout)"}):
                encryption.deploy_encryption(template_path=template)
        # The regeneration itself already ran and overwrote the files on disk
        # (that part of the bug is inherent to how openssl req works -- it
        # can't validate a live TLS handshake before writing); what matters
        # is that the failed deployment's rollback restores the previous,
        # actually-working material rather than leaving the new one in place.
        self.assertEqual(encryption.CERT_PATH_DEFAULT.read_bytes(), good_cert)
        self.assertEqual(encryption.KEY_PATH_DEFAULT.read_bytes(), good_key)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "rolled_back")

    def test_deploy_encryption_preserves_previous_uploaded_cert_on_deploy_failure(self) -> None:
        """Same as above for an uploaded certificate/key pair, and also
        proves the staged pending-upload files are consumed (not left
        behind) even though the deployment ultimately fails."""
        template = self._prepare_template_and_conf()
        # Two independently generated (but each internally matching)
        # cert/key pairs to upload in turn.
        with mock.patch.object(encryption, "run", self.fake_run_ok):
            encryption.generate_self_signed("cert-a.example.com", days=30)
        cert_a = encryption.CERT_PATH_DEFAULT.read_bytes()
        key_a = encryption.KEY_PATH_DEFAULT.read_bytes()
        with mock.patch.object(encryption, "run", self.fake_run_ok):
            encryption.generate_self_signed("cert-b.example.com", days=30)
        cert_b = encryption.CERT_PATH_DEFAULT.read_bytes()
        key_b = encryption.KEY_PATH_DEFAULT.read_bytes()

        # A successful upload+deploy of pair A establishes it as the active
        # uploaded certificate.
        encryption.update_settings({**encryption.settings(), "cert_mode": "uploaded"})
        encryption.request_cert_upload(cert_a, key_a)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok"}):
            encryption.deploy_encryption(template_path=template)
        self.assertEqual(encryption.UPLOADED_CERT_PATH.read_bytes(), cert_a)

        # Uploading pair B, whose deployment then fails its protocol test,
        # must not leave pair B in place over the last known-good pair A.
        encryption.request_cert_upload(cert_b, key_b)
        self.assertTrue(encryption.PENDING_UPLOAD_CERT.exists())
        with self.assertRaises(RuntimeError):
            with mock.patch.object(encryption, "run", self.fake_run_ok), \
                 mock.patch.object(encryption, "_wait_active", return_value=True), \
                 mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "failed (timeout)"}):
                encryption.deploy_encryption(template_path=template)

        self.assertFalse(encryption.PENDING_UPLOAD_CERT.exists())
        self.assertFalse(encryption.PENDING_UPLOAD_KEY.exists())
        self.assertEqual(encryption.UPLOADED_CERT_PATH.read_bytes(), cert_a)
        self.assertEqual(encryption.UPLOADED_KEY_PATH.read_bytes(), key_a)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "rolled_back")

    # -- dnsdist capability detection --------------------------------------

    def test_dnsdist_capabilities_detects_stock_debian13_build(self) -> None:
        stock_debian13_version = (
            "dnsdist 1.9.15 (Lua 5.1.4 [LuaJIT])\n"
            "Enabled features: AF_XDP cdb dns-over-tls(openssl) "
            "dns-over-https(nghttp2) dnscrypt ebpf fstrm ipcipher libsodium "
            "lmdb protobuf re2 recvmmsg/sendmmsg snmp systemd\n"
        )
        with mock.patch.object(
            encryption, "run",
            return_value=subprocess.CompletedProcess(["dnsdist", "--version"], 0, stock_debian13_version),
        ):
            caps = encryption.dnsdist_capabilities()
        self.assertEqual(
            caps,
            {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True},
        )

    def test_dnsdist_capabilities_detects_quic_capable_build(self) -> None:
        with mock.patch.object(
            encryption, "run",
            return_value=subprocess.CompletedProcess(["dnsdist", "--version"], 0, self.FAKE_DNSDIST_VERSION_FULL),
        ):
            caps = encryption.dnsdist_capabilities()
        self.assertTrue(caps["doq"])
        self.assertTrue(caps["doh3"])

    def test_dnsdist_capabilities_fails_closed_when_dnsdist_missing(self) -> None:
        with mock.patch.object(encryption, "run", side_effect=FileNotFoundError()):
            caps = encryption.dnsdist_capabilities()
        self.assertEqual(caps, {"doh": False, "dot": False, "doq": False, "doh3": False, "dnscrypt": False})

    def test_enforce_capabilities_forces_unsupported_flags_off(self) -> None:
        stock_caps = {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True}
        values = {"doh_enabled": "1", "dot_enabled": "1", "doq_enabled": "1", "doh3_enabled": "1", "dnscrypt_enabled": "1"}
        out, warnings_list = encryption.enforce_capabilities(values, caps=stock_caps)
        self.assertEqual(out["doq_enabled"], "0")
        self.assertEqual(out["doh3_enabled"], "0")
        self.assertEqual(out["doh_enabled"], "1")
        self.assertEqual(out["dot_enabled"], "1")
        self.assertEqual(out["dnscrypt_enabled"], "1")
        self.assertEqual(len(warnings_list), 2)
        self.assertTrue(any("DoQ was disabled" in w and "not supported by the installed dnsdist build" in w for w in warnings_list))
        self.assertTrue(any("DoH3 was disabled" in w for w in warnings_list))

    def test_enforce_capabilities_leaves_already_disabled_flags_alone(self) -> None:
        stock_caps = {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True}
        values = {"doh_enabled": "0", "dot_enabled": "0", "doq_enabled": "0", "doh3_enabled": "0", "dnscrypt_enabled": "0"}
        out, warnings_list = encryption.enforce_capabilities(values, caps=stock_caps)
        self.assertEqual(out, values)
        self.assertEqual(warnings_list, [])

    def test_deploy_encryption_disables_unsupported_protocols_without_failing_deployment(self) -> None:
        # Simulates Debian 13's own archive dnsdist build: DoH/DoT/DNSCrypt
        # are supported, DoQ/DoH3 are not. A saved configuration that
        # (incorrectly) requests DoQ/DoH3 -- e.g. restored from a backup
        # taken on a QUIC-capable install -- must not crash-loop dnsdist or
        # fail the whole deployment; it must deploy everything that *is*
        # supported and report the rest as skipped.
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        encryption.update_settings({**encryption.settings(), "doh_enabled": "1", "doq_enabled": "1", "doh3_enabled": "1"})
        stock_caps = {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True}
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "dnsdist_capabilities", return_value=stock_caps), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok", "doh": "ok"}):
            encryption.deploy_encryption(template_path=template)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "deployed")
        self.assertIn("DoQ was disabled for this deployment: not supported by the installed dnsdist build", deployment["message"])
        self.assertIn("DoH3 was disabled for this deployment: not supported by the installed dnsdist build", deployment["message"])
        env_text = encryption.DNSDIST_ENV_OVERRIDE.read_text()
        self.assertIn("Environment=ALDERPOINTDNS_DNS_DOQ=0", env_text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_DOH3=0", env_text)
        self.assertIn("Environment=ALDERPOINTDNS_DNS_DOH=1", env_text)

    def test_deploy_encryption_unchanged_when_nothing_differs(self) -> None:
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok"}):
            encryption.deploy_encryption(template_path=template)
            encryption.deploy_encryption(template_path=template)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "unchanged")

    def test_deploy_encryption_cert_regeneration_forces_redeploy_even_if_env_unchanged(self) -> None:
        template = self._prepare_template_and_conf()
        encryption.generate_self_signed("dns.example.com", days=30)
        with mock.patch.object(encryption, "run", self.fake_run_ok), \
             mock.patch.object(encryption, "_wait_active", return_value=True), \
             mock.patch.object(encryption, "test_protocols", return_value={"plain": "ok"}):
            encryption.deploy_encryption(template_path=template)
            encryption.request_cert_action("generate_self_signed")
            encryption.deploy_encryption(template_path=template)
        deployment = encryption.last_deployment()
        self.assertEqual(deployment["status"], "deployed")

    # -- connection info and Apple profiles --------------------------------

    def test_connection_info_only_lists_enabled_protocols(self) -> None:
        cfg = dict(encryption.DEFAULTS)
        cfg.update(doh_enabled="1", dot_enabled="0", doq_enabled="0", doh3_enabled="0", dnscrypt_enabled="0", bootstrap_ip="192.168.1.101")
        info = encryption.connection_info(cfg)
        self.assertIn("DoH", info)
        self.assertNotIn("DoT", info)

    def test_apple_mobileconfig_doh_contains_server_url(self) -> None:
        cfg = dict(encryption.DEFAULTS)
        cfg["server_hostname"] = "dns.example.com"
        data = encryption.apple_mobileconfig(cfg, "doh")
        self.assertIn(b"com.apple.dnsSettings.managed", data)
        self.assertIn(b"dns.example.com", data)
        self.assertIn(b"HTTPS", data)

    def test_apple_mobileconfig_dot_uses_tls_protocol(self) -> None:
        cfg = dict(encryption.DEFAULTS)
        cfg["server_hostname"] = "dns.example.com"
        cfg["bootstrap_ip"] = "192.168.1.101"
        data = encryption.apple_mobileconfig(cfg, "dot")
        self.assertIn(b"TLS", data)
        self.assertIn(b"192.168.1.101", data)

    def test_apple_mobileconfig_rejects_unknown_protocol(self) -> None:
        with self.assertRaises(encryption.EncryptionError):
            encryption.apple_mobileconfig(dict(encryption.DEFAULTS), "doq")


class EncryptionWebRouteTests(unittest.TestCase):
    """Exercises the /encryption page and settings POST through the real
    FastAPI app, against a stock-Debian-13-like capability set (DoH/DoT/
    DNSCrypt supported, DoQ/DoH3 not) -- proving the disabled state is
    both rendered and enforced server-side, not just a template guess."""

    STOCK_CAPS = {"doh": True, "dot": True, "doq": False, "doh3": False, "dnscrypt": True}

    def setUp(self) -> None:
        import sqlite3
        import shutil as shutil_mod

        from fastapi.templating import Jinja2Templates
        from fastapi.testclient import TestClient

        from app import alderpointdns_compiler as compiler
        from app import replication, webapp

        self.shutil = shutil_mod
        self.tmp = Path(tempfile.mkdtemp(prefix="alderpointdns-encryption-web-test-"))
        self.webapp = webapp
        self.old = {
            "e_DB_PATH": encryption.DB_PATH,
            "e_CERT_DIR": encryption.CERT_DIR,
            "e_CERT_PATH_DEFAULT": encryption.CERT_PATH_DEFAULT,
            "e_KEY_PATH_DEFAULT": encryption.KEY_PATH_DEFAULT,
            "e_CA_CERT_PATH": encryption.CA_CERT_PATH,
            "e_CA_KEY_PATH": encryption.CA_KEY_PATH,
            "e_CA_SERIAL_PATH": encryption.CA_SERIAL_PATH,
            "e_UPLOADED_CERT_PATH": encryption.UPLOADED_CERT_PATH,
            "e_UPLOADED_KEY_PATH": encryption.UPLOADED_KEY_PATH,
            "e_STAGING_DIR": encryption.STAGING_DIR,
            "e_PENDING_UPLOAD_CERT": encryption.PENDING_UPLOAD_CERT,
            "e_PENDING_UPLOAD_KEY": encryption.PENDING_UPLOAD_KEY,
            "w_DB_PATH": webapp.DB_PATH,
            "c_DB_PATH": compiler.DB_PATH,
        }
        db_path = self.tmp / "alderpointdns.db"
        encryption.DB_PATH = db_path
        encryption.CERT_DIR = self.tmp / "certs"
        encryption.CERT_DIR.mkdir(parents=True)
        # CERT_PATH_DEFAULT/KEY_PATH_DEFAULT/CA_*/UPLOADED_* are each bound
        # to a concrete Path object at module-import time (CERT_DIR / "...")
        # -- reassigning encryption.CERT_DIR above does NOT retroactively
        # repoint them. Any test in this class that goes on to actually
        # write certificate material (not just mock encryption_deploy_apply
        # and never call the real deploy/generate functions) must have
        # these repointed too, or it silently writes through to the real
        # system paths under /etc/alderpointdns/certs -- found live, the
        # hard way, when an earlier version of this file's certificate
        # upload test clobbered the actual dev appliance's active TLS cert.
        encryption.CERT_PATH_DEFAULT = encryption.CERT_DIR / "alderpointdns-lab.crt"
        encryption.KEY_PATH_DEFAULT = encryption.CERT_DIR / "alderpointdns-lab.key"
        encryption.CA_CERT_PATH = encryption.CERT_DIR / "alderpointdns-ca.crt"
        encryption.CA_KEY_PATH = encryption.CERT_DIR / "alderpointdns-ca.key"
        encryption.CA_SERIAL_PATH = encryption.CERT_DIR / "alderpointdns-ca.srl"
        encryption.UPLOADED_CERT_PATH = encryption.CERT_DIR / "alderpointdns-uploaded.crt"
        encryption.UPLOADED_KEY_PATH = encryption.CERT_DIR / "alderpointdns-uploaded.key"
        encryption.STAGING_DIR = self.tmp / "staging"
        encryption.STAGING_DIR.mkdir(parents=True)
        encryption.PENDING_UPLOAD_CERT = encryption.STAGING_DIR / "pending-cert-upload.crt"
        encryption.PENDING_UPLOAD_KEY = encryption.STAGING_DIR / "pending-cert-upload.key"
        webapp.DB_PATH = db_path
        compiler.DB_PATH = db_path
        encryption.init_db()
        conn = sqlite3.connect(db_path)
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)"
        )
        conn.execute("INSERT INTO admins(username, password_hash, created_at) VALUES ('admin', 'x', 'now')")
        conn.execute(
            "CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, admin_id INTEGER, created_at TEXT NOT NULL, last_seen_at TEXT NOT NULL, ip TEXT, user_agent TEXT, csrf TEXT NOT NULL)"
        )
        conn.execute(
            "CREATE TABLE IF NOT EXISTS admin_audit_log (id INTEGER PRIMARY KEY, at TEXT NOT NULL, admin_id INTEGER, username TEXT NOT NULL DEFAULT '', action TEXT NOT NULL, success INTEGER NOT NULL, ip TEXT, detail TEXT NOT NULL DEFAULT '')"
        )
        self.csrf = "test-csrf-token"
        session_id = "test-session-id"
        conn.execute(
            "INSERT INTO sessions(id, admin_id, created_at, last_seen_at, ip, user_agent, csrf) VALUES (?, 1, 'now', 'now', '', '', ?)",
            (session_id, self.csrf),
        )
        conn.commit()
        conn.close()

        self.patches = [
            mock.patch.object(webapp, "encryption_deploy_apply", lambda: (0, "ok")),
            mock.patch.object(replication, "autostart", lambda: None),
            mock.patch.object(encryption, "dnsdist_capabilities", return_value=dict(self.STOCK_CAPS)),
            # Render the templates checked out with this code, not whatever
            # happens to be installed at the live /opt/alderpointdns path.
            mock.patch.object(webapp, "TEMPLATES", Jinja2Templates(directory=str(ROOT / "web" / "templates"))),
        ]
        for patcher in self.patches:
            patcher.start()
        self.client = TestClient(webapp.app)
        self.client.cookies.set(
            "alderpointdns_session",
            webapp.serializer.dumps({"sid": session_id}),
        )

    def tearDown(self) -> None:
        for patcher in reversed(self.patches):
            patcher.stop()
        self.webapp.DB_PATH = self.old["w_DB_PATH"]
        from app import alderpointdns_compiler as compiler  # noqa: PLC0415

        compiler.DB_PATH = self.old["c_DB_PATH"]
        for key in (
            "DB_PATH", "CERT_DIR", "CERT_PATH_DEFAULT", "KEY_PATH_DEFAULT",
            "CA_CERT_PATH", "CA_KEY_PATH", "CA_SERIAL_PATH",
            "UPLOADED_CERT_PATH", "UPLOADED_KEY_PATH",
            "STAGING_DIR", "PENDING_UPLOAD_CERT", "PENDING_UPLOAD_KEY",
        ):
            setattr(encryption, key, self.old[f"e_{key}"])
        self.shutil.rmtree(self.tmp, ignore_errors=True)

    def test_encryption_page_renders_doq_and_doh3_disabled_when_unsupported(self) -> None:
        response = self.client.get("/encryption")
        self.assertEqual(response.status_code, 200)
        self.assertRegex(response.text, r'name="doq_enabled"[^>]*disabled')
        self.assertRegex(response.text, r'name="doh3_enabled"[^>]*disabled')
        self.assertNotRegex(response.text, r'name="doh_enabled"[^>]*disabled')
        self.assertNotRegex(response.text, r'name="dot_enabled"[^>]*disabled')
        self.assertIn("Unsupported by installed dnsdist", response.text)

    def test_forged_post_cannot_persist_unsupported_protocols_as_enabled(self) -> None:
        response = self.client.post(
            "/encryption/settings",
            data={
                "csrf": self.csrf,
                "server_hostname": "dns.example.com",
                "bootstrap_ip": "192.168.1.50",
                "listen_ipv4": "0.0.0.0",
                "listen_ipv6": "::",
                "doh_enabled": "1",
                "dot_enabled": "1",
                # Forged: these controls are rendered disabled in the UI,
                # but nothing stops a raw POST from setting them -- the
                # server must still refuse to persist them as enabled.
                "doq_enabled": "1",
                "doh3_enabled": "1",
                "dnscrypt_enabled": "0",
                "doh_path": "/dns-query",
                "doh_port": "443",
                "doh3_port": "443",
                "dot_port": "853",
                "doq_port": "853",
                "dnscrypt_port": "5443",
                "dnscrypt_provider": "2.dnscrypt-cert.example",
            },
            follow_redirects=False,
        )
        self.assertEqual(response.status_code, 303)
        saved = encryption.settings()
        self.assertEqual(saved["doq_enabled"], "0")
        self.assertEqual(saved["doh3_enabled"], "0")
        self.assertEqual(saved["doh_enabled"], "1")
        self.assertEqual(saved["dot_enabled"], "1")
        # And the re-rendered page must still show them unchecked and disabled.
        page = self.client.get("/encryption")
        self.assertRegex(page.text, r'name="doq_enabled"[^>]*disabled')
        self.assertNotRegex(page.text, r'name="doq_enabled"[^>]*checked')
        self.assertRegex(page.text, r'name="doh3_enabled"[^>]*disabled')
        self.assertNotRegex(page.text, r'name="doh3_enabled"[^>]*checked')

    # -- deployment false-success regression (encryption_deploy_apply()'s
    # (code, output) return value being ignored by every /encryption/*
    # mutation route) -----------------------------------------------------

    def _audit_rows(self, action: str) -> list:
        import sqlite3 as sqlite3_mod

        conn = sqlite3_mod.connect(self.webapp.DB_PATH)
        try:
            return conn.execute(
                "SELECT success, detail FROM admin_audit_log WHERE action=? ORDER BY id", (action,)
            ).fetchall()
        finally:
            conn.close()

    def test_self_signed_deploy_success_redirects_and_audits_success(self) -> None:
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (0, "deployed with protocols: {'plain': 'ok'}")):
            response = self.client.post(
                "/encryption/certificate/self-signed",
                data={"csrf": self.csrf},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        rows = self._audit_rows("encryption_cert_self_signed")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 1)

    def test_self_signed_deploy_failure_does_not_redirect_or_claim_success(self) -> None:
        """The core regression: encryption_deploy_apply() returning a
        non-zero code must never still redirect to /encryption as if the
        deployment had succeeded."""
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, "dnsdist did not become active after restart")):
            response = self.client.post(
                "/encryption/certificate/self-signed",
                data={"csrf": self.csrf},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertNotEqual(response.status_code, 303)
        self.assertIn("deploying it to dnsdist failed", response.text)
        self.assertIn("dnsdist did not become active after restart", response.text)
        self.assertNotIn("alert success", response.text)
        rows = self._audit_rows("encryption_cert_self_signed")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 0)
        self.assertIn("dnsdist did not become active after restart", rows[0][1])

    def test_deploy_failure_output_with_markup_is_escaped_not_executed(self) -> None:
        malicious_output = "<script>alert(document.cookie)</script>"
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, malicious_output)):
            response = self.client.post(
                "/encryption/certificate/self-signed",
                data={"csrf": self.csrf},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertNotIn("<script>alert(document.cookie)</script>", response.text)
        self.assertIn("&lt;script&gt;", response.text)

    def test_deploy_failure_multiline_output_handled_safely(self) -> None:
        multiline_output = "dnsdist --check-config failed:\nsyntax error near 'addDOHLocal'\nline 42"
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, multiline_output)):
            response = self.client.post(
                "/encryption/certificate/self-signed",
                data={"csrf": self.csrf},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("syntax error near", response.text)
        self.assertIn("line 42", response.text)

    def test_certificate_upload_deploy_failure_does_not_report_success(self) -> None:
        """/encryption/certificate/upload specifically -- the route named in
        the original bug report -- must share the same fix as every other
        encryption mutation route."""
        cert, key = self._matching_self_signed_pair()
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, "protocol test failed for: doh")):
            response = self.client.post(
                "/encryption/certificate/upload",
                data={"csrf": self.csrf},
                files={
                    "cert_file": ("uploaded.crt", cert, "application/x-pem-file"),
                    "key_file": ("uploaded.key", key, "application/x-pem-file"),
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("deploying it to dnsdist failed", response.text)
        rows = self._audit_rows("encryption_cert_uploaded")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 0)

    def test_certificate_upload_deploy_success_redirects(self) -> None:
        cert, key = self._matching_self_signed_pair()
        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (0, "deployed with protocols: {'plain': 'ok'}")):
            response = self.client.post(
                "/encryption/certificate/upload",
                data={"csrf": self.csrf},
                files={
                    "cert_file": ("uploaded.crt", cert, "application/x-pem-file"),
                    "key_file": ("uploaded.key", key, "application/x-pem-file"),
                },
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 303)
        rows = self._audit_rows("encryption_cert_uploaded")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], 1)

    def _matching_self_signed_pair(self) -> tuple[bytes, bytes]:
        with mock.patch.object(encryption, "run", subprocess.run):
            encryption.generate_self_signed("upload-test.example.com", days=1)
        return encryption.CERT_PATH_DEFAULT.read_bytes(), encryption.KEY_PATH_DEFAULT.read_bytes()

    def test_all_encryption_deploy_routes_surface_failure_not_success(self) -> None:
        """Every caller of encryption_deploy_apply() (Step 11: settings,
        self-signed, local-ca, upload, existing-path) must handle a
        non-zero return code the same way -- not just the one route named
        in the original bug report."""
        cert, key = self._matching_self_signed_pair()
        routes = [
            ("/encryption/certificate/self-signed", {"csrf": self.csrf}, None),
            ("/encryption/certificate/local-ca", {"csrf": self.csrf}, None),
            (
                "/encryption/certificate/existing-path",
                {"csrf": self.csrf, "cert_path": str(encryption.CERT_PATH_DEFAULT), "key_path": str(encryption.KEY_PATH_DEFAULT)},
                None,
            ),
            (
                "/encryption/certificate/upload",
                {"csrf": self.csrf},
                {"cert_file": ("uploaded.crt", cert, "application/x-pem-file"), "key_file": ("uploaded.key", key, "application/x-pem-file")},
            ),
            (
                "/encryption/settings",
                {
                    "csrf": self.csrf,
                    "server_hostname": "dns.example.com",
                    "bootstrap_ip": "192.168.1.50",
                    "listen_ipv4": "0.0.0.0",
                    "listen_ipv6": "::",
                    "doh_enabled": "1",
                    "dot_enabled": "1",
                    "doq_enabled": "0",
                    "doh3_enabled": "0",
                    "dnscrypt_enabled": "0",
                    "doh_path": "/dns-query",
                    "doh_port": "443",
                    "doh3_port": "443",
                    "dot_port": "853",
                    "doq_port": "853",
                    "dnscrypt_port": "5443",
                    "dnscrypt_provider": "2.dnscrypt-cert.example",
                },
                None,
            ),
        ]
        for path, data, files in routes:
            with self.subTest(path=path):
                with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, f"simulated failure for {path}")):
                    response = self.client.post(path, data=data, files=files, follow_redirects=False)
                self.assertEqual(response.status_code, 400, f"{path} did not surface deploy failure")
                self.assertIn("deploying it to dnsdist failed", response.text)

    def test_existing_path_deploy_failure_with_unreadable_cert_does_not_500(self) -> None:
        """Live-found regression: an existing-path certificate the
        unprivileged web process can't stat (e.g. root-only material
        outside /etc/alderpointdns/certs) crashed the *failure* re-render
        itself with an unhandled PermissionError from cert_info(), turning
        a clean 400 error page into a raw 500 the moment this bug's fix
        started actually reaching that failure path."""
        import pathlib

        real_exists = pathlib.Path.exists

        def flaky_exists(self, *a, **kw):
            if str(self) == "/root/unreadable.crt":
                raise PermissionError("denied")
            return real_exists(self, *a, **kw)

        with mock.patch.object(self.webapp, "encryption_deploy_apply", lambda: (1, "certificate and key do not match")), \
             mock.patch.object(pathlib.Path, "exists", flaky_exists):
            response = self.client.post(
                "/encryption/certificate/existing-path",
                data={"csrf": self.csrf, "cert_path": "/root/unreadable.crt", "key_path": "/root/unreadable.key"},
                follow_redirects=False,
            )
        self.assertEqual(response.status_code, 400)
        self.assertIn("deploying it to dnsdist failed", response.text)

    def test_encryption_deploy_apply_raising_is_not_reported_as_success(self) -> None:
        """encryption_deploy_apply() itself never raises (run() always
        returns a (code, output) tuple), but if a caller further down the
        stack ever did raise, it must propagate as a real error rather than
        the route silently proceeding to its success redirect -- it must
        never be swallowed by a bare `except Exception` between the deploy
        call and the redirect."""
        with mock.patch.object(self.webapp, "encryption_deploy_apply", side_effect=RuntimeError("unexpected deploy helper crash")):
            with self.assertRaises(RuntimeError):
                self.client.post(
                    "/encryption/certificate/self-signed",
                    data={"csrf": self.csrf},
                    follow_redirects=False,
                )


if __name__ == "__main__":
    unittest.main()
