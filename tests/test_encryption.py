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

    def fake_run_ok(self, command: list[str], check: bool = True, env=None, input_text=None) -> subprocess.CompletedProcess[str]:
        # Only fake the dnsdist/systemctl side effects that would otherwise
        # touch the live host; let openssl/named-style commands run for real
        # so certificate generation inside deploy_encryption stays honest.
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
        self.assertIn(f"Environment=ALDERPOINTDNS_TLS_CERT={cfg['cert_path']}", text)

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


if __name__ == "__main__":
    unittest.main()
