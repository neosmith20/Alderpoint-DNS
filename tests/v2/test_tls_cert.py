"""Workstream 4B: real X.509 self-signed generation + validate/stage/
promote semantics for the management-plane TLS bootstrap."""

import datetime

import pytest

from app.v2.tls_cert import (
    TlsCertMismatchError,
    TlsCertValidationError,
    ensure_bootstrap_cert,
    generate_self_signed,
    load_active_cert_info,
    stage_validate_promote,
    validate_cert_key_pair,
)


class TestGeneration:
    def test_generates_real_ec_p256_cert(self):
        cert_pem, key_pem = generate_self_signed()
        info = validate_cert_key_pair(cert_pem, key_pem)
        assert "Alderpoint DNS V2 Local" in info.subject
        assert info.is_self_signed

    def test_san_includes_requested_hostnames_and_ips(self):
        cert_pem, key_pem = generate_self_signed(hostnames=("example.local",), ip_addresses=("192.0.2.5",))
        info = validate_cert_key_pair(cert_pem, key_pem)
        assert "example.local" in info.san
        assert "192.0.2.5" in info.san

    def test_validity_window_is_bounded_not_forever(self):
        cert_pem, key_pem = generate_self_signed()
        info = validate_cert_key_pair(cert_pem, key_pem)
        not_after = datetime.datetime.fromisoformat(info.not_valid_after)
        span = not_after - datetime.datetime.now(datetime.timezone.utc)
        assert span.days < 400  # bounded, not a 10-year cert
        assert span.days > 300


class TestPairValidation:
    def test_mismatched_key_rejected(self):
        cert1, _ = generate_self_signed()
        _, key2 = generate_self_signed()
        with pytest.raises(TlsCertMismatchError):
            validate_cert_key_pair(cert1, key2)

    def test_garbage_cert_rejected(self):
        _, key = generate_self_signed()
        with pytest.raises(TlsCertValidationError):
            validate_cert_key_pair(b"not a cert", key)

    def test_garbage_key_rejected(self):
        cert, _ = generate_self_signed()
        with pytest.raises(TlsCertValidationError):
            validate_cert_key_pair(cert, b"not a key")


class TestStagePromote:
    def test_valid_pair_promoted_atomically(self, tmp_path):
        cert_pem, key_pem = generate_self_signed()
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        info = stage_validate_promote(cert_pem, key_pem, cert_path, key_path)
        assert cert_path.exists() and key_path.exists()
        assert oct(key_path.stat().st_mode)[-3:] == "600"
        assert info.is_self_signed

    def test_invalid_replacement_does_not_touch_existing_working_pair(self, tmp_path):
        cert_pem, key_pem = generate_self_signed()
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        stage_validate_promote(cert_pem, key_pem, cert_path, key_path)
        original_cert = cert_path.read_bytes()
        original_key = key_path.read_bytes()

        bad_cert, _ = generate_self_signed()
        _, mismatched_key = generate_self_signed()
        with pytest.raises(TlsCertMismatchError):
            stage_validate_promote(bad_cert, mismatched_key, cert_path, key_path)

        assert cert_path.read_bytes() == original_cert
        assert key_path.read_bytes() == original_key

    def test_no_leftover_staging_files_on_failure(self, tmp_path):
        cert_pem, key_pem = generate_self_signed()
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        _, mismatched_key = generate_self_signed()
        with pytest.raises(TlsCertMismatchError):
            stage_validate_promote(cert_pem, mismatched_key, cert_path, key_path)
        leftovers = [p.name for p in tmp_path.iterdir() if p.name.startswith(".stage-")]
        assert leftovers == []


class TestEnsureBootstrap:
    def test_fresh_generation_when_absent(self, tmp_path):
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        info = ensure_bootstrap_cert(cert_path, key_path)
        assert cert_path.exists()
        assert info.is_self_signed

    def test_idempotent_no_regeneration_on_restart(self, tmp_path):
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        ensure_bootstrap_cert(cert_path, key_path)
        first_bytes = cert_path.read_bytes()
        ensure_bootstrap_cert(cert_path, key_path)
        assert cert_path.read_bytes() == first_bytes

    def test_regenerates_if_existing_pair_is_corrupt(self, tmp_path):
        cert_path, key_path = tmp_path / "server.crt", tmp_path / "server.key"
        cert_path.write_bytes(b"garbage")
        key_path.write_bytes(b"garbage")
        info = ensure_bootstrap_cert(cert_path, key_path)
        assert info.is_self_signed
        validate_cert_key_pair(cert_path.read_bytes(), key_path.read_bytes())  # does not raise


class TestLoadActiveCertInfo:
    def test_returns_none_when_absent(self, tmp_path):
        assert load_active_cert_info(tmp_path / "a.crt", tmp_path / "a.key") is None

    def test_returns_none_when_corrupt(self, tmp_path):
        (tmp_path / "a.crt").write_bytes(b"x")
        (tmp_path / "a.key").write_bytes(b"y")
        assert load_active_cert_info(tmp_path / "a.crt", tmp_path / "a.key") is None
