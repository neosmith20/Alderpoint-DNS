import pytest
from cryptography.fernet import Fernet

from app.v2.secret_replication import (
    SecretReplicationAuthError,
    SecretReplicationError,
    apply_envelope,
    build_envelope,
)
from app.v2.secret_store import SecretStore


@pytest.fixture()
def key():
    return Fernet.generate_key()


@pytest.fixture()
def primary(tmp_path):
    store = SecretStore(tmp_path / "primary-secrets")
    store.create("token-1", secret_id="webhook-token")
    return store


@pytest.fixture()
def secondary(tmp_path):
    return SecretStore(tmp_path / "secondary-secrets")


class TestBasicReplication:
    def test_apply_to_isolated_secondary(self, primary, secondary, key):
        envelope = build_envelope(primary, key, node_id="primary-1", generation=1)
        result = apply_envelope(envelope, key, secondary, known_generations={})
        assert result.applied
        assert secondary.get("webhook-token") == "token-1"

    def test_generation_tracked_after_apply(self, primary, secondary, key):
        gens = {}
        apply_envelope(build_envelope(primary, key, "node-a", 1), key, secondary, gens)
        assert gens["node-a"] == 1


class TestConflictAndVersioning:
    def test_stale_generation_not_applied(self, primary, secondary, key):
        gens = {"node-a": 5}
        result = apply_envelope(build_envelope(primary, key, "node-a", 3), key, secondary, gens)
        assert not result.applied
        assert result.reason == "stale_generation"

    def test_duplicate_generation_not_reapplied(self, primary, secondary, key):
        gens = {}
        apply_envelope(build_envelope(primary, key, "node-a", 1), key, secondary, gens)
        result = apply_envelope(build_envelope(primary, key, "node-a", 1), key, secondary, gens)
        assert not result.applied

    def test_newer_generation_applied_and_overwrites(self, primary, secondary, key):
        gens = {}
        apply_envelope(build_envelope(primary, key, "node-a", 1), key, secondary, gens)
        primary.update("webhook-token", "token-2")
        result = apply_envelope(build_envelope(primary, key, "node-a", 2), key, secondary, gens)
        assert result.applied
        assert secondary.get("webhook-token") == "token-2"

    def test_independent_nodes_tracked_separately(self, primary, secondary, key):
        gens = {}
        apply_envelope(build_envelope(primary, key, "node-a", 1), key, secondary, gens)
        result_b = apply_envelope(build_envelope(primary, key, "node-b", 1), key, secondary, gens)
        assert result_b.applied  # different node_id, generation 1 is still new for it
        assert gens == {"node-a": 1, "node-b": 1}


class TestAuthentication:
    def test_wrong_key_raises_auth_error(self, primary, secondary, key):
        envelope = build_envelope(primary, key, "node-a", 1)
        wrong_key = Fernet.generate_key()
        with pytest.raises(SecretReplicationAuthError):
            apply_envelope(envelope, wrong_key, secondary, known_generations={})

    def test_tampered_envelope_rejected(self, primary, secondary, key):
        envelope = bytearray(build_envelope(primary, key, "node-a", 1))
        envelope[5:15] = b"TAMPERED!!"
        with pytest.raises(SecretReplicationAuthError):
            apply_envelope(bytes(envelope), key, secondary, known_generations={})


class TestNoLogLeakage:
    def test_secret_repr_of_apply_result_never_contains_value(self, primary, secondary, key):
        envelope = build_envelope(primary, key, "node-a", 1)
        result = apply_envelope(envelope, key, secondary, known_generations={})
        assert "token-1" not in repr(result)
        assert "token-1" not in str(result)

    def test_envelope_bytes_are_ciphertext_not_plaintext(self, primary, key):
        envelope = build_envelope(primary, key, "node-a", 1)
        assert b"token-1" not in envelope


class TestValidation:
    def test_empty_node_id_rejected(self, primary, key):
        with pytest.raises(SecretReplicationError):
            build_envelope(primary, key, node_id="", generation=1)

    def test_malformed_envelope_rejected(self, secondary, key):
        with pytest.raises(SecretReplicationAuthError):
            apply_envelope(b"not a real envelope", key, secondary, known_generations={})
