import pytest

from app.v2.runtime_staging import (
    ValidationFailedError,
    ValidationResult,
    run_command_validator,
    stage,
    stage_validate_promote,
)


def _always_ok(path):
    return ValidationResult(ok=True, output="")


def _always_fail(path):
    return ValidationResult(ok=False, output="synthetic failure")


class TestStage:
    def test_stage_writes_content(self, tmp_path):
        p = stage(tmp_path, "thing.conf", "hello\n")
        assert p.read_text() == "hello\n"
        assert p.parent == tmp_path

    def test_stage_never_touches_temp_file_name_visibly(self, tmp_path):
        stage(tmp_path, "thing.conf", "x")
        names = [f.name for f in tmp_path.iterdir()]
        assert names == ["thing.conf"]


class TestValidateBlocksPromotion:
    def test_failed_validation_raises_and_never_writes_live_path(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir()
        live_path = tmp_path / "live" / "thing.conf"
        with pytest.raises(ValidationFailedError):
            stage_validate_promote(staging_root, "thing.conf", "bad", live_path, _always_fail)
        assert not live_path.exists()

    def test_successful_validation_promotes(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir()
        live_path = tmp_path / "live" / "thing.conf"
        result = stage_validate_promote(staging_root, "thing.conf", "good", live_path, _always_ok)
        assert result.promoted
        assert live_path.read_text() == "good"


class TestHealthCheckRollback:
    def test_failed_health_check_restores_previous_content(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir()
        live_path = tmp_path / "live" / "thing.conf"
        live_path.parent.mkdir(parents=True)
        live_path.write_text("old-content")

        result = stage_validate_promote(
            staging_root,
            "thing.conf",
            "new-content",
            live_path,
            _always_ok,
            health_check=lambda: False,
        )
        assert result.rolled_back
        assert not result.promoted
        assert live_path.read_text() == "old-content"

    def test_failed_health_check_with_no_prior_content_removes_file(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir()
        live_path = tmp_path / "live" / "thing.conf"

        result = stage_validate_promote(
            staging_root, "thing.conf", "new", live_path, _always_ok, health_check=lambda: False
        )
        assert result.rolled_back
        assert not live_path.exists()

    def test_passing_health_check_keeps_promotion(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir()
        live_path = tmp_path / "live" / "thing.conf"

        result = stage_validate_promote(
            staging_root, "thing.conf", "new", live_path, _always_ok, health_check=lambda: True
        )
        assert result.promoted
        assert not result.rolled_back


class TestCommandValidator:
    def test_command_validator_true_binary_passes(self, tmp_path):
        validator = run_command_validator(["true"])
        p = stage(tmp_path, "x.conf", "irrelevant")
        result = validator(p)
        assert result.ok

    def test_command_validator_false_binary_fails(self, tmp_path):
        validator = run_command_validator(["false"])
        p = stage(tmp_path, "x.conf", "irrelevant")
        result = validator(p)
        assert not result.ok

    def test_command_validator_missing_binary_fails_not_raises(self, tmp_path):
        validator = run_command_validator(["/no/such/binary-xyz"])
        p = stage(tmp_path, "x.conf", "irrelevant")
        result = validator(p)
        assert not result.ok
        assert "failed" in result.output.lower()

    def test_command_validator_path_substitution(self, tmp_path):
        p = stage(tmp_path, "x.conf", "needle-content")
        validator = run_command_validator(["grep", "-q", "needle-content", "{path}"])
        assert validator(p).ok
        validator2 = run_command_validator(["grep", "-q", "not-present", "{path}"])
        assert not validator2(p).ok
