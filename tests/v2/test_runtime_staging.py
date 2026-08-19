import pytest

from app.v2.runtime_staging import (
    Artifact,
    ValidationFailedError,
    ValidationResult,
    run_command_validator,
    stage,
    stage_validate_promote,
    stage_validate_promote_all,
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


class TestStageValidatePromoteAll:
    """Gate #3 acceptance closure §13: coherent multi-artifact promotion
    (dnsdist.conf + one-or-more BIND context named.confs + the shared RPZ
    zone) -- injected real validation failures at each position must
    never leave a mismatched generation live."""

    def test_all_succeed_all_promoted(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        live_a = tmp_path / "live" / "a.conf"
        live_b = tmp_path / "live" / "b.conf"
        results = stage_validate_promote_all(
            tmp_path / "staging",
            [
                Artifact(name="a.conf", content="A", live_path=live_a, validator=_always_ok),
                Artifact(name="b.conf", content="B", live_path=live_b, validator=_always_ok),
            ],
        )
        assert all(r.promoted for r in results)
        assert live_a.read_text() == "A"
        assert live_b.read_text() == "B"

    def test_last_artifact_failing_promotes_none(self, tmp_path):
        # Simulates: dnsdist.conf would validate fine, but a BIND
        # context's named.conf (checked later in the list) fails
        # named-checkconf -- neither must be promoted, so dnsdist can
        # never end up pointed at a BIND context that never got its new
        # config.
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        live_a = tmp_path / "live" / "a.conf"
        live_b = tmp_path / "live" / "b.conf"
        live_a.parent.mkdir(parents=True, exist_ok=True)
        live_a.write_text("OLD-A")
        live_b.write_text("OLD-B")
        with pytest.raises(ValidationFailedError):
            stage_validate_promote_all(
                staging_root,
                [
                    Artifact(name="a.conf", content="NEW-A", live_path=live_a, validator=_always_ok),
                    Artifact(name="b.conf", content="NEW-B", live_path=live_b, validator=_always_fail),
                ],
            )
        assert live_a.read_text() == "OLD-A"
        assert live_b.read_text() == "OLD-B"

    def test_first_artifact_failing_promotes_none(self, tmp_path):
        # Same coherence guarantee regardless of which artifact in the
        # list is the one that fails.
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        live_a = tmp_path / "live" / "a.conf"
        live_b = tmp_path / "live" / "b.conf"
        live_a.parent.mkdir(parents=True, exist_ok=True)
        live_a.write_text("OLD-A")
        live_b.write_text("OLD-B")
        with pytest.raises(ValidationFailedError):
            stage_validate_promote_all(
                staging_root,
                [
                    Artifact(name="a.conf", content="NEW-A", live_path=live_a, validator=_always_fail),
                    Artifact(name="b.conf", content="NEW-B", live_path=live_b, validator=_always_ok),
                ],
            )
        assert live_a.read_text() == "OLD-A"
        assert live_b.read_text() == "OLD-B"

    def test_no_prior_content_and_failure_leaves_nothing_created(self, tmp_path):
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        live_a = tmp_path / "live" / "a.conf"
        live_b = tmp_path / "live" / "b.conf"
        with pytest.raises(ValidationFailedError):
            stage_validate_promote_all(
                staging_root,
                [
                    Artifact(name="a.conf", content="NEW-A", live_path=live_a, validator=_always_ok),
                    Artifact(name="b.conf", content="NEW-B", live_path=live_b, validator=_always_fail),
                ],
            )
        assert not live_a.exists()
        assert not live_b.exists()

    def test_three_artifacts_middle_fails_none_promoted(self, tmp_path):
        # Mirrors the real three-artifact case (RPZ zone, BIND
        # named.conf, dnsdist.conf) exactly.
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        paths = [tmp_path / "live" / f"{n}.conf" for n in ("rpz", "bind", "dnsdist")]
        for pth in paths:
            pth.parent.mkdir(parents=True, exist_ok=True)
            pth.write_text("OLD")
        with pytest.raises(ValidationFailedError):
            stage_validate_promote_all(
                staging_root,
                [
                    Artifact(name="rpz.conf", content="NEW", live_path=paths[0], validator=_always_ok),
                    Artifact(name="bind.conf", content="NEW", live_path=paths[1], validator=_always_fail),
                    Artifact(name="dnsdist.conf", content="NEW", live_path=paths[2], validator=_always_ok),
                ],
            )
        assert all(pth.read_text() == "OLD" for pth in paths)

    def test_generation_stays_coherent_after_repeated_failed_attempts(self, tmp_path):
        # A management API caller retrying a bad mutation repeatedly must
        # never accumulate partial state -- every attempt either promotes
        # everything or nothing.
        staging_root = tmp_path / "staging"
        staging_root.mkdir(exist_ok=True)
        live_a = tmp_path / "live" / "a.conf"
        live_b = tmp_path / "live" / "b.conf"
        live_a.parent.mkdir(parents=True, exist_ok=True)
        live_a.write_text("V1-A")
        live_b.write_text("V1-B")
        for _ in range(3):
            with pytest.raises(ValidationFailedError):
                stage_validate_promote_all(
                    staging_root,
                    [
                        Artifact(name="a.conf", content="BAD-A", live_path=live_a, validator=_always_ok),
                        Artifact(name="b.conf", content="BAD-B", live_path=live_b, validator=_always_fail),
                    ],
                )
        assert live_a.read_text() == "V1-A"
        assert live_b.read_text() == "V1-B"
        # A subsequent real success still works correctly afterward.
        results = stage_validate_promote_all(
            tmp_path / "staging",
            [
                Artifact(name="a.conf", content="V2-A", live_path=live_a, validator=_always_ok),
                Artifact(name="b.conf", content="V2-B", live_path=live_b, validator=_always_ok),
            ],
        )
        assert all(r.promoted for r in results)
        assert live_a.read_text() == "V2-A"
        assert live_b.read_text() == "V2-B"
