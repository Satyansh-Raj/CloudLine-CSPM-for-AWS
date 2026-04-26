"""TDD Batch 4 RED tests — migration script."""

import textwrap
from pathlib import Path

import pytest

from scripts.migrate_custom_policies import (
    BUILTIN_MANIFEST,
    find_movable_policies,
    main,
    migrate,
)

_BUILTIN_CONTENT = textwrap.dedent("""\
    package aws.identity.iam

    violations contains result if {
        result := {"check_id": "iam_root_mfa"}
    }
""")

_CUSTOM_CONTENT = textwrap.dedent("""\
    package aws.identity.custom_check

    violations contains result if {
        result := {"check_id": "my_custom_01"}
    }
""")


@pytest.fixture
def policies_dir(tmp_path: Path) -> Path:
    """Policies dir with one builtin and one custom file."""
    (tmp_path / "identity").mkdir()
    (tmp_path / "identity" / "iam.rego").write_text(
        _BUILTIN_CONTENT
    )
    (tmp_path / "identity" / "my_custom.rego").write_text(
        _CUSTOM_CONTENT
    )
    return tmp_path


def test_manifest_contains_all_20_builtin_check_ids():
    assert len(BUILTIN_MANIFEST) == 20


def test_dry_run_lists_movable_files_without_changes(
    policies_dir: Path,
):
    result = migrate(policies_dir, apply=False)
    # Reports the custom file as would-move
    would_move = result["would_move"]
    names = [Path(p).name for p in would_move]
    assert "my_custom.rego" in names
    assert "iam.rego" not in names
    # Filesystem unchanged — custom/ dir NOT created
    assert not (policies_dir / "custom").exists()
    # Original file still in place
    assert (
        policies_dir / "identity" / "my_custom.rego"
    ).exists()


def test_dry_run_is_default_mode(policies_dir: Path):
    rc = main(["--policies-dir", str(policies_dir)])
    # Dry run → 0 exit, no filesystem changes
    assert rc == 0
    assert not (policies_dir / "custom").exists()


def test_apply_moves_only_non_manifest_policies(
    policies_dir: Path,
):
    result = migrate(policies_dir, apply=True)
    moved = result["moved"]
    names = [Path(p["src"]).name for p in moved]
    assert "my_custom.rego" in names
    assert "iam.rego" not in names
    # Builtin still in original location
    assert (
        policies_dir / "identity" / "iam.rego"
    ).exists()
    # Custom moved out
    assert not (
        policies_dir / "identity" / "my_custom.rego"
    ).exists()


def test_apply_preserves_subdirectory_structure(
    policies_dir: Path,
):
    migrate(policies_dir, apply=True)
    dest = (
        policies_dir
        / "custom"
        / "identity"
        / "my_custom.rego"
    )
    assert dest.exists()


def test_apply_is_idempotent(policies_dir: Path):
    r1 = migrate(policies_dir, apply=True)
    r2 = migrate(policies_dir, apply=True)
    assert len(r2["moved"]) == 0
    assert len(r2["collisions"]) == 0
    # File still exists at destination
    dest = (
        policies_dir
        / "custom"
        / "identity"
        / "my_custom.rego"
    )
    assert dest.exists()


def test_apply_skips_when_destination_already_exists(
    policies_dir: Path,
):
    # Pre-create destination
    dest_dir = policies_dir / "custom" / "identity"
    dest_dir.mkdir(parents=True)
    (dest_dir / "my_custom.rego").write_text(
        "# already here"
    )
    result = migrate(policies_dir, apply=True)
    collisions = result["collisions"]
    assert len(collisions) == 1
    # Source NOT deleted
    assert (
        policies_dir / "identity" / "my_custom.rego"
    ).exists()


def test_apply_exit_code_zero_on_success_nonzero_on_collision(
    policies_dir: Path,
):
    # Clean run → 0
    rc = main(
        ["--apply", "--policies-dir", str(policies_dir)]
    )
    assert rc == 0

    # Restore for collision test
    (policies_dir / "identity" / "my_custom.rego").write_text(
        _CUSTOM_CONTENT
    )
    rc_collision = main(
        ["--apply", "--policies-dir", str(policies_dir)]
    )
    assert rc_collision != 0
