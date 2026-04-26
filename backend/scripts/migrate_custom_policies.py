"""Migrate user-created policies to the custom/ subtree.

Usage:
  python migrate_custom_policies.py [--apply] [--policies-dir PATH]

Default is dry-run (no filesystem changes).
Pass --apply to move files.
"""

import argparse
import shutil
import sys
from pathlib import Path

BUILTIN_MANIFEST: frozenset[str] = frozenset({
    "compute/ec2.rego",
    "compute/serverless.rego",
    "cross_resource/capital_one_scenario.rego",
    "data_protection/database.rego",
    "data_protection/kms.rego",
    "data_protection/macie.rego",
    "data_protection/s3.rego",
    "data_protection/secretsmanager.rego",
    "data_protection/storage.rego",
    "detection/aws_security.rego",
    "governance/tagging.rego",
    "identity/cognito.rego",
    "identity/iam.rego",
    "logging/cloudtrail.rego",
    "logging/cloudwatch.rego",
    "logging/config.rego",
    "network/api_gateway.rego",
    "network/vpc.rego",
    "network/waf.rego",
    "risk_scoring/risk_score.rego",
})

CUSTOM_SUBDIR = "custom"


def find_movable_policies(
    policies_dir: Path,
) -> list[Path]:
    """Return .rego files not in manifest and not already
    under custom/."""
    movable: list[Path] = []
    for rego in sorted(policies_dir.rglob("*.rego")):
        if "_test.rego" in rego.name:
            continue
        rel = rego.relative_to(policies_dir)
        parts = rel.parts
        # Skip files already in custom/ subtree
        if CUSTOM_SUBDIR in parts:
            continue
        # Skip builtin manifest files
        if str(rel) in BUILTIN_MANIFEST:
            continue
        movable.append(rego)
    return movable


def migrate(
    policies_dir: Path,
    apply: bool,
) -> dict:
    """Classify and optionally move non-builtin policies.

    Returns:
        dry-run (apply=False):
            {"would_move": [str, ...], "collisions": []}
        apply (apply=True):
            {"moved": [{"src": str, "dst": str}, ...],
             "collisions": [{"src": str, "dst": str}, ...]}
    """
    movable = find_movable_policies(policies_dir)

    if not apply:
        return {
            "would_move": [str(p) for p in movable],
            "collisions": [],
        }

    moved: list[dict] = []
    collisions: list[dict] = []

    for src in movable:
        rel = src.relative_to(policies_dir)
        dst = policies_dir / CUSTOM_SUBDIR / rel
        src_str = str(src)
        dst_str = str(dst)

        if dst.exists():
            collisions.append(
                {"src": src_str, "dst": dst_str}
            )
            continue

        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(src_str, dst_str)
        moved.append({"src": src_str, "dst": dst_str})

    return {"moved": moved, "collisions": collisions}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Migrate custom policies to custom/ subdir"
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        default=False,
        help="Apply changes (default: dry-run)",
    )
    parser.add_argument(
        "--policies-dir",
        default=str(
            Path(__file__).resolve().parent.parent.parent
            / "policies"
        ),
        help="Path to policies directory",
    )
    args = parser.parse_args(argv)

    policies_dir = Path(args.policies_dir)
    result = migrate(policies_dir, apply=args.apply)

    if args.apply:
        for item in result["moved"]:
            print(f"MOVED  {item['src']} -> {item['dst']}")
        for item in result["collisions"]:
            print(
                f"SKIP   {item['src']} "
                f"(collision: {item['dst']})"
            )
        return 1 if result["collisions"] else 0
    else:
        for path in result["would_move"]:
            print(f"DRY    {path}")
        return 0


if __name__ == "__main__":
    sys.exit(main())
