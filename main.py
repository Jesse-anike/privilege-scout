from __future__ import annotations

import argparse
import json
import os
import stat
import sys
from pathlib import Path


def scan_directory(root: Path) -> dict:
    root = root.expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {root}")
    if not root.is_dir():
        raise NotADirectoryError(f"Target is not a directory: {root}")

    findings = []
    errors = []

    for current, directories, filenames in os.walk(root, followlinks=False):
        # Do not traverse symlinked directories.
        current_path = Path(current)
        directories[:] = [
            name for name in directories
            if not (current_path / name).is_symlink()
        ]

        for name in filenames:
            candidate = current_path / name
            try:
                metadata = candidate.lstat()
            except OSError as exc:
                errors.append({"path": str(candidate), "error": str(exc)})
                continue

            # Inventory regular files only; symlinks and special files are excluded.
            if not stat.S_ISREG(metadata.st_mode):
                continue

            mode = metadata.st_mode
            has_suid = bool(mode & stat.S_ISUID)
            has_sgid = bool(mode & stat.S_ISGID)
            if not (has_suid or has_sgid):
                continue

            findings.append({
                "path": str(candidate.relative_to(root)),
                "mode": stat.filemode(mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
                "suid": has_suid,
                "sgid": has_sgid,
            })

    findings.sort(key=lambda item: item["path"])
    return {
        "scan_root": str(root),
        "files_with_privileged_bits": len(findings),
        "suid_count": sum(item["suid"] for item in findings),
        "sgid_count": sum(item["sgid"] for item in findings),
        "findings": findings,
        "inspection_errors": errors,
        "note": (
            "Read-only metadata inventory. A SUID/SGID bit is a review signal, "
            "not proof of a vulnerability. No file is executed or modified."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Inventory regular files with SUID/SGID permission bits."
    )
    parser.add_argument("target", type=Path, help="Directory to inspect")
    parser.add_argument("--output", help="Optional JSON report output path")
    args = parser.parse_args()

    try:
        report = scan_directory(args.target)
    except (OSError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        return 2

    rendered = json.dumps(report, indent=2)
    if args.output:
        Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
