#!/usr/bin/env python3
"""Rebase kernel patch hunk coordinates from an exact GNU patch offset report.

Only @@ start-line coordinates are changed; hunk bodies and patch payloads
must remain byte-for-byte identical. The script validates every CSV record
before it writes any patch file.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
from pathlib import Path

HUNK_RE = re.compile(
    r"^@@ -(?P<old>\d+)(?P<old_count>,\d+)? "
    r"\+(?P<new>\d+)(?P<new_count>,\d+)? @@(?P<suffix>.*)$"
)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def normalize_path(value: str) -> str:
    value = value.split("\t", 1)[0].strip()
    if len(value) >= 2 and value[0] == value[-1] == '"':
        value = value[1:-1]
    if value == "/dev/null":
        return value
    if value.startswith(("a/", "b/")):
        value = value[2:]
    if value.startswith("./"):
        value = value[2:]
    return value


def load_records(csv_path: Path) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    with csv_path.open("r", encoding="utf-8", newline="") as handle:
        reader = csv.DictReader(handle)
        required = {"patch_path", "source_file", "hunk", "actual_applied_line", "offset_lines"}
        if not required.issubset(reader.fieldnames or []):
            raise SystemExit(f"offset CSV is missing columns: {sorted(required)}")
        for row in reader:
            patch = row["patch_path"]
            source = row["source_file"]
            if not patch or patch.startswith("/") or ".." in Path(patch).parts:
                raise SystemExit(f"unsafe patch path: {patch!r}")
            if not patch.startswith(("target/linux/generic/", "target/linux/mediatek/")):
                raise SystemExit(f"record is outside the kernel patch tree: {patch}")
            if not source or source.startswith("/") or ".." in Path(source).parts:
                raise SystemExit(f"unsafe source path: {source!r}")
            offset = int(row["offset_lines"])
            if offset == 0:
                raise SystemExit(f"zero-offset record is not a rebase input: {patch} {source}")
            groups.setdefault(patch, []).append({
                "file": source,
                "hunk": int(row["hunk"]),
                "actual_applied_line": int(row["actual_applied_line"]),
                "offset": offset,
            })
    return groups


def transform_patch(patch_path: Path, records: list[dict]) -> tuple[str, list[dict]]:
    with patch_path.open("r", encoding="utf-8", newline="") as handle:
        original = handle.read()
    lines = original.splitlines(keepends=True)

    old_file = None
    current_file = None
    waiting_for_new_path = False
    hunk_number = 0
    in_hunk = False
    old_remaining = 0
    new_remaining = 0
    record_index = 0
    changes: list[dict] = []

    for index, raw_line in enumerate(lines):
        line = raw_line.rstrip("\r\n")

        if not in_hunk:
            if line.startswith("--- "):
                old_file = normalize_path(line[4:])
                waiting_for_new_path = True
                continue
            if waiting_for_new_path and line.startswith("+++ "):
                new_file = normalize_path(line[4:])
                current_file = old_file if new_file == "/dev/null" else new_file
                if current_file == "/dev/null":
                    current_file = old_file
                hunk_number = 0
                waiting_for_new_path = False
                continue

        if line.startswith("@@"):
            if not line.startswith("@@ "):
                raise SystemExit(f"unsupported combined-diff hunk in {patch_path}: {line}")
            if not current_file:
                raise SystemExit(f"hunk has no file header in {patch_path}: {line}")
            match = HUNK_RE.match(line)
            if not match:
                raise SystemExit(f"unsupported hunk header in {patch_path}: {line}")
            hunk_number += 1

            record = records[record_index] if record_index < len(records) else None
            if record and record["file"] == current_file and record["hunk"] == hunk_number:
                offset = record["offset"]
                old_start = int(match.group("old"))
                new_start = int(match.group("new"))
                if old_start == 0 or new_start == 0:
                    raise SystemExit(f"cannot rebase zero-start hunk in {patch_path}: {line}")
                rebased_old = old_start + offset
                rebased_new = new_start + offset
                if rebased_old < 0 or rebased_new < 0:
                    raise SystemExit(f"negative hunk coordinate in {patch_path}: {line}")
                newline = "\r\n" if raw_line.endswith("\r\n") else "\n" if raw_line.endswith("\n") else ""
                updated_header = (
                    f"@@ -{rebased_old}{match.group('old_count') or ''} "
                    f"+{rebased_new}{match.group('new_count') or ''} @@{match.group('suffix')}{newline}"
                )
                changes.append({
                    "source_file": current_file,
                    "hunk": hunk_number,
                    "offset_lines": offset,
                    "actual_applied_line": record["actual_applied_line"],
                    "old_header": line,
                    "new_header": updated_header.rstrip("\r\n"),
                })
                lines[index] = updated_header
                record_index += 1
            elif record and record["file"] == current_file and record["hunk"] < hunk_number:
                raise SystemExit(
                    f"hunk sequence mismatch in {patch_path}: expected "
                    f"{record['file']} hunk {record['hunk']}, reached {current_file} hunk {hunk_number}"
                )

            old_remaining = int((match.group("old_count") or ",1").lstrip(","))
            new_remaining = int((match.group("new_count") or ",1").lstrip(","))
            in_hunk = old_remaining > 0 or new_remaining > 0
            continue

        if in_hunk:
            if raw_line.startswith(" "):
                old_remaining -= 1
                new_remaining -= 1
            elif raw_line.startswith("-"):
                old_remaining -= 1
            elif raw_line.startswith("+"):
                new_remaining -= 1
            elif raw_line.startswith("\\"):
                pass
            else:
                raise SystemExit(f"malformed hunk body in {patch_path}, line {index + 1}: {line!r}")
            if old_remaining < 0 or new_remaining < 0:
                raise SystemExit(f"hunk body count underflow in {patch_path}, line {index + 1}")
            if old_remaining == 0 and new_remaining == 0:
                in_hunk = False

    if in_hunk:
        raise SystemExit(f"truncated hunk body in {patch_path}")
    if record_index != len(records):
        record = records[record_index]
        raise SystemExit(
            f"unmatched offset record in {patch_path}: {record['file']} "
            f"hunk {record['hunk']} offset {record['offset']}"
        )

    updated = "".join(lines)
    before = original.splitlines(keepends=True)
    after = updated.splitlines(keepends=True)
    if len(before) != len(after):
        raise SystemExit(f"patch line count changed in {patch_path}")
    for old_line, new_line in zip(before, after):
        if old_line != new_line and not (old_line.startswith("@@ ") and new_line.startswith("@@ ")):
            raise SystemExit(f"non-hunk patch payload changed in {patch_path}")
    return updated, changes


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--csv", type=Path, required=True)
    parser.add_argument("--apply", action="store_true", help="write rebased patch files")
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()

    repo = args.repo.resolve()
    csv_path = args.csv if args.csv.is_absolute() else repo / args.csv
    csv_path = csv_path.resolve()
    groups = load_records(csv_path)

    patch_reports = []
    all_changes = []
    total_records = sum(len(items) for items in groups.values())

    # Validate and transform every file in memory before writing any file.
    for relative in sorted(groups):
        patch_path = (repo / relative).resolve()
        if repo not in patch_path.parents:
            raise SystemExit(f"patch path escapes repository: {relative}")
        if not patch_path.is_file():
            raise SystemExit(f"patch file is missing: {relative}")
        old_bytes = patch_path.read_bytes()
        updated, changes = transform_patch(patch_path, groups[relative])
        new_bytes = updated.encode("utf-8")
        if len(changes) != len(groups[relative]):
            raise SystemExit(f"not all offset records mapped in {relative}")
        if old_bytes == new_bytes:
            raise SystemExit(f"offset records did not change {relative}")
        patch_reports.append({
            "patch_path": relative,
            "old_sha256": sha256(old_bytes),
            "new_sha256": sha256(new_bytes),
            "rebased_hunks": len(changes),
        })
        all_changes.extend({"patch_path": relative, **item} for item in changes)
        groups[relative] = {"updated": updated, "path": patch_path}

    if len(all_changes) != total_records:
        raise SystemExit(f"record accounting mismatch: {len(all_changes)} != {total_records}")

    if args.apply:
        for item in groups.values():
            with item["path"].open("w", encoding="utf-8", newline="") as handle:
                handle.write(item["updated"])

    report = {
        "operation": "hunk-coordinate-only-rebase",
        "source_commit": os.environ.get("GITHUB_SHA", "local"),
        "input_csv": str(csv_path.relative_to(repo)),
        "input_csv_sha256": sha256(csv_path.read_bytes()),
        "patches_changed": len(patch_reports),
        "hunks_rebased": len(all_changes),
        "offset_records_consumed": total_records,
        "patch_payload_changed": False,
        "mode": "applied" if args.apply else "check-only",
        "patches": patch_reports,
        "changes": all_changes,
    }
    report_path = args.report if args.report.is_absolute() else repo / args.report
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(
        f"PASS: mapped {total_records} offset records across {len(patch_reports)} patches; "
        f"rebased {len(all_changes)} hunk headers; patch payload unchanged; "
        f"mode={'apply' if args.apply else 'check-only'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
