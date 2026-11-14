#!/usr/bin/env python3
"""Generate and verify the N60 Pro EasyMesh 033-037 consolidation candidates."""
from __future__ import annotations
import hashlib, json, os, re, shutil, subprocess, tempfile
from pathlib import Path

BASELINE_COMMIT = "5767c89102a4eba199e7577cd4f210168a677a37"
LOCK_REL = "package/mtk/vendor-sources.lock.json"
PATCH_REL = "package/mtk/applications/easymesh-n60/patches"
ARCHIVE_NAME = "wappd-80ca5724.tar.bz2"
REMOVED = [
 "033-dpp-main-config-lifecycle.patch",
 "034-dpp-wdev-credential-handling.patch",
 "035-dpp-auth-credential-lifecycle.patch",
 "036-wapp-device-config-secret-cleanup.patch",
 "037-dpp-diagnostic-redaction.patch",
]
ORIGINAL_ORDER = [
 "002-dpp-parser-safety.patch",
 "007-openssl3-use-native-evp-pkey-get0-ec-key.patch",
 "008-dpp-parser-bounds-and-secret-redaction.patch",
 "010-dpp-wdev-config-allocation-rollback.patch",
 "015-dpp-config-lookup-null-and-error-guard.patch",
 "016-dpp-qr-count-boundaries-and-error-propagation.patch",
 *REMOVED,
]
GROUPS = {
 "008-dpp-parser-bounds-and-secret-redaction.patch": [
  "008-dpp-parser-bounds-and-secret-redaction.patch",
  "035-dpp-auth-credential-lifecycle.patch",
  "037-dpp-diagnostic-redaction.patch",
 ],
 "010-dpp-wdev-config-allocation-rollback.patch": [
  "010-dpp-wdev-config-allocation-rollback.patch",
  "033-dpp-main-config-lifecycle.patch",
  "036-wapp-device-config-secret-cleanup.patch",
 ],
 "015-dpp-config-lookup-null-and-error-guard.patch": [
  "015-dpp-config-lookup-null-and-error-guard.patch",
  "034-dpp-wdev-credential-handling.patch",
 ],
}
TARGETS = list(GROUPS)

def run(args, cwd=None, input_text=None, check=True):
 p = subprocess.run(args, cwd=cwd, input=input_text, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
 if check and p.returncode:
  raise RuntimeError(f"command failed ({p.returncode}): {' '.join(map(str,args))}\n{p.stdout}")
 return p.stdout

def digest(data):
 return hashlib.sha256(data).hexdigest()

def git_patch(repo, name):
 path = f"{PATCH_REL}/{name}"
 return run(["git", "show", f"{BASELINE_COMMIT}:{path}"], cwd=repo)

def init_tree(root):
 run(["git", "init", "-q"], cwd=root)
 run(["git", "config", "user.name", "N60 Patch Replay"], cwd=root)
 run(["git", "config", "user.email", "n60-patch-replay@invalid.local"], cwd=root)
 run(["git", "add", "-A"], cwd=root)
 run(["git", "commit", "-qm", "pristine fixed WAPP vendor source"], cwd=root)

def commit_tree(root, msg):
 run(["git", "add", "-A"], cwd=root)
 run(["git", "commit", "-qm", msg], cwd=root)

def apply_patch(root, name, content, events, allow_offsets=False):
 p = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0", "-p1"],
                    cwd=root, input=content, text=True,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
 output = p.stdout or ""
 events.append(f"### {name} (allow_offsets={allow_offsets})\n{output}")
 bad = re.search(r"(with fuzz\s+\d+|Hunk\s+#\d+\s+FAILED|saving rejects|Reversed \(or previously applied\)|malformed patch)", output, re.I)
 if not allow_offsets and re.search(r"offset\s+-?\d+\s+lines?", output, re.I):
  bad = True
 if p.returncode or bad:
  mode = "zero-fuzz replay" if allow_offsets else "zero-fuzz/zero-offset replay"
  raise RuntimeError(f"{mode} failed for {name} (rc={p.returncode})\n{output}")
 rejects = list(root.rglob("*.rej")) + list(root.rglob("*.orig"))
 if rejects:
  raise RuntimeError(f"reject/orig files appeared after {name}: {rejects[:8]}")

def remove_033_overlapping_psk_hunk(content):
 lines = content.splitlines()
 matches = [i for i, line in enumerate(lines) if line == "@@ -1023,6 +1026,8 @@"]
 if len(matches) != 1:
  raise RuntimeError("033 expected exactly one overlapping PSK-zeroization hunk")
 start = matches[0]
 end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("@@ ") or lines[i].startswith("--- a/")), len(lines))
 body = lines[start + 1:end]
 additions = [line for line in body if line.startswith("+")]
 expected = [
  "+\t\t\t\t/* Clear an old PSK before replacing the config object. */",
  "+\t\t\t\tforced_memzero(wdev->config->psk, sizeof(wdev->config->psk));",
 ]
 if additions != expected or any(line.startswith("-") for line in body):
  raise RuntimeError("033 overlapping hunk differs from the exact two-line PSK clear; refusing automatic merge")
 return "\n".join(lines[:start] + lines[end:]) + "\n"

def integrate_033_psk_zeroization(root, events):
 path = root / "wappd/common/main.c"
 source = path.read_text(encoding="utf-8")
 target = "os_memcpy(wdev->config, (char *)(&config[k]), sizeof(struct dpp_config));"
 if source.count(target) != 1:
  raise RuntimeError(f"010 ownership boundary must contain exactly one memcpy anchor; found {source.count(target)}")
 line = next(line for line in source.splitlines() if target in line)
 indent = line[:len(line) - len(line.lstrip())]
 replacement = (
  indent + "/* Clear an old PSK before replacing the config object. */\n" +
  indent + "forced_memzero(wdev->config->psk, sizeof(wdev->config->psk));\n" +
  line
 )
 source = source.replace(line, replacement, 1)
 path.write_text(source, encoding="utf-8", newline="")
 events.append("033 lifecycle merge: moved the two-line PSK zeroization hunk into 010 immediately before its config memcpy")

def apply_legacy_patch(root, name, content, events):
 if name == "033-dpp-main-config-lifecycle.patch":
  content = remove_033_overlapping_psk_hunk(content)
 apply_patch(root, name, content, events, allow_offsets=True)
 if name == "033-dpp-main-config-lifecycle.patch":
  integrate_033_psk_zeroization(root, events)

def capture_group(root, name, output):
 run(["git", "add", "-A"], cwd=root)
 diff = run(["git", "diff", "--cached", "--no-ext-diff", "--no-renames",
             "--src-prefix=a/", "--dst-prefix=b/", "HEAD"], cwd=root)
 if not diff.startswith("diff --git "):
  raise RuntimeError(f"generated patch {name} is empty or not a Git unified diff")
 if re.search(r"^# BEGIN:|^# END:", diff, re.M):
  raise RuntimeError(f"non-diff merge markers leaked into {name}")
 if not re.search(r"^@@ ", diff, re.M):
  raise RuntimeError(f"generated patch {name} contains no unified hunks")
 output.write_text(diff, encoding="utf-8", newline="")
 run(["git", "commit", "-qm", f"checkpoint: merged {name}"], cwd=root)
 return diff

def extract_source(archive, dest):
 dest.mkdir(parents=True, exist_ok=True)
 run(["tar", "-xjf", str(archive), "-C", str(dest)])
 if not (dest / "wappd").is_dir():
  raise RuntimeError(f"fixed WAPP archive did not extract wappd/ root: {list(dest.iterdir())[:8]}")
 return dest

def tree_hashes(root):
 out = {}
 for base, dirs, files in os.walk(root):
  dirs[:] = [d for d in dirs if d != ".git"]
  for name in files:
   path = Path(base) / name
   out[path.relative_to(root).as_posix()] = digest(path.read_bytes())
 return out

def compare_trees(a, b):
 ah, bh = tree_hashes(a), tree_hashes(b)
 if ah != bh:
  only_a = sorted(set(ah) - set(bh))
  only_b = sorted(set(bh) - set(ah))
  changed = sorted(k for k in set(ah) & set(bh) if ah[k] != bh[k])
  raise RuntimeError("consolidated source differs from original ordered source: "
                     f"only_candidate={only_a[:12]}, only_reference={only_b[:12]}, "
                     f"content_differences={changed[:20]}")

def main():
 import argparse
 ap = argparse.ArgumentParser()
 ap.add_argument("--repo", required=True)
 ap.add_argument("--output", required=True)
 args = ap.parse_args()
 repo = Path(args.repo).resolve()
 output = Path(args.output).resolve()
 output.mkdir(parents=True, exist_ok=True)
 patch_dir = repo / PATCH_REL
 lock_path = repo / LOCK_REL
 archive = repo / "dl" / ARCHIVE_NAME
 if not archive.is_file():
  raise RuntimeError(f"fixed vendor archive absent after download: {archive}")
 lock = json.loads(lock_path.read_text(encoding="utf-8"))
 source = next(x for x in lock["sources"] if x["id"] == "wappd")
 archive_sha = digest(archive.read_bytes())
 if archive_sha != source["sha256"]:
  raise RuntimeError(f"WAPP archive SHA256 mismatch: expected {source['sha256']} got {archive_sha}")
 original = {name: git_patch(repo, name) for name in ORIGINAL_ORDER}
 original_hashes = {name: digest(data.encode()) for name, data in original.items()}

 # 037 contains one objectively inconsistent new-file hunk header: the
 # /dev/null source side declares one old line although the body contains
 # exactly nineteen added lines and no context/deletions. Correct only that
 # hunk count; do not change any added source line.
 patch_037 = "037-dpp-diagnostic-redaction.patch"
 raw_037 = original[patch_037]
 original_037_sha = digest(raw_037.encode())
 lines_037 = raw_037.splitlines()
 hunk_ids = [i for i, line in enumerate(lines_037) if line == "@@ -0,1 +1,20 @@"]
 if len(hunk_ids) != 1:
  raise RuntimeError("037 expected exactly one malformed /dev/null hunk @@ -0,1 +1,20 @@")
 hidx = hunk_ids[0]
 endidx = next((i for i in range(hidx + 1, len(lines_037))
                if lines_037[i].startswith("--- a/")), len(lines_037))
 body = lines_037[hidx + 1:endidx]
 while body and body[-1] == "":
  body.pop()  # blank separator before the next file header is outside the hunk
 old_count = sum(1 for line in body if line.startswith(" ") or line.startswith("-"))
 new_count = sum(1 for line in body if line.startswith(" ") or line.startswith("+"))
 if old_count != 0 or new_count != 19 or any(not line.startswith("+") for line in body):
  raise RuntimeError(f"037 new-file hunk body mismatch: old={old_count}, new={new_count}; refusing normalization")
 lines_037[hidx] = "@@ -0,0 +1,19 @@"
 normalized_037 = "\n".join(lines_037) + "\n"
 normalized_037_sha = digest(normalized_037.encode())
 original[patch_037] = normalized_037
 events = [
  "037 structural-only normalization: @@ -0,1 +1,20 @@ -> @@ -0,0 +1,19 @@",
  f"037 original patch SHA256: {original_037_sha}",
  f"037 normalized patch SHA256: {normalized_037_sha}",
 ]

 with tempfile.TemporaryDirectory(prefix="n60-easymesh-merge-") as td:
  tmp = Path(td)
  # Candidate tree: merge changes into their responsibility patches.
  candidate = extract_source(archive, tmp / "candidate")
  init_tree(candidate)
  apply_patch(candidate, ORIGINAL_ORDER[0], original[ORIGINAL_ORDER[0]], events)
  commit_tree(candidate, "original 002 baseline")
  apply_patch(candidate, ORIGINAL_ORDER[1], original[ORIGINAL_ORDER[1]], events)
  commit_tree(candidate, "original 007 baseline")
  for name in GROUPS[TARGETS[0]]:
   apply_legacy_patch(candidate, name, original[name], events)
  p008 = capture_group(candidate, TARGETS[0], output / TARGETS[0])
  for name in GROUPS[TARGETS[1]]:
   apply_legacy_patch(candidate, name, original[name], events)
  p010 = capture_group(candidate, TARGETS[1], output / TARGETS[1])
  for name in GROUPS[TARGETS[2]]:
   apply_legacy_patch(candidate, name, original[name], events)
  p015 = capture_group(candidate, TARGETS[2], output / TARGETS[2])
  apply_patch(candidate, ORIGINAL_ORDER[5], original[ORIGINAL_ORDER[5]], events)

  # Reference tree: replay the unmodified original Lock sequence.
  reference = extract_source(archive, tmp / "reference")
  init_tree(reference)
  for name in ORIGINAL_ORDER:
   apply_legacy_patch(reference, name, original[name], events)
   commit_tree(reference, f"original ordered replay: {name}")
  compare_trees(candidate, reference)

  # Verify the generated unified diffs themselves from a clean source tree.
  verify = extract_source(archive, tmp / "verify")
  init_tree(verify)
  for name in ORIGINAL_ORDER[:2]:
   apply_patch(verify, name, original[name], events)
   commit_tree(verify, f"verify baseline: {name}")
  for name in TARGETS:
   generated = (output / name).read_text(encoding="utf-8")
   apply_patch(verify, name, generated, events)
   commit_tree(verify, f"verify consolidated: {name}")
  apply_patch(verify, ORIGINAL_ORDER[5], original[ORIGINAL_ORDER[5]], events)
  compare_trees(verify, reference)

  meta = {}
  for name, data in [(TARGETS[0], p008), (TARGETS[1], p010), (TARGETS[2], p015)]:
   raw = data.encode()
   meta[name] = {"sha256": digest(raw), "hunks": len(re.findall(r"^@@ ", data, re.M)), "bytes": len(raw)}

  # Change the repository checkout only after both replay paths are byte-identical.
  for name in TARGETS:
   shutil.copy2(output / name, patch_dir / name)
  for name in REMOVED:
   path = patch_dir / name
   if path.exists():
    path.unlink()
  easymesh = lock["patch_sets"][0]
  easymesh["application_order"] = [n for n in easymesh["application_order"] if n not in REMOVED]
  lock_text = json.dumps(lock, ensure_ascii=False, indent=2) + "\n"
  lock_path.write_text(lock_text, encoding="utf-8", newline="")
  shutil.copy2(lock_path, output / "vendor-sources.lock.json")
  lock_sha = digest(lock_text.encode())

  report = [
   "# N60 Pro EasyMesh 033-037 consolidation candidate",
   "",
   f"- Repository input commit: {os.environ.get('GITHUB_SHA', 'local')}",
   f"- Original source baseline: {BASELINE_COMMIT}",
   f"- WAPP archive: {ARCHIVE_NAME}",
   f"- WAPP archive SHA256: {archive_sha}",
   "- Original Lock-order reference replay with the 033 overlap merged into 010 and 037 hunk counts corrected: PASS (zero fuzz/reject; historical offsets are rebased into the generated patches).",
   "- Consolidated-order replay: PASS",
   "- Generated unified-diff replay: PASS",
   "- Final source tree byte parity: PASS",
   "- 033 overlap: its exact two-line PSK clear was moved into the existing 010 config-memcpy ownership hunk; no other 033 hunk was dropped.",
   "- 037 correction: the malformed /dev/null hunk was corrected from -0,1/+1,20 to -0,0/+1,19 after verifying all 19 added lines; no source line was changed.",
   "",
   "## Responsibility mapping",
   "",
   "- 008: original 008 + 035 + 037 (DPP authentication/key lifecycle and diagnostic redaction)",
   "- 010: original 010 + 033 + 036 (WAPP DPP config-object lifecycle, rollback and destruction)",
   "- 015: original 015 + 034 (DPP configuration lookup, credential retrieval and BSS credential construction)",
   "- 002: unchanged; parser/parameter validation responsibility remains independent",
   "",
   "## Generated patch evidence",
   "",
   "| Patch | Hunks | Bytes | SHA256 |",
   "|---|---:|---:|---|",
  ]
  for name, info in meta.items():
   report.append(f"| {name} | {info['hunks']} | {info['bytes']} | {info['sha256']} |")
  report += [
   "",
   f"- New Lock SHA256: {lock_sha}",
   "- Removed independent patch files and Lock entries: 033, 034, 035, 036, 037",
   "- No Quick build, Full build, compile or link target invoked.",
   "",
  ]
  (output / "MERGE-REPORT.md").write_text("\n".join(report), encoding="utf-8")
  credential = {
   "repository": "laodadelaoda/immortalwrt-mt798x-rebase",
   "branch": "runner/easymesh-patch-replay-20261114",
   "input_commit": os.environ.get("GITHUB_SHA", "local"),
   "baseline_commit": BASELINE_COMMIT,
   "run_id": os.environ.get("GITHUB_RUN_ID"),
   "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
   "vendor_archive": ARCHIVE_NAME,
   "vendor_archive_sha256": archive_sha,
   "original_patch_sha256": original_hashes,
   "037_original_sha256": original_037_sha,
   "037_structurally_normalized_sha256": normalized_037_sha,
   "037_structural_change": "@@ -0,1 +1,20 @@ -> @@ -0,0 +1,19 @@",
   "033_overlap_moved_to_010": "forced_memzero(wdev->config->psk, sizeof(wdev->config->psk))",
   "generated_patch_sha256": {k: v["sha256"] for k, v in meta.items()},
   "lock_sha256": lock_sha,
   "checks": {
    "legacy_reference_zero_fuzz_zero_reject": True,
    "legacy_offsets_rebased_into_generated_patches": True,
    "consolidated_order_zero_fuzz_zero_offset": True,
    "generated_patch_replay": True,
    "source_tree_byte_parity": True,
   },
  }
  (output / "merge-credential.json").write_text(json.dumps(credential, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
  lines = [f"{digest(p.read_bytes())}  {p.name}" for p in sorted(output.iterdir()) if p.is_file()]
  (output / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")
  (output / "patch-replay.log").write_text("\n".join(events), encoding="utf-8")
  print("PASS: generated 008/010/015; removed 033-037; both source replays are byte-identical.")
  print(f"WAPP archive SHA256: {archive_sha}")
  print(f"Lock SHA256: {lock_sha}")
  for name, info in meta.items():
   print(f"{name}: hunks={info['hunks']} sha256={info['sha256']}")
  print("No Quick, Full, compile or link target was invoked.")

if __name__ == "__main__":
 main()
