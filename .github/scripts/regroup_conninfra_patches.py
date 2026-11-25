#!/usr/bin/env python3
# Regrouping is accepted only after strict GNU replay proves byte-for-byte parity.
from __future__ import annotations
import difflib, hashlib, json, os, re, shutil, subprocess, tarfile, tempfile, urllib.request
from pathlib import Path, PurePosixPath

ROOT = Path.cwd()
LOCK_PATH = ROOT / "package/mtk/vendor-sources.lock.json"
PATCH_DIR = ROOT / "package/mtk/drivers/conninfra/patches"
BRANCH = "n60pro-25.12-upstream-base"

def fail(message):
    raise SystemExit("FAIL: " + message)

def run(cmd, cwd=None):
    p = subprocess.run(cmd, cwd=cwd, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if p.returncode:
        fail("command failed: " + " ".join(map(str, cmd)) + "\n" + p.stdout)
    if re.search(r"\boffset\b|\bfuzz\b|FAILED|malformed patch|Reversed \(or previously applied\)", p.stdout, re.I):
        fail("non-zero-offset/fuzz or rejected patch:\n" + p.stdout)
    return p.stdout

def safe_extract(archive, dest):
    with tarfile.open(archive, "r:*") as tf:
        for member in tf.getmembers():
            name = PurePosixPath(member.name)
            if name.is_absolute() or ".." in name.parts:
                fail("unsafe archive member: " + member.name)
        tf.extractall(dest, filter="data")

def find_source_root(extracted):
    matches = []
    for header in extracted.rglob("base/include/osal.h"):
        candidate = header.parents[2]
        if (candidate / "platform/consys_hw.c").is_file() and (candidate / "src/conninfra_dev.c").is_file():
            matches.append(candidate)
    if len(matches) != 1:
        fail("expected exactly one Conninfra source root; found " + repr([str(x) for x in matches]))
    return matches[0]

def patch_targets(patch_text):
    if isinstance(patch_text, bytes):
        raw_targets = re.findall(rb"^--- a/([^\r\n]+)$", patch_text, re.M)
        targets = [item.decode("utf-8") for item in raw_targets]
    else:
        targets = re.findall(r"^--- a/(.+)$", patch_text, re.M)
    if not targets:
        fail("patch has no --- a/ target")
    return targets

def patch_name(rel):
    if rel == "Makefile":
        return "build-makefile.patch"
    parts = rel.split("/")
    stem = parts[-1].replace("_", "-").replace(".", "-")
    parents = parts[:-1]
    while parents and stem.startswith(parents[-1] + "-"):
        stem = stem[len(parents[-1]) + 1:]
    return "-".join(parents + [stem]) + ".patch"

def apply_series(source, patches):
    for patch in patches:
        output = run(["patch", "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(patch)], cwd=source)
        print(output, end="")

def main():
    lock = json.loads(LOCK_PATH.read_text(encoding="utf-8"))
    source = next((x for x in lock["sources"] if x["id"] == "conninfra"), None)
    series = next((x for x in lock["patch_sets"] if x["id"] == "conninfra"), None)
    if not source or not series:
        fail("Conninfra source or patch set missing from canonical Lock")
    if series["directory"] != "package/mtk/drivers/conninfra/patches":
        fail("unexpected Conninfra patch directory")
    old_order = list(series["application_order"])
    actual = sorted(p.name for p in PATCH_DIR.glob("*.patch"))
    if actual != sorted(old_order) or len(actual) != len(old_order):
        fail("current Conninfra patch inventory does not match Lock")

    with tempfile.TemporaryDirectory(prefix="conninfra-regroup-") as td:
        temp = Path(td)
        archive = temp / source["archive"]
        request = urllib.request.Request(source["url"], headers={"User-Agent": "N60-Conninfra-Patch-Regroup/1"})
        with urllib.request.urlopen(request, timeout=180) as response, archive.open("wb") as out:
            shutil.copyfileobj(response, out)
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != source["sha256"]:
            fail("Conninfra archive SHA256 mismatch: " + digest)

        extracted = temp / "extract"
        extracted.mkdir()
        safe_extract(archive, extracted)
        pristine_root = find_source_root(extracted)
        pristine = temp / "pristine"
        shutil.copytree(pristine_root, pristine)
        patched = temp / "patched"
        shutil.copytree(pristine_root, patched)

        original_patches = [PATCH_DIR / name for name in old_order]
        touched = []
        for patch in original_patches:
            text = patch.read_text(encoding="utf-8")
            for rel in patch_targets(text):
                if rel not in touched:
                    touched.append(rel)
        apply_series(patched, original_patches)

        generated = temp / "generated"
        generated.mkdir()
        names = []
        for rel in touched:
            before = pristine / rel
            after = patched / rel
            if not before.is_file() or not after.is_file():
                fail("touched source file missing before/after replay: " + rel)
            old = before.read_bytes().splitlines(keepends=True)
            new = after.read_bytes().splitlines(keepends=True)
            diff = b"".join(difflib.diff_bytes(
                difflib.unified_diff, old, new,
                fromfile=("a/" + rel).encode("ascii"),
                tofile=("b/" + rel).encode("ascii"), n=3))
            if not diff:
                continue
            name = patch_name(rel)
            if name in names:
                fail("stable patch filename collision: " + name)
            if len(re.findall(rb"^--- a/", diff, re.M)) != 1:
                fail("generated patch does not target exactly one source file: " + name)
            (generated / name).write_bytes(diff)
            names.append(name)

        names.sort()
        replay = temp / "replay"
        shutil.copytree(pristine, replay)
        apply_series(replay, [generated / name for name in names])
        for rel in touched:
            if (patched / rel).read_bytes() != (replay / rel).read_bytes():
                fail("regrouped patch replay differs from original series: " + rel)

        if len(names) != len(touched):
            fail("not every touched source file produced exactly one patch")
        if len(list(generated.glob("*.patch"))) != len(names):
            fail("unexpected generated patch count")

        for old in PATCH_DIR.glob("*.patch"):
            old.unlink()
        for new in generated.glob("*.patch"):
            shutil.copy2(new, PATCH_DIR / new.name)
        series["application_order"] = names
        LOCK_PATH.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

        # Verify the canonical Lock inventory and native lexical order.
        actual_after = sorted(p.name for p in PATCH_DIR.glob("*.patch"))
        if actual_after != names:
            fail("new patch inventory does not match sorted Lock order")
        for patch in PATCH_DIR.glob("*.patch"):
            targets = patch_targets(patch.read_bytes())
            if len(targets) != 1:
                fail("one-file-per-patch invariant failed: " + patch.name)

    run(["git", "add", "--", str(PATCH_DIR.relative_to(ROOT)), str(LOCK_PATH.relative_to(ROOT))], cwd=ROOT)
    status = subprocess.run(["git", "status", "--porcelain"], cwd=ROOT, text=True, stdout=subprocess.PIPE).stdout
    if not status.strip():
        print("Conninfra patch series already normalized; no commit required.")
        return
    run(["git", "config", "user.name", "github-actions[bot]"], cwd=ROOT)
    run(["git", "config", "user.email", "41898282+github-actions[bot]@users.noreply.github.com"], cwd=ROOT)
    run(["git", "commit", "-m", "refactor(conninfra): consolidate patches by source file"], cwd=ROOT)
    run(["git", "push", "origin", "HEAD:refs/heads/" + BRANCH], cwd=ROOT)
    print("PASS: Conninfra patches consolidated by source file; original and regenerated series are byte-identical.")
    print("PATCH_COUNT=" + str(len(names)))
    print("PATCH_ORDER=" + ",".join(names))

if __name__ == "__main__":
    main()
