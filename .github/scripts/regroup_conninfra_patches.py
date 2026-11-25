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

def extract_function(root, name, only_path=None):
    pattern = re.compile(rb"\b" + re.escape(name.encode("ascii")) + rb"\s*\([^;{}]*?\)\s*\{", re.S)
    files = [root / only_path] if only_path else root.rglob("*")
    for path in files:
        if not path.is_file() or path.suffix not in {".c", ".h"}:
            continue
        data = path.read_bytes()
        for match in pattern.finditer(data):
            opening = data.find(b"{", match.start(), match.end())
            depth, state, escaped, i = 0, "code", False, opening
            while i < len(data):
                ch = data[i]
                nxt = data[i + 1] if i + 1 < len(data) else 0
                if state == "code":
                    if ch == 47 and nxt == 47:
                        state = "line"; i += 1
                    elif ch == 47 and nxt == 42:
                        state = "block"; i += 1
                    elif ch == 34:
                        state = "string"; escaped = False
                    elif ch == 39:
                        state = "char"; escaped = False
                    elif ch == 123:
                        depth += 1
                    elif ch == 125:
                        depth -= 1
                        if depth == 0:
                            start = data.rfind(b"\n", 0, match.start()) + 1
                            return path.relative_to(root).as_posix(), data[start:i + 1].decode("latin-1")
                elif state == "line":
                    if ch == 10:
                        state = "code"
                elif state == "block":
                    if ch == 42 and nxt == 47:
                        state = "code"; i += 1
                elif state in {"string", "char"}:
                    quote = 34 if state == "string" else 39
                    if escaped:
                        escaped = False
                    elif ch == 92:
                        escaped = True
                    elif ch == quote:
                        state = "code"
                i += 1
    return None

def find_function_end(data, name):
    pattern = re.compile(rb"\b" + re.escape(name.encode("ascii")) + rb"\s*\([^;{}]*?\)\s*\{", re.S)
    match = pattern.search(data)
    if not match:
        fail("function not found for lifecycle fix: " + name)
    opening = data.find(b"{", match.start(), match.end())
    depth, state, escaped, i = 0, "code", False, opening
    while i < len(data):
        ch = data[i]
        nxt = data[i + 1] if i + 1 < len(data) else 0
        if state == "code":
            if ch == 47 and nxt == 47:
                state = "line"; i += 1
            elif ch == 47 and nxt == 42:
                state = "block"; i += 1
            elif ch == 34:
                state = "string"; escaped = False
            elif ch == 39:
                state = "char"; escaped = False
            elif ch == 123:
                depth += 1
            elif ch == 125:
                depth -= 1
                if depth == 0:
                    return i + 1
        elif state == "line":
            if ch == 10:
                state = "code"
        elif state == "block":
            if ch == 42 and nxt == 47:
                state = "code"; i += 1
        elif state in {"string", "char"}:
            quote = 34 if state == "string" else 39
            if escaped:
                escaped = False
            elif ch == 92:
                escaped = True
            elif ch == quote:
                state = "code"
        i += 1
    fail("unterminated function while applying lifecycle fix: " + name)

def apply_op_history_lifecycle_fix(root):
    header_path = root / "base/include/osal.h"
    osal_path = root / "base/osal.c"
    thread_path = root / "base/msg_thread.c"
    header = header_path.read_bytes()
    osal = osal_path.read_bytes()
    thread = thread_path.read_bytes()

    if b"osal_op_history_deinit(" not in header:
        proto = b"void osal_op_history_init(struct osal_op_history *log_history, int queue_size);\n"
        if proto not in header:
            fail("osal_op_history_init prototype not found")
        header = header.replace(proto, proto + b"void osal_op_history_deinit(struct osal_op_history *log_history);\n", 1)

    if b"void osal_op_history_deinit(" not in osal:
        init_end = find_function_end(osal, "osal_op_history_init")
        init_work = b"\tINIT_WORK(&log_history->dump_work, osal_op_history_print_work);\n"
        if osal.count(init_work) != 1:
            fail("expected one op-history INIT_WORK")
        osal = osal.replace(init_work, b"", 1)
        init_start = osal.find(b"void osal_op_history_init")
        init_end = find_function_end(osal, "osal_op_history_init")
        init_body = osal[init_start:init_end]
        lock_init = b"\tspin_lock_init(&(log_history->lock));\n"
        if lock_init not in init_body:
            fail("op-history spinlock init not found")
        init_body = init_body.replace(lock_init, lock_init + init_work, 1)
        osal = osal[:init_start] + init_body + osal[init_end:]

        init_end = find_function_end(osal, "osal_op_history_init")
        insert_at = init_end
        if osal[insert_at:insert_at + 2] == b"\r\n":
            insert_at += 2
        elif osal[insert_at:insert_at + 1] == b"\n":
            insert_at += 1
        deinit = (
            b"\nvoid osal_op_history_deinit(struct osal_op_history *log_history)\n"
            b"{\n"
            b"\tstruct osal_op_history_entry *queue;\n"
            b"\tunsigned long flags;\n"
            b"\n"
            b"\tif (!log_history)\n"
            b"\t\treturn;\n"
            b"\n"
            b"\tspin_lock_irqsave(&log_history->lock, flags);\n"
            b"\tqueue = log_history->queue;\n"
            b"\tlog_history->queue = NULL;\n"
            b"\tlog_history->ring_buffer.base = NULL;\n"
            b"\tspin_unlock_irqrestore(&log_history->lock, flags);\n"
            b"\n"
            b"\tcancel_work_sync(&log_history->dump_work);\n"
            b"\tkfree(log_history->dump_ring_buffer.base);\n"
            b"\tlog_history->dump_ring_buffer.base = NULL;\n"
            b"\tkfree(queue);\n"
            b"}\n"
        )
        osal = osal[:insert_at] + deinit + osal[insert_at:]

    print_fn_start = osal.find(b"void osal_op_history_print(")
    if print_fn_start < 0:
        fail("osal_op_history_print definition not found")
    print_fn_end = find_function_end(osal, "osal_op_history_print")
    print_fn = osal[print_fn_start:print_fn_end]
    lock_line = b"\tspin_lock_irqsave(lock, flags);\n"
    recheck = (
        b"\tif (log_history->queue == NULL) {\n"
        b"\t\tspin_unlock_irqrestore(lock, flags);\n"
        b"\t\tkfree(queue);\n"
        b"\t\treturn;\n"
        b"\t}\n"
    )
    if recheck not in print_fn:
        if lock_line not in print_fn:
            fail("op-history print lock not found")
        print_fn = print_fn.replace(lock_line, lock_line + recheck, 1)
    old_schedule = (
        b"\tdump_ring_buffer->base = queue;\n"
        b"\tspin_unlock_irqrestore(lock, flags);\n"
        b"\tschedule_work(work);\n"
    )
    new_schedule = (
        b"\tdump_ring_buffer->base = queue;\n"
        b"\tschedule_work(work);\n"
        b"\tspin_unlock_irqrestore(lock, flags);\n"
    )
    if old_schedule in print_fn:
        print_fn = print_fn.replace(old_schedule, new_schedule, 1)
    elif new_schedule not in print_fn:
        fail("op-history print scheduling sequence not found")
    osal = osal[:print_fn_start] + print_fn + osal[print_fn_end:]

    if b"osal_op_history_deinit(&ctx->op_history);" not in thread:
        init_needle = (
            b"\t\tosal_thread_destroy(p_thread);\n"
            b"\t\tfor (i = 0; i < MSG_THREAD_OP_BUF_SIZE; i++)"
        )
        if init_needle not in thread:
            fail("msg_thread_init failure cleanup insertion point not found")
        thread = thread.replace(
            init_needle,
            b"\t\tosal_thread_destroy(p_thread);\n"
            b"\t\tosal_op_history_deinit(&ctx->op_history);\n"
            b"\t\tfor (i = 0; i < MSG_THREAD_OP_BUF_SIZE; i++)", 1)
        deinit_needle = (
            b"\t\treturn -1;\n"
            b"\t}\n\n"
            b"\tfor (i = 0; i < MSG_THREAD_OP_BUF_SIZE; i++)"
        )
        if deinit_needle not in thread:
            fail("msg_thread_deinit cleanup insertion point not found")
        thread = thread.replace(
            deinit_needle,
            b"\t\treturn -1;\n"
            b"\t}\n\n"
            b"\tosal_op_history_deinit(&ctx->op_history);\n\n"
            b"\tfor (i = 0; i < MSG_THREAD_OP_BUF_SIZE; i++)", 1)

    header_path.write_bytes(header)
    osal_path.write_bytes(osal)
    thread_path.write_bytes(thread)
    print("APPLIED: op-history queue and dump-work lifetime cleanup")

def emit_source_review(root):
    names = [
        "mtk_conninfra_probe", "mtk_conninfra_remove",
        "consys_hw_init", "consys_hw_deinit",
        "pmic_mng_init", "pmic_mng_deinit",
        "emi_mng_init", "emi_mng_deinit",
        "consys_reg_mng_init", "consys_reg_mng_deinit",
        "consys_reg_init", "consys_reg_deinit",
        "conninfra_core_init", "conninfra_core_deinit",
        "msg_thread_init", "msg_thread_deinit",
        "msg_op_history_save", "osal_op_history_print_work", "osal_op_history_dump",
        "osal_op_history_print", "msg_thread_dump",
        "consys_plt_clk_get_from_dts", "consys_plt_clk_detach",
    ]
    for name in names:
        found = extract_function(root, name)
        if not found:
            print("SOURCE REVIEW MISSING: " + name)
            continue
        rel, body = found
        lines = body.splitlines()
        print("===== SOURCE REVIEW " + name + " (" + rel + ") lines=" + str(len(lines)) + " =====")
        print("\n".join(lines[:160]))
        if len(lines) > 160:
            print("===== SOURCE REVIEW TRUNCATED " + name + " =====")

    specific_functions = [
        ("platform/mt7986/mt7986_pos.c", "consys_plt_hw_init"),
        ("platform/mt7986/mt7986_pos.c", "consys_plt_hw_deinit"),
        ("platform/mt7986/mt7986_pos.c", "consys_plt_clk_get_from_dts"),
        ("platform/mt7986/mt7986_pos.c", "consys_plt_clk_detach"),
        ("platform/mt7986/mt7986_consys_reg.c", "consys_reg_init"),
        ("platform/mt7986/mt7986_consys_reg.c", "consys_reg_deinit"),
        ("base/osal.c", "osal_op_history_init"),
        ("base/osal.c", "osal_op_history_deinit"),
        ("src/conninfra_dev.c", "conninfra_dev_init"),
        ("src/conninfra_dev.c", "conninfra_dev_deinit"),
    ]
    for rel, name in specific_functions:
        found = extract_function(root, name, rel)
        if found:
            source_path, body = found
            lines = body.splitlines()
            print("===== SOURCE REVIEW " + name + " exact path (" + source_path + ") lines=" + str(len(lines)) + " =====")
            print("\n".join(lines[:180]))
            if len(lines) > 180:
                print("===== SOURCE REVIEW TRUNCATED " + name + " =====")
        else:
            print("SOURCE REVIEW MISSING exact path: " + rel + " :: " + name)
    for rel in ["platform/mt7981/mt7981_consys_reg.c", "platform/mt7986/mt7986_consys_reg.c"]:
        found = extract_function(root, "consys_reg_init", rel)
        if found:
            source_path, body = found
            print("===== SOURCE REVIEW consys_reg_init exact path (" + source_path + ") =====")
            print(body)
    for file in root.rglob("*"):
        if file.is_file() and file.suffix in {".c", ".h"}:
            data = file.read_bytes()
            for line_no, line in enumerate(data.splitlines(), 1):
                if b"CFG_REG_LOAD_FROM_DTS_CTRL" in line:
                    print("CFG_REG_LOAD_FROM_DTS_CTRL " + file.relative_to(root).as_posix() + ":" + str(line_no) + " " + line.decode("latin-1"))

    for file in root.rglob("*"):
        if file.is_file() and file.suffix in {".c", ".h"}:
            for line_no, line in enumerate(file.read_bytes().splitlines(), 1):
                if any(token in line for token in (b"dump_ring_buffer", b"dump_work", b"osal_op_history", b"consys_plt_clk_")):
                    print("SOURCE OWNERSHIP REFERENCE " + file.relative_to(root).as_posix() + ":" + str(line_no) + " " + line.decode("latin-1"))

    staticized = {
        "base/ring.c": ["__ring_segment_prepare"],
        "base/osal.c": ["get_default_bin_image_file", "_osal_fifo_init", "_osal_fifo_deinit",
                        "_osal_fifo_size", "_osal_fifo_avail_size", "_osal_fifo_len",
                        "_osal_fifo_is_empty", "_osal_fifo_is_full", "_osal_fifo_data_in",
                        "_osal_fifo_data_out", "_osal_fifo_reset"],
        "base/msg_thread.c": ["msg_evt_put_op_to_free_queue", "msg_evt_get_free_op",
                              "msg_evt_put_op_to_active", "msg_op_history_save",
                              "msg_evt_wait_event_checker", "msg_evt_set_current_op",
                              "msg_evt_opid_handler"],
        "platform/consys_hw.c": ["consys_hw_dump_cpupcr"],
        "platform/mt7981/mt7981_pos.c": ["_is_flash_content_valid", "_consys_check_adie_cfg",
            "_consys_polling_chipid_int", "_connsys_a_die_cfg_7976", "_connsys_a_die_cfg_7975",
            "_consys_afe_wbg_cal_7976", "_consys_afe_wbg_cal_7975", "_connsys_subsys_pll_initial",
            "_consys_adie_top_ck_en_on_off_ctrl", "_consys_check_sku_cfg"],
        "platform/mt7986/mt7986_pos.c": ["_is_flash_content_valid", "_consys_check_adie_cfg",
            "_consys_polling_chipid_int", "_connsys_a_die_cfg_7976", "_connsys_a_die_cfg_7975",
            "_consys_afe_wbg_cal_7976", "_consys_afe_wbg_cal_7975", "_connsys_subsys_pll_initial",
            "_consys_adie_top_ck_en_on_off_ctrl", "_consys_check_sku_cfg", "_is_wmcpu_run_allow",
            "_connsys_a_die_chip_id_confirm"],
        "platform/mt7981/mt7981_emi.c": ["consys_emi_get_fw_emi_size"],
        "platform/mt7986/mt7986_emi.c": ["consys_emi_get_fw_emi_size"],
    }
    for owner, symbols in staticized.items():
        for symbol in symbols:
            external = []
            needle = re.compile(rb"\b" + re.escape(symbol.encode("ascii")) + rb"\b")
            for file in root.rglob("*"):
                if not file.is_file() or file.suffix not in {".c", ".h"}:
                    continue
                rel = file.relative_to(root).as_posix()
                if rel == owner:
                    continue
                data = file.read_bytes()
                own_definition = re.search(
                    rb"\b" + re.escape(symbol.encode("ascii")) + rb"\s*\([^;{}]*?\)\s*\{", data, re.S)
                if own_definition:
                    continue
                for match in needle.finditer(data):
                    line = data.count(b"\n", 0, match.start()) + 1
                    external.append(rel + ":" + str(line))
            if external:
                print("STATIC SYMBOL CROSS-FILE REFERENCE: " + symbol + " owner=" + owner +
                      " refs=" + ",".join(external[:12]))
            else:
                print("STATIC SYMBOL LOCAL-ONLY PASS: " + symbol + " owner=" + owner)

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
        apply_op_history_lifecycle_fix(patched)
        emit_source_review(patched)

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
