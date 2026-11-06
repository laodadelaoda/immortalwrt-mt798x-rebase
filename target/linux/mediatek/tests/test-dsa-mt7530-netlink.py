#!/usr/bin/env python3
"""Source-level safety contract for the MediaTek MT7530 Generic Netlink patch stack.

Run against the real, fully patched Linux source tree produced by OpenWrt
Kernel/Prepare. This is deliberately a pre-configuration, no-compile gate.
"""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-dsa-mt7530-netlink.py <linux-source-dir>")

root = Path(sys.argv[1])
dsa = root / "drivers/net/dsa"
required = [
    dsa / "mt7530.c",
    dsa / "mt7530.h",
    dsa / "mt7530-mdio.c",
    dsa / "mt7530-mmio.c",
    dsa / "mt7530_nl.c",
    dsa / "mt7530_nl.h",
]
missing = [str(p) for p in required if not p.is_file()]
if missing:
    raise SystemExit("FAIL: MT7530 DSA/Netlink source files missing: " + ", ".join(missing))

def body(source: str, signature: str) -> str:
    start = source.find(signature)
    if start < 0:
        return ""
    brace = source.find("{", start)
    if brace < 0:
        return ""
    depth = 0
    for pos in range(brace, len(source)):
        if source[pos] == "{":
            depth += 1
        elif source[pos] == "}":
            depth -= 1
            if depth == 0:
                return source[brace:pos + 1]
    return ""

def check(ok: bool, message: str) -> None:
    if not ok:
        failures.append(message)

failures = []
header = (dsa / "mt7530.h").read_text(errors="replace")
nl = (dsa / "mt7530_nl.c").read_text(errors="replace")
mdio = (dsa / "mt7530-mdio.c").read_text(errors="replace")
mmio = (dsa / "mt7530-mmio.c").read_text(errors="replace")

# Public declarations must be unique and match the implementation signatures.
write_decl = re.findall(r"\bvoid\s+mt7530_write\s*\(\s*struct mt7530_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s+val\s*\)\s*;", header)
check(len(write_decl) == 1, f"mt7530_write prototype must occur once; found {len(write_decl)}")

init = body(nl, "int mt7530_nl_init")
exit_body = body(nl, "void mt7530_nl_exit")
response = body(nl, "static int mt7530_nl_response")
check(bool(init), "mt7530_nl_init implementation missing")
check(bool(exit_body), "mt7530_nl_exit implementation missing")
check(bool(response), "mt7530_nl_response implementation missing")

# Registration failure must never publish a pointer to an unregistered or
# failed device. The family must be unregistered before its private pointer
# is cleared, with callback synchronization protecting teardown.
reg = init.find("genl_register_family")
publish = init.find("sw_priv =")
check(reg >= 0 and publish > reg, "Netlink init publishes sw_priv before successful family registration")
check("if (ret)" in init and "sw_priv =" in init, "Netlink init does not conditionally publish the device after registration")
unreg = exit_body.find("genl_unregister_family")
clear = exit_body.find("sw_priv = NULL")
check(unreg >= 0 and clear > unreg, "Netlink exit clears sw_priv before unregistering the family")
check("mutex_lock" in exit_body and "mutex_unlock" in exit_body, "Netlink teardown does not synchronize against in-flight callbacks")
check("if (!sw_priv)" in response or "if (!READ_ONCE(sw_priv))" in response, "Netlink request handler lacks a null-device guard")

# Both probe paths share one Generic Netlink family. A failed second probe
# must not overwrite the already-registered device context.
check("mt7530_nl_init(&priv)" in mdio and "mt7530_nl_init(&priv)" in mmio, "MDIO/MMIO probe paths do not both use the audited Netlink initializer")
mdio_remove = body(mdio, "mt7530_remove")
mmio_remove = body(mmio, "static void mt7988_remove")
check(mdio_remove.find("mt7530_nl_exit") >= 0 and mdio_remove.find("mt7530_nl_exit") < mdio_remove.find("mt7530_remove_common"), "MDIO remove frees MT7530 resources before Netlink teardown")
check(mmio_remove.find("mt7530_nl_exit") >= 0 and mmio_remove.find("mt7530_nl_exit") < mmio_remove.find("mt7530_remove_common"), "MMIO remove frees MT7530 resources before Netlink teardown")

# Reject unchecked PHY/register operations and missing bounds validation.
read = body(nl, "static int mt7530_nl_reply_read")
write = body(nl, "static int mt7530_nl_reply_write")
check(bool(re.search(r"phy\s*<\s*0\s*\|\|\s*phy\s*>=", read + write), "Netlink PHY operations lack explicit PHY-index bounds checks")
check(bool(re.search(r"devad\s*<\s*0\s*\|\|\s*devad\s*>=", read + write), "Netlink Clause-45 operations lack explicit DEVAD bounds checks")
check(bool(re.search(r"reg\s*>=", read + write), "Netlink register operations lack an upper-bound check")
for call in ("mt7531_ind_c22_phy_write", "mt7531_ind_c45_phy_write"):
    check(bool(re.search(r"ret\s*=\s*" + call + r"\s*\(", write) or re.search(r"if\s*\(\s*" + call + r"\s*\(", write), f"{call} return value is ignored")
check(bool(re.search(r"ret\s*=\s*mt7530_write\s*\(", write) or re.search(r"if\s*\(\s*mt7530_write\s*\(", write), "MT7530 register-write path does not propagate hardware access errors")

if failures:
    print("MT7530 DSA/Generic Netlink source audit: FAIL")
    for item in failures:
        print(" - " + item)
    raise SystemExit(1)

print("MT7530 DSA/Generic Netlink source audit: PASS")
