#!/usr/bin/env python3
"""Pre-configuration source contract for the patched MT7530 Generic Netlink API."""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-dsa-mt7530-netlink.py <linux-source-dir>")

root = Path(sys.argv[1])
dsa = root / "drivers/net/dsa"
required = ("mt7530.c", "mt7530.h", "mt7530-mdio.c", "mt7530-mmio.c",
            "mt7530_nl.c", "mt7530_nl.h")
missing = [name for name in required if not (dsa / name).is_file()]
if missing:
    raise SystemExit("FAIL: missing patched MT7530 source: " + ", ".join(missing))

def function(source, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\\([^;]*?\\)\\s*\\{", source, re.S)
    if not match:
        return ""
    opening = source.find("{", match.start())
    depth = 0
    for i in range(opening, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[opening:i + 1]
    return ""

failures = []
def check(condition, message):
    if not condition:
        failures.append(message)

header = (dsa / "mt7530.h").read_text(errors="replace")
nl = (dsa / "mt7530_nl.c").read_text(errors="replace")
mdio = (dsa / "mt7530-mdio.c").read_text(errors="replace")
mmio = (dsa / "mt7530-mmio.c").read_text(errors="replace")

# Declaration, implementation and family lifecycle.
decls = re.findall(r"\bvoid\s+mt7530_write\s*\(\s*struct mt7530_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s+val\s*\)\s*;", header)
check(len(decls) == 1, f"mt7530_write prototype must occur exactly once (found {len(decls)})")

init = function(nl, "mt7530_nl_init")
exit_fn = function(nl, "mt7530_nl_exit")
response = function(nl, "mt7530_nl_response")
check(bool(init), "mt7530_nl_init is missing")
check(bool(exit_fn), "mt7530_nl_exit is missing")
check(bool(response), "mt7530_nl_response is missing")

register_pos = init.find("genl_register_family")
publish_pos = init.find("sw_priv =")
check(register_pos >= 0 and publish_pos > register_pos,
      "sw_priv is published before Generic Netlink family registration succeeds")
check("if (!ret)" in init and "return ret" in init,
      "mt7530_nl_init does not propagate family-registration failure")
unregister_pos = exit_fn.find("genl_unregister_family")
clear_pos = exit_fn.find("sw_priv = NULL")
check(unregister_pos >= 0 and clear_pos > unregister_pos,
      "sw_priv is cleared before the Generic Netlink family is unregistered")
check("mutex_lock" in exit_fn and "mutex_unlock" in exit_fn,
      "Netlink teardown is not synchronized against in-flight handlers")
check("if (!sw_priv)" in response or "if (!READ_ONCE(sw_priv))" in response,
      "Netlink request handler has no null-device guard")

# Both probe paths must initialize the same interface; teardown must precede
# release of the hardware/private state.
check("mt7530_nl_init(priv)" in mdio, "MDIO probe does not initialize MT7530 Netlink")
check("mt7530_nl_init(priv)" in mmio, "MMIO probe does not initialize MT7530 Netlink")
mdio_remove = function(mdio, "mt7530_remove")
mmio_remove = function(mmio, "mt7988_remove")
check(mdio_remove.find("mt7530_nl_exit") >= 0 and
      mdio_remove.find("mt7530_nl_exit") < mdio_remove.find("mt7530_remove_common"),
      "MDIO remove releases MT7530 resources before Netlink teardown")
check(mmio_remove.find("mt7530_nl_exit") >= 0 and
      mmio_remove.find("mt7530_nl_exit") < mmio_remove.find("mt7530_remove_common"),
      "MMIO remove releases MT7530 resources before Netlink teardown")

# User-supplied register and PHY selectors must be bounded before access.
read_fn = function(nl, "mt7530_nl_reply_read")
write_fn = function(nl, "mt7530_nl_reply_write")
validate_fn = function(nl, "mt7530_nl_validate_access")
operations = validate_fn + read_fn + write_fn
check(bool(re.search(r"phy\s*<\s*-1\s*\|\|\s*phy\s*>=", operations)),
      "Netlink PHY operations lack an explicit upper-bound check")
check(bool(re.search(r"devad\s*<\s*-1\s*\|\|\s*devad\s*>", operations)),
      "Netlink Clause-45 DEVAD lacks an explicit upper-bound check")
check(bool(re.search(r"reg\s*>", operations)),
      "Netlink register address lacks an explicit upper-bound check")

# PHY write helpers return errors; do not acknowledge a failed hardware write.
for name in ("mt7531_ind_c22_phy_write", "mt7531_ind_c45_phy_write"):
    checked = (re.search(r"ret\s*=\s*" + name + r"\s*\(", write_fn) or
               re.search(r"if\s*\(\s*" + name + r"\s*\(", write_fn))
    check(bool(checked), name + " return value is ignored")

if failures:
    print("MT7530 DSA/Generic Netlink source audit: FAIL")
    for item in failures:
        print(" - " + item)
    raise SystemExit(1)

print("MT7530 DSA/Generic Netlink source audit: PASS")
