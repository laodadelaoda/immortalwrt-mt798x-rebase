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
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;]*?\)\s*\{", source, re.S)
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
nl_header = (dsa / "mt7530_nl.h").read_text(errors="replace")
check("int mt7530_nl_init(struct mt7530_priv *priv);" in nl_header,
      "MT7530 Netlink init declaration does not match the audited implementation")
check("void mt7530_nl_exit(struct mt7530_priv *priv);" in nl_header,
      "MT7530 Netlink exit declaration does not match the audited implementation")
check("int mt7530_nl_init(struct mt7530_priv *priv)" in nl,
      "MT7530 Netlink init definition has a mismatched signature")
check("void mt7530_nl_exit(struct mt7530_priv *priv)" in nl,
      "MT7530 Netlink exit definition has a mismatched signature")

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


# AN8855 is another active DSA Generic Netlink implementation in this patch
# stack. Audit it independently; do not assume the MT7530 checks cover it.
an8855_c = (dsa / "an8855.c").read_text(errors="replace")
an8855_h = (dsa / "an8855.h").read_text(errors="replace")
an8855_nl = (dsa / "an8855_nl.c").read_text(errors="replace")
an8855_nlh = (dsa / "an8855_nl.h").read_text(errors="replace")

an_init = function(an8855_nl, "an8855_nl_init")
an_exit = function(an8855_nl, "an8855_nl_exit")
an_response = function(an8855_nl, "an8855_nl_response")
an_validate = function(an8855_nl, "an8855_nl_validate_access")
an_read = function(an8855_nl, "an8855_nl_reply_read")
an_write = function(an8855_nl, "an8855_nl_reply_write")
check(bool(an_init), "AN8855 Netlink init implementation is missing")
check(bool(an_exit), "AN8855 Netlink exit implementation is missing")
check(bool(an_response), "AN8855 Netlink response implementation is missing")
check(an_init.find("genl_register_family") >= 0 and
      an_init.find("an8855_sw_priv = priv") > an_init.find("genl_register_family"),
      "AN8855 publishes its private pointer before successful family registration")
check("if (!ret)" in an_init and "return ret" in an_init,
      "AN8855 Netlink init does not propagate family-registration failure")
check(an_exit.find("genl_unregister_family") >= 0 and
      an_exit.find("an8855_sw_priv = NULL") > an_exit.find("genl_unregister_family"),
      "AN8855 clears its private pointer before family unregistration")
check("mutex_lock" in an_exit or "an8855_lock" in an_exit,
      "AN8855 Netlink teardown is not synchronized")
check("if (!an8855_sw_priv)" in an_response,
      "AN8855 Netlink handler lacks a null-device guard")
check("an8855_nl_init(priv)" in an8855_c,
      "AN8855 probe does not use the audited Netlink initializer")
an_probe = function(an8855_c, "an8855_switch_probe")
an_remove = function(an8855_c, "an8855_switch_remove")
check("ret = an8855_proc_device_init()" in an_probe and "if (ret)" in an_probe,
      "AN8855 probe does not unwind when procfs creation fails")
check(an_remove.find("an8855_nl_exit(priv)") >= 0 and
      an_remove.find("an8855_nl_exit(priv)") < an_remove.find("dsa_unregister_switch"),
      "AN8855 removes the DSA switch before Netlink teardown")
proc_init = function(an8855_c, "an8855_proc_device_init")
proc_exit = function(an8855_c, "an8855_proc_device_exit")
check("proc_create" in proc_init and "proc_remove" in proc_init,
      "AN8855 procfs creation is not transactional")
check("proc_remove" in proc_exit,
      "AN8855 procfs teardown does not remove its owned subtree")
read_api = function(an8855_c, "an8855_read")
write_api = function(an8855_c, "an8855_write")
check("return regmap_read" in read_api,
      "AN8855 register-read API does not propagate regmap errors")
check("return regmap_write" in write_api,
      "AN8855 register-write API does not propagate regmap errors")
check("an8855_read(struct an8855_priv *priv, u32 reg, u32 *val)" in an8855_h,
      "AN8855 register-read declaration does not expose an error return/out value")
check("int an8855_write(struct an8855_priv *priv" in an8855_h,
      "AN8855 register-write declaration does not expose an error return")
check(bool(re.search(r"phy\s*<\s*-1\s*\|\|\s*phy\s*>=", an_validate)),
      "AN8855 Netlink PHY index lacks bounds validation")
check(bool(re.search(r"devad\s*<\s*-1\s*\|\|\s*devad\s*>", an_validate)),
      "AN8855 Netlink DEVAD lacks bounds validation")
check(bool(re.search(r"reg\s*>", an_validate)),
      "AN8855 Netlink register address lacks bounds validation")
check(bool(re.search(r"ret\s*=\s*an8855_phy_cl22_write\s*\(", an_write)),
      "AN8855 Clause-22 PHY write return value is ignored")
check(bool(re.search(r"ret\s*=\s*an8855_phy_cl45_write\s*\(", an_write)),
      "AN8855 Clause-45 PHY write return value is ignored")
check(bool(re.search(r"ret\s*=\s*an8855_write\s*\(", an_write)),
      "AN8855 switch-register write return value is ignored")
check("AN8855_CMD_REQUEST" not in an8855_nl[an8855_nl.index("static const struct genl_ops"):an8855_nl.index("static struct genl_family")],
      "AN8855 advertises an unsupported REQUEST operation")

check("int an8855_nl_init(struct an8855_priv *priv);" in an8855_nlh,
      "AN8855 Netlink init declaration does not match the audited implementation")
check("void an8855_nl_exit(struct an8855_priv *priv);" in an8855_nlh,
      "AN8855 Netlink exit declaration does not match the audited implementation")
check("an8855_nl_init(struct an8855_priv *priv)" in an8855_nl,
      "AN8855 Netlink init definition has a mismatched signature")
check("an8855_nl_exit(struct an8855_priv *priv)" in an8855_nl,
      "AN8855 Netlink exit definition has a mismatched signature")

if failures:
    print("MT7530 DSA/Generic Netlink source audit: FAIL")
    for item in failures:
        print(" - " + item)
    raise SystemExit(1)

print("MT7530 DSA/Generic Netlink source audit: PASS")
