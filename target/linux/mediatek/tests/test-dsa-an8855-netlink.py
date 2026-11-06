#!/usr/bin/env python3
"""Pre-configuration source contract for AN8855 Generic Netlink and procfs."""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-dsa-an8855-netlink.py <linux-source-dir>")

root = Path(sys.argv[1])
dsa = root / "drivers/net/dsa"
required = ("an8855.c", "an8855.h", "an8855_nl.c", "an8855_nl.h")
missing = [name for name in required if not (dsa / name).is_file()]
if missing:
    raise SystemExit("FAIL: missing patched AN8855 source: " + ", ".join(missing))

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

source = (dsa / "an8855.c").read_text(errors="replace")
header = (dsa / "an8855.h").read_text(errors="replace")
nl = (dsa / "an8855_nl.c").read_text(errors="replace")
nl_header = (dsa / "an8855_nl.h").read_text(errors="replace")

# Register I/O must return errno separately from register data.
check(bool(re.search(r"\bint\s+an8855_read\s*\(\s*struct an8855_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s*\*\s*val\s*\)", header)),
      "AN8855 read declaration must return int and provide a value output pointer")
check(bool(re.search(r"\bint\s+an8855_read\s*\(\s*struct an8855_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s*\*\s*val\s*\)", source)),
      "AN8855 read implementation signature is inconsistent")
check("return regmap_read(priv->regmap, reg, val);" in source,
      "AN8855 read must propagate regmap errno without converting it to unsigned data")
check("u32 an8855_read(" not in source + header,
      "Legacy unsigned AN8855 read API remains")
check(bool(re.search(r"\bint\s+an8855_write\s*\(\s*struct an8855_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s+val\s*\)", header)),
      "AN8855 write declaration must propagate errno")
check("return regmap_write(priv->regmap, reg, val);" in source,
      "AN8855 write must propagate regmap errno")

# Netlink access must validate all externally supplied selectors before I/O.
validate = function(nl, "an8855_nl_validate_access")
read_fn = function(nl, "an8855_nl_reply_read")
write_fn = function(nl, "an8855_nl_reply_write")
check(bool(validate), "AN8855 Netlink access validator is missing")
for expression, label in (
    (r"phy\s*<\s*-1", "negative PHY selector"),
    (r"phy\s*>=\s*priv->ds->num_ports", "PHY upper bound"),
    (r"devad\s*<\s*-1", "negative DEVAD selector"),
    (r"devad\s*>\s*31", "DEVAD upper bound"),
    (r"reg\s*>\s*0xffff", "register upper bound"),
    (r"reg\s*&\s*0x3", "register alignment"),
):
    check(bool(re.search(expression, validate)), "AN8855 access validator lacks " + label)
check("value > U16_MAX" in write_fn, "AN8855 PHY writes must reject values wider than 16 bits")
check(bool(re.search(r"ret\s*=\s*an8855_read\s*\(", read_fn)) and
      bool(re.search(r"if\s*\(\s*ret\s*\)", read_fn)),
      "AN8855 Netlink read does not propagate register read errors")
for name in ("an8855_phy_cl22_write", "an8855_phy_cl45_write"):
    check(bool(re.search(r"ret\s*=\s*" + name + r"\s*\(", write_fn)),
          name + " result is not checked")

# Family registration and device lifetime must be synchronized.
check("int an8855_nl_init(struct an8855_priv *priv);" in nl_header,
      "AN8855 Netlink init prototype must take struct an8855_priv *")
check("void an8855_nl_exit(struct an8855_priv *priv);" in nl_header,
      "AN8855 Netlink exit prototype must take struct an8855_priv *")
init = function(nl, "an8855_nl_init")
exit_fn = function(nl, "an8855_nl_exit")
response = function(nl, "an8855_nl_response")
check(bool(init) and "genl_register_family" in init and
      init.find("genl_register_family") < init.find("an8855_sw_priv = priv"),
      "AN8855 device pointer must be published only after family registration succeeds")
check(bool(exit_fn) and "genl_unregister_family" in exit_fn and
      "an8855_nl_unregistering" in exit_fn,
      "AN8855 family teardown must be serialized and unregister the family")
check(bool(response) and "if (!an8855_sw_priv)" in response,
      "AN8855 request handler lacks a null-device guard")

# Procfs creation failure must unwind, and probe/remove order must be symmetric.
proc_init = function(source, "an8855_proc_device_init")
proc_exit = function(source, "an8855_proc_device_exit")
probe = function(source, "an8855_switch_probe")
remove = function(source, "an8855_switch_remove")
check("if (!proc_an8855_dsa_dir)" in proc_init and "return -ENOMEM" in proc_init,
      "AN8855 proc_mkdir failure is not propagated")
check("if (!proc_create" in proc_init and "proc_remove(proc_an8855_dsa_dir)" in proc_init,
      "AN8855 proc_create failure does not unwind the procfs directory")
check("proc_remove(proc_an8855_dsa_dir)" in proc_exit and
      "proc_an8855_dsa_dir = NULL" in proc_exit,
      "AN8855 procfs teardown does not remove and clear its directory")
check("ret = an8855_nl_init(priv)" in probe and "ret = an8855_proc_device_init()" in probe,
      "AN8855 probe does not check both Netlink and procfs initialization")
check("an8855_nl_exit(priv)" in probe and "dsa_unregister_switch" in probe,
      "AN8855 probe failure does not unwind Netlink and DSA registration")
check(remove.find("an8855_nl_exit(priv)") >= 0 and
      remove.find("an8855_nl_exit(priv)") < remove.find("dsa_unregister_switch"),
      "AN8855 remove releases DSA state before Netlink teardown")
check(remove.find("an8855_proc_device_exit()") >= 0 and
      remove.find("an8855_proc_device_exit()") < remove.find("dsa_unregister_switch"),
      "AN8855 remove releases DSA state before procfs teardown")

if failures:
    for item in failures:
        print("FAIL: " + item, file=sys.stderr)
    raise SystemExit(1)
print("PASS: AN8855 Netlink bounds, errno propagation, registration and procfs lifecycle")
