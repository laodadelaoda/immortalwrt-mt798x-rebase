#!/usr/bin/env python3
"""Validate the MT7530 base feature patch before its dependent hardening patch."""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-dsa-mt7530-netlink-base.py <linux-source-dir>")
root = Path(sys.argv[1])
dsa = root / "drivers/net/dsa"
required = ("mt7530.h", "mt7530_nl.c", "mt7530_nl.h", "mt7530-mdio.c", "mt7530-mmio.c")
missing = [name for name in required if not (dsa / name).is_file()]
if missing:
    raise SystemExit("FAIL: missing MT7530 base patch files: " + ", ".join(missing))

header = (dsa / "mt7530.h").read_text(errors="replace")
nl_header = (dsa / "mt7530_nl.h").read_text(errors="replace")
nl = (dsa / "mt7530_nl.c").read_text(errors="replace")
mdio = (dsa / "mt7530-mdio.c").read_text(errors="replace")
mmio = (dsa / "mt7530-mmio.c").read_text(errors="replace")

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

prototypes = re.findall(
    r"\bvoid\s+mt7530_write\s*\(\s*struct mt7530_priv\s*\*\s*priv\s*,\s*u32\s+reg\s*,\s*u32\s+val\s*\)\s*;",
    header,
)
require(len(prototypes) == 1,
        "base patch must declare mt7530_write exactly once (found %d)" % len(prototypes))
require(bool(re.search(r"\bint\s+mt7530_nl_init\s*\(\s*struct mt7530_priv\s*\*\s*\*\s*priv\s*\)\s*;", nl_header)),
        "base Netlink init declaration and pointer-to-pointer implementation contract differ")
require("int mt7530_nl_init(struct mt7530_priv **priv)" in nl,
        "base Netlink init definition has an unexpected signature")
require("void mt7530_nl_exit(void);" in nl_header and "void mt7530_nl_exit()" in nl,
        "base Netlink exit declaration/definition contract differs")
require(mdio.count("mt7530_nl_init(&priv)") == 1,
        "MDIO probe must initialize the base Netlink interface exactly once")
require(mmio.count("mt7530_nl_init(&priv)") == 1,
        "MMIO probe must initialize the base Netlink interface exactly once")
for name, source in (("MDIO", mdio), ("MMIO", mmio)):
    require("dsa_unregister_switch(priv->ds);" in source,
            name + " probe must roll back DSA registration when Netlink init fails")
print("PASS: MT7530 base patch declarations and probe contracts are internally consistent")
