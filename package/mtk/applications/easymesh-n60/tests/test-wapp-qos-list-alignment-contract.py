#!/usr/bin/env python3
"""Regression contract for WAPP QoS intrusive-list container alignment."""
from pathlib import Path
import re
import sys

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

if len(sys.argv) != 2:
    raise SystemExit("usage: test-wapp-qos-list-alignment-contract.py <easymesh-build-dir>")

root = Path(sys.argv[1])
header = root / "wappd/include/qos.h"
source = root / "wappd/qos/qos.c"
list_header = root / "wappd/include/list.h"
for path in (header, source, list_header):
    require(path.is_file(), f"required QoS source is missing: {path}")

h = header.read_text(encoding="utf-8")
c = source.read_text(encoding="utf-8")
lists = list_header.read_text(encoding="utf-8")

# These are heap-allocated in-memory intrusive-list containers, not packed
# wire-format records. Their first member must be the naturally aligned list.
for name in ("mscs_configuration", "scs_configuration", "dscp_policy_db"):
    match = re.search(
        rf"struct\s+(?:GNU_PACKED\s+)?{name}\s*\{{(?P<body>.*?)\n\}};",
        h, re.S
    )
    require(match is not None, f"{name} declaration is missing")
    declaration = h[match.start():match.end()]
    require(not re.search(r"struct\s+GNU_PACKED\s+" + name, declaration),
            f"{name} must not be packed: its dl_list contains native pointers")
    members = [line.strip() for line in match.group("body").splitlines()
               if line.strip() and not line.strip().startswith("/*")
               and not line.strip().startswith("*")]
    require(bool(members) and members[0] == "struct dl_list list;",
            f"{name}.list must remain the first member at offset zero")

require(re.search(r"struct\s+dl_list\s*\{\s*struct\s+dl_list\s*\*next;\s*struct\s+dl_list\s*\*prev;", lists, re.S) is not None,
        "dl_list must retain native pointer members")
for token in (
    "dl_list_for_each_safe(mscscfg, mscscfg_tmp, &mscs_cfg_list",
    "dl_list_for_each_safe(scscfg, scscfg_tmp, &scs_cfg_list",
    "dl_list_for_each_safe(pos, pos_tmp, &dscp_policy_list",
    "os_zalloc(sizeof(struct mscs_configuration))",
    "os_zalloc(sizeof(struct scs_configuration))",
    "os_zalloc(sizeof(struct dscp_policy_db))",
):
    require(token in c, f"QoS list ownership/allocation contract changed: {token}")

# The complete container objects are used only as internal state; verify there
# is no raw network serialization of these list-bearing structures.
for name in ("mscs_configuration", "scs_configuration", "dscp_policy_db"):
    require(not re.search(r"(?:send|write|memcpy)\s*\([^;]*sizeof\s*\(\s*struct\s+" + name, c, re.S),
            f"{name} appears to be serialized/copied as an external wire object")

print("PASS: MSCS/SCS/DSCP QoS list containers retain native dl_list alignment and internal-only ownership.")
