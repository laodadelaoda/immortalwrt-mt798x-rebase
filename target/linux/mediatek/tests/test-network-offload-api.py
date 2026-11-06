#!/usr/bin/env python3
"""Targeted Linux 6.12 API and ownership contracts for Ethernet/HNAT/PPE/NPU/TNL."""
from pathlib import Path
import re
import sys

if len(sys.argv) != 2:
    raise SystemExit("usage: test-network-offload-api.py <prepared-linux-source>")

root = Path(sys.argv[1])
failures = []
reviews = []

def check(condition, message):
    if not condition:
        failures.append(message)

def read(rel):
    path = root / rel
    if not path.is_file():
        failures.append("missing prepared source: " + rel)
        return ""
    return path.read_text(errors="replace")

def body(text, name):
    match = re.search(r"\b" + re.escape(name) + r"\s*\([^;{}]*\)\s*\{", text, re.S)
    if not match:
        return ""
    start = text.find("{", match.start())
    depth = 0
    for pos in range(start, len(text)):
        if text[pos] == "{":
            depth += 1
        elif text[pos] == "}":
            depth -= 1
            if depth == 0:
                return text[start:pos + 1]
    return ""

xfrm_h = read("include/net/xfrm.h")
dst_h = read("include/net/dst.h")
neigh_h = read("include/net/neighbour.h")
flow_h = read("include/net/flow_offload.h")
netdev_h = read("include/linux/netdevice.h")
flow_table_h = read("include/net/netfilter/nf_flow_table.h")
ppp_h = read("include/linux/ppp_channel.h")

for symbol, header in (
    ("xfrm_state_lookup_byaddr", xfrm_h),
    ("xfrm_state_put", xfrm_h),
    ("dst_xfrm", xfrm_h + dst_h),
    ("dst_release", dst_h),
    ("sk_dst_get", dst_h),
    ("dst_neigh_lookup", dst_h + neigh_h),
    ("neigh_ha_snapshot", neigh_h),
    ("ip_rt_put", read("include/net/route.h")),
    ("flow_action_entry_next", flow_h),
):
    check(bool(re.search(r"\b" + re.escape(symbol) + r"\s*\(", header)),
          "Linux 6.12 header declaration/inline missing: " + symbol)

check("ndo_flow_offload_check" in netdev_h,
      "net_device_ops lacks the HNAT ndo_flow_offload_check extension")
check("DEV_PATH_TNL" in netdev_h and "DEV_PATH_L2TP" in netdev_h and "DEV_PATH_PPTP" in netdev_h,
      "net_device_path enum lacks one or more TNL/NPU path types")
check("mtk_flow_tnl_offloadable" in netdev_h,
      "netdevice tunnel-offload eligibility hook is absent")
check("struct flow_offload_hw_path" in flow_table_h and "FLOW_OFFLOAD_TNL_L2TP_V2" in flow_table_h,
      "HNAT/TNL flow_offload_hw_path contract is incomplete")
check("FLOW_ACTION_NPU_ENCAP" in flow_h and "npu_entry" in flow_h,
      "NPU flow action contract is absent from flow_offload.h")
check("flow_offload_check" in ppp_h and "fill_forward_path" in ppp_h,
      "PPP channel callback extensions are missing")
check("sock_put()" in read("include/linux/ppp_channel.h"),
      "PPP socket helper contract does not document the required socket reference release")

xfrm_state = ""
m = re.search(r"struct xfrm_state\s*\{", xfrm_h)
if m:
    start = xfrm_h.find("{", m.start())
    depth = 0
    for pos in range(start, len(xfrm_h)):
        if xfrm_h[pos] == "{":
            depth += 1
        elif xfrm_h[pos] == "}":
            depth -= 1
            if depth == 0:
                xfrm_state = xfrm_h[start:pos + 1]
                break
check(bool(xfrm_state) and all(field in xfrm_state for field in ("mark", "id", "props")),
      "Linux XFRM state layout lacks fields consumed by the PPE rekey lookup")

l2tp = read("net/l2tp/l2tp_ppp.c")
l2tp_path = body(l2tp, "pppol2tp_fill_forward_path")
check("sk_dst_get" in l2tp_path and "dst_xfrm(dst)" in l2tp_path,
      "L2TP forward-path callback does not obtain and classify a referenced dst")
check("path->tunnel.dst = dst" in l2tp_path and "dst_release(dst)" in l2tp_path,
      "L2TP XFRM dst ownership transfer/release paths are incomplete")
check("NUD_VALID" in l2tp_path and "neigh_release(n)" in l2tp_path,
      "L2TP forward path can offload using an unresolved neighbor entry")
check("l2tp_session_put(session)" in l2tp_path,
      "L2TP forward-path callback leaks its session reference")

nft = read("net/netfilter/nft_flow_offload.c")
nf_core = read("net/netfilter/nf_flow_table_core.c")
nft_path = body(nft, "nft_dev_path_info")
nft_forward = body(nft, "nft_dev_forward_path")
check("path->tunnel.dst" in nft_path and "info->dst" in nft_path,
      "nft path walker does not carry the NPU tunnel dst")
check("dst_release(path->tunnel.dst)" in nft_path and "path->tunnel.dst = NULL" in nft_path,
      "nft path walker leaks the L2TP XFRM dst when the NPU callback rejects the path")
check("route->tuple[dir].npu.dst = info.dst" in nft_forward,
      "nft forward path does not transfer NPU dst into the route")
check("dst_release(info.dst)" in nft_forward and
      nft_forward.find("dst_release(info.dst)") < nft_forward.find("return -ENOENT"),
      "nft forward path leaks a held XFRM dst when the flowtable device is unavailable")
check("dst_release(route.tuple[dir].npu.dst)" in nft and
      "dst_release(route.tuple[!dir].npu.dst)" in nft,
      "nft route failure path does not release both direction-specific NPU dst references")
fill_route = body(nf_core, "flow_offload_fill_route")
release_route = body(nf_core, "flow_offload_route_release")
check("flow_tuple->npu.dst = route->tuple[dir].npu.dst" in fill_route and
      "route->tuple[dir].npu.dst = NULL" in fill_route,
      "flow creation does not move NPU dst ownership out of the temporary route")
check("dst_release(flow->tuplehash[FLOW_OFFLOAD_DIR_ORIGINAL].tuple.npu.dst)" in release_route and
      "dst_release(flow->tuplehash[FLOW_OFFLOAD_DIR_REPLY].tuple.npu.dst)" in release_route,
      "flow teardown does not release both NPU dst references")

ppe = read("drivers/net/ethernet/mediatek/mtk_ppe_offload.c")
replace = body(ppe, "mtk_flow_offload_replace")
check("xfrm_state_lookup_byaddr(" in replace and "xfrm_state_put(xs)" in replace,
      "PPE IPsec rekey lookup does not release the referenced XFRM state")
check("if (!xs)" in replace and "if (!xs_old)" in replace,
      "PPE IPsec lookup lacks null-state handling")
check("dst_xfrm(act->npu.dst)" in replace and "dev_net(act->npu.dst->dev)" in replace,
      "PPE IPsec lookup does not derive the state from the held tunnel dst")

eth = read("drivers/net/ethernet/mediatek/mtk_eth_soc.c")
poll = body(eth, "mtk_poll_rx")
check("mtk_get_tnl_dev(tops_crsn)" in poll and "IS_ERR(netdev)" in poll and
      "if (!netdev)" in poll and "netdev = eth->netdev[mac]" in poll,
      "Ethernet NPU RX selection lacks ERR_PTR/null fallback to the physical MAC netdev")

gre = read("net/ipv4/ip_gre.c")
vxlan = read("drivers/net/vxlan/vxlan_core.c")
for label, source, fn in (
    ("GRE", gre, "gre_dev_flow_offload_check"),
    ("VXLAN", vxlan, "vxlan_flow_offload_check"),
):
    callback = body(source, fn)
    check("path->flags & BIT(DEV_PATH_TNL)" in callback and
          "path->flags |= BIT(DEV_PATH_TNL)" in callback,
          label + " callback does not prevent nested tunnel-path recursion")
    check(".ndo_flow_offload_check" in source and fn in source,
          label + " callback is not registered in net_device_ops")

all_c = []
for base in ("drivers", "net"):
    folder = root / base
    if folder.is_dir():
        all_c.extend(folder.rglob("*.c"))
provider_hits = []
for path in all_c:
    try:
        data = path.read_text(errors="replace")
    except OSError:
        continue
    if re.search(r"\bmtk_flow_tnl_offloadable\s*=", data) or re.search(r"\bmtk_flow_tnl_offload\s*=", data):
        provider_hits.append(path.relative_to(root).as_posix())
if not provider_hits:
    reviews.append("no in-tree assignment to the nullable MediaTek tunnel-offload hooks; confirm the external WED/WARP provider registers them")



# MTK netdev restart/reset work must be drained before netdev teardown.
restart_work = body(eth, "mtk_netdev_restart_work")
cleanup = body(eth, "mtk_cleanup")
check("!netif_running(eth->netdev[i])" in restart_work and
      "if (mtk_open(eth->netdev[i]))" in restart_work and
      "dev_close(eth->netdev[i])" in restart_work,
      "MTK restart work does not preserve administratively-down interfaces or close a failed restart")
for work_call in (
    "cancel_work_sync(&eth->pending_work)",
    "cancel_work_sync(&eth->netdev_restart_work)",
    "cancel_delayed_work_sync(&eth->reset.monitor_work)",
):
    check(work_call in cleanup and cleanup.find(work_call) < cleanup.find("mtk_unreg_dev(eth)") and
          cleanup.find(work_call) < cleanup.find("mtk_free_dev(eth)"),
          "MTK cleanup frees netdevs before draining work: " + work_call)

# SKB headroom metadata-copy callbacks must propagate allocation failures.
dev_c = read("net/core/dev.c")
validate = body(dev_c, "validate_xmit_skb")
check("mtk_gso_skb_copy_head && mtk_gso_skb_copy_head(segs, skb)" in validate and
      "kfree_skb_list(segs)" in validate and "goto out_kfree_skb" in validate,
      "GSO headroom-copy failure is ignored or leaks the generated segment list")
ip_output = read("net/ipv4/ip_output.c")
frag_next = body(ip_output, "ip_frag_next")
check("int ret = mtk_ip_frag_skb_copy_head(skb2, skb)" in frag_next and
      "kfree_skb(skb2)" in frag_next and "return ERR_PTR(ret)" in frag_next,
      "IP-fragment headroom-copy failure is ignored or leaks the new fragment")
tnl_h = read("drivers/net/ethernet/mediatek/mtk_tnl.h")
copy_head = body(tnl_h, "mtk_skb_copy_head")
check("if (!need_copy)" in copy_head and
      copy_head.find("if (!need_copy)") < copy_head.find("while (temp)"),
      "SKB headroom helper performs unnecessary copy-on-write when no tunnel metadata exists")


# PPE global flow-table lifetime and tuple teardown iteration are serialized.
ppe_core = read("drivers/net/ethernet/mediatek/mtk_ppe.c")
ppe_deinit = body(ppe_core, "mtk_ppe_deinit")
ppe_offload = read("drivers/net/ethernet/mediatek/mtk_ppe_offload.c")
ppe_init = body(ppe_offload, "mtk_eth_offload_init")
check("continue;" in ppe_deinit and "flow_table_initialized" in ppe_deinit and
      "rhashtable_destroy(&eth->flow_table)" in ppe_deinit,
      "PPE deinit can return early on an empty PPE slot or destroy an uninitialized global flow table")
check("rhashtable_init(&eth->flow_table" in ppe_init and
      "if (!ret)" in ppe_init and "eth->flow_table_initialized = true" in ppe_init,
      "PPE global flow-table initialization state is not recorded after successful init")

nf_core = read("net/netfilter/nf_flow_table_core.c")
teardown = body(nf_core, "flow_offload_teardown_by_tuple")
check("rtnl_lock()" in teardown and "mutex_lock(&flowtable_lock)" in teardown and
      teardown.find("rtnl_lock()") < teardown.find("mutex_lock(&flowtable_lock)") and
      "mutex_unlock(&flowtable_lock)" in teardown and "rtnl_unlock()" in teardown,
      "PPE tuple teardown does not serialize netdevice and flowtable iteration in RTNL-to-flowtable lock order")
check("rcu_read_lock()" in teardown and "rcu_read_unlock()" in teardown and
      teardown.find("rcu_read_lock()") < teardown.find("flow_offload_lookup(") <
      teardown.find("rcu_read_unlock()"),
      "PPE tuple teardown calls rhashtable lookup without an RCU read-side critical section")

ppp_generic = read("drivers/net/ppp/ppp_generic.c")
ppp_sock = body(ppp_generic, "ppp_netdev_get_sock")
check("spin_lock_bh(&ppp->wlock)" in ppp_sock and
      "spin_lock_bh(&pch->downl)" in ppp_sock and
      "list_first_entry_or_null(&ppp->channels" in ppp_sock,
      "PPP socket helper does not serialize channel-list and channel-pointer access")
check("sock_hold(sk)" in ppp_sock,
      "PPP socket helper returns an unreferenced socket that can be freed after channel unlock")

if failures:
    for item in failures:
        print("FAIL: " + item, file=sys.stderr)
    for item in reviews:
        print("REVIEW: " + item, file=sys.stderr)
    raise SystemExit(1)
for item in reviews:
    print("REVIEW: " + item, file=sys.stderr)
print("PASS: Linux 6.12 XFRM/dst APIs and Ethernet/HNAT/PPE/NPU/TNL ownership contracts")
