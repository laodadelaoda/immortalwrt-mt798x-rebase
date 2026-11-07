#!/usr/bin/env python3
"""Static semantic checks for the overlapping MediaTek PPE/QoS patch group."""
from pathlib import Path
import re
import sys

root = Path(sys.argv[1])

def read(path):
    p = root / path
    if not p.is_file():
        raise SystemExit(f"FAIL: missing patched source: {p}")
    return p.read_text(encoding="utf-8", errors="replace")

def require(condition, message):
    if not condition:
        raise SystemExit("FAIL: " + message)

offload = read("drivers/net/ethernet/mediatek/mtk_ppe_offload.c")
qos_h = read("include/net/netfilter/nf_conntrack_qos.h")
xt = read("net/netfilter/xt_FLOWOFFLOAD.c")
flow_ip = read("net/netfilter/nf_flow_table_ip.c")
debugfs = read("drivers/net/ethernet/mediatek/mtk_ppe_debugfs.c")
ppe_c = read("drivers/net/ethernet/mediatek/mtk_ppe.c")

# #04 -> #05 -> #39 -> WED-07 share this function signature and call contract.
require(re.search(r"mtk_flow_set_output_device\([\s\S]{0,500}?int \*wed_index,\s*int dscp\)", offload),
        "mtk_flow_set_output_device() must retain the #05 DSCP argument after #04.")
replace_marker = offload.split("mtk_flow_offload_replace", 1)[1]
require(re.search(r"mtk_flow_set_output_device\([\s\S]{0,300}?data\.eth\.h_dest,\s*&wed_index,\s*dscp\)", replace_marker),
        "mtk_flow_offload_replace() call must pass the DSCP argument.")
require("struct net_device *odev_conduit = odev;" in offload,
        "the #04 output-device conduit state must survive the #05 signature extension.")

# Conntrack extension allocation failure must not fall through to memset(NULL).
add = qos_h.split("nf_ct_qos_ext_add", 1)[1].split("#else", 1)[0]
require(re.search(r"if\s*\(!qos\)\s*\{[\s\S]*?return NULL;[\s\S]*?\}\s*memset\(qos", add),
        "nf_ct_qos_ext_add() must return on allocation failure before memset.")

# DSCP learning is a bidirectional TCP threshold, and only learned TCP DSCP is applied.
require("nf_ct_protonum(ct) == IPPROTO_TCP" in xt,
        "DSCP learning must be limited to TCP flows.")
require(re.search(r"qos->tos\[dir\]\.counter[\s\S]{0,220}qos->tos\[!dir\]\.counter", xt),
        "both conntrack directions must reach the configured DSCP-learning threshold.")
dscp_init = xt.split("xt_flowoffload_dscp_init", 1)[1].split("static unsigned int", 1)[0]
require("nf_ct_protonum(ct) == IPPROTO_TCP" in dscp_init and
        "qos->tos[!dir].counter" in dscp_init,
        "DSCP tuple initialization must require a bidirectional TCP learning threshold.")

# skb_try_make_writable() can replace skb storage; refresh the network-header pointer afterwards.
ipv4 = flow_ip.split("static int nf_flow_offload_forward", 1)[1].split("unsigned int", 1)[0]
ipv6 = flow_ip.split("static int nf_flow_offload_ipv6_forward", 1)[1].split("static struct flow_offload_tuple_rhash", 1)[0]
require(re.search(r"skb_try_make_writable[\s\S]*?iph = \(struct iphdr \*\)\(skb_network_header\(skb\) \+ ctx->offset\);[\s\S]*?if \(net->ct.sysctl_qos &&\s*flow->tuplehash\[dir\]\.tuple\.l4proto == IPPROTO_TCP\)\s*ipv4_change_dsfield\(iph", ipv4),
        "IPv4 DS-field rewrite must refresh the offset header pointer and apply only to TCP after skb_try_make_writable().")
require(re.search(r"skb_try_make_writable[\s\S]*?ip6h = \(struct ipv6hdr \*\)\(skb_network_header\(skb\) \+ ctx->offset\);[\s\S]*?if \(net->ct.sysctl_qos &&\s*flow->tuplehash\[dir\]\.tuple\.l4proto == IPPROTO_TCP\)\s*ipv6_change_dsfield\(ip6h", ipv6),
        "IPv6 DS-field rewrite must refresh the offset header pointer and apply only to TCP after skb_try_make_writable().")

# These debugfs controls have write callbacks; their modes must permit writes.
for name in ("qos_toggle", "l4s_toggle", "464xlat"):
    require(re.search(rf'debugfs_create_file\("{name}",\s*S_IRUGO\s*\|\s*S_IWUSR', debugfs),
            f"{name} debugfs control has a write callback but is not user-writable.")
require('seq_puts(m, "HQoS is disabled now!\\n");' in debugfs,
        "qos_toggle read callback must write to seq_file.")
require('seq_puts(m, "L4S is disabled now!\\n");' in debugfs,
        "l4s_toggle read callback must write to seq_file.")
require("case '3':" in debugfs and "qos_toggle = 3" in debugfs,
        "adaptive PPPQ mode 3 must be selectable through qos_toggle.")
require("qos_toggle == 3" in offload,
        "adaptive PPPQ mode 3 consumer is missing.")
require("idev && mtk_is_xlat464_enabled()" in offload,
        "464XLAT name lookup must not dereference a missing ingress device.")

# #20 must release the software hash even when hardware state was already cleared.
clear = ppe_c.split("__mtk_foe_entry_clear", 1)[1].split("static int __mtk_foe_entry_idle_time", 1)[0]
require(re.search(r"if\s*\(entry->hash != 0xffff && set_state\)[\s\S]*?\n\s*\}\s*\n\s*entry->hash = 0xffff;", clear),
        "software hash must be reset outside the set_state conditional.")

# #32/#33: teardown must tolerate sparse PPE arrays and always destroy the flow table.
deinit = ppe_c.split("void mtk_ppe_deinit", 1)[1].split("static void mtk_ppe_init_foe_table", 1)[0]
require("if (!eth->ppe[i])\n\t\t\tcontinue;" in deinit,
        "PPE deinit must skip absent PPE instances rather than returning early.")
require("rhashtable_destroy(&eth->flow_table);" in deinit,
        "flow_table must be destroyed after iterating PPE instances.")
teardown = ppe_c.split("void mtk_flow_offload_teardown_by_tnl", 1)[1]
require(re.search(r"struct mtk_ppe \*ppe = eth->ppe\[i\];[\s\S]{0,120}if\s*\(!ppe\)\s*continue;", teardown),
        "XFRM teardown must skip absent PPE instances.")

# #39: 464XLAT lookup must skip absent PPE instances.
lookup = offload.split("mtk_find_tuple_in_ppe", 1)[1]
require(re.search(r"ppe = eth->ppe\[i\];[\s\S]{0,100}if\s*\(!ppe\)\s*continue;", lookup),
        "464XLAT PPE lookup must skip absent PPE instances.")
require("DSA_TAG_PROTO_MXL862_8021Q" in offload and "mtk_foe_entry_set_dsa(eth, foe, dsa_proto, dsa_port)" in offload,
        "MXL862 DSA protocol must be preserved into the PPE DSA entry.")
require("FLOW_ACTION_NPU_ENCAP" in offload and "xfrm_state_lookup_byaddr" in offload and "xfrm_state_put(xs)" in offload,
        "NPU/XFRM flow actions must resolve and release the xfrm_state reference.")
require("mtk_flow_is_dev_3addr_sta" in offload and "NL80211_IFTYPE_STATION" in offload and "ether_addr_copy(data.eth.h_source, odev->dev_addr)" in offload,
        "3-address station egress must use the egress device source MAC.")
require("ndo_fill_forward_path" in offload and "info.tid = dscp" in offload and "FIELD_PREP(MTK_FOE_WINFO_AMSDU_TID, tid)" in read("drivers/net/ethernet/mediatek/mtk_ppe.c"),
        "WED WMM TID must flow through the netdevice path and PPE WDMA entry.")
wdma = offload.split("mtk_flow_get_wdma_info", 1)[1].split("static int", 1)[0]
require(re.search(r"rcu_read_lock\(\);[\s\S]*ndo_fill_forward_path\(&ctx, &path\);[\s\S]*rcu_read_unlock\(\);", wdma),
        "WED forward-path callback must run under RCU read-side protection.")

print("PASS: PPE/QoS overlap contracts (#04/#05/#11/#20/#28/#32/#33/#35/#39/#42/#45/WED-07).")
