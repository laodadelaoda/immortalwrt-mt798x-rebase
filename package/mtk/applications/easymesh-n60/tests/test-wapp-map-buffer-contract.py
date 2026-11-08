#!/usr/bin/env python3
"""Regression checks for WAPP MAP flexible-array, event-length and alignment fixes."""
from pathlib import Path
import re
import shutil
import subprocess
import sys


def need(ok, message):
    if not ok:
        raise SystemExit("FAIL: " + message)

if len(sys.argv) != 2:
    raise SystemExit("usage: test-wapp-map-buffer-contract.py <easymesh-build-dir>")
root = Path(sys.argv[1]) / "wappd"
map_c = root / "map/map_1905.c"
map_h = root / "include/map.h"
map_api = root / "include/map_1905.h"
for path in (map_c, map_h, map_api):
    need(path.is_file(), f"required WAPP MAP source missing: {path}")
src = map_c.read_text(encoding="utf-8")
hdr = map_h.read_text(encoding="utf-8")
api = map_api.read_text(encoding="utf-8")

# Structure layout: all four variable-tail records must remain zero-length tails,
# with packed CAC wire records retaining their exact field order.
for token in (
    "struct assoc_status status[0];",
    "struct cac_completion_report_opcap opcap[0];",
    "struct cac_ongoing_channel cac_ongoing_channel[0];",
    "struct GNU_PACKED cac_completion_status_lib",
    "struct GNU_PACKED cac_ongoing_channel",
):
    need(token in hdr, f"vendor MAP ABI layout changed: {token}")
need("struct assoc_notification_tlv status[0]" not in hdr,
     "association status tail unexpectedly changed")

cc = shutil.which("cc")
need(cc is not None, "host C compiler is required for MAP structure-layout assertions")
layout_probe = r"""
#define GNU_PACKED __attribute__((packed))
#include <stddef.h>
#include <stdint.h>
#define MAC_ADDR_LEN 6
#define MAX_CLASS_CHANNEL 68
#define MAX_CLASS_CHAN_NON_ALLOWED 52
struct assoc_status { uint8_t bssid[MAC_ADDR_LEN]; uint8_t status; };
struct assoc_notification_tlv { uint8_t bssid_num; struct assoc_status status[0]; };
struct assoc_notification_lib { uint8_t assoc_notification_tlv_num; struct assoc_notification_tlv notification_tlv[0]; };
struct GNU_PACKED cac_completion_report_opcap { uint8_t op_class; uint8_t ch_num; };
struct GNU_PACKED cac_completion_status_lib { uint8_t identifier[MAC_ADDR_LEN]; uint8_t op_class; uint8_t channel; uint8_t cac_status; uint8_t op_class_num; struct cac_completion_report_opcap opcap[0]; };
struct GNU_PACKED cac_completion_report_lib { uint8_t radio_num; struct cac_completion_status_lib cac_completion_status[0]; };
struct GNU_PACKED cac_allowed_channel { uint8_t op_class; uint8_t ch_num; uint16_t cac_interval; };
struct GNU_PACKED cac_non_allowed_channel { uint8_t op_class; uint8_t ch_num; uint16_t remain_interval; };
struct GNU_PACKED cac_ongoing_channel { uint8_t op_class; uint8_t ch_num; uint32_t remain_interval; };
struct GNU_PACKED cac_status_report_lib { uint8_t allowed_channel_num; uint8_t non_allowed_channel_num; uint8_t ongoing_cac_channel_num; struct cac_allowed_channel allowed_channel[MAX_CLASS_CHANNEL]; struct cac_non_allowed_channel non_allowed_channel[MAX_CLASS_CHAN_NON_ALLOWED]; struct cac_ongoing_channel cac_ongoing_channel[0]; };
_Static_assert(sizeof(struct assoc_status) == 7, "assoc status ABI");
_Static_assert(sizeof(struct assoc_notification_tlv) == 1, "assoc TLV prefix ABI");
_Static_assert(sizeof(struct cac_completion_report_opcap) == 2, "CAC opcap ABI");
_Static_assert(sizeof(struct cac_completion_status_lib) == 10, "CAC completion prefix ABI");
_Static_assert(offsetof(struct cac_completion_status_lib, opcap) == sizeof(struct cac_completion_status_lib), "CAC opcap tail offset");
_Static_assert(sizeof(struct cac_completion_report_lib) == 1, "CAC completion report prefix ABI");
_Static_assert(sizeof(struct cac_ongoing_channel) == 6, "CAC ongoing in-memory ABI");
_Static_assert(sizeof(struct cac_status_report_lib) == 483, "CAC status fixed prefix ABI");
_Static_assert(offsetof(struct cac_ongoing_channel, remain_interval) == 2, "CAC interval offset");
int main(void) { return 0; }
"""
probe = subprocess.run([cc, "-std=gnu11", "-Wall", "-Werror", "-x", "c", "-fsyntax-only", "-"],
                       input=layout_probe, text=True, capture_output=True)
need(probe.returncode == 0, "C structure-layout assertions failed: " + probe.stderr)

# Association notification: allocation and copy must walk variable-size TLVs,
# not index a zero-length member as a fixed C array.
assoc_start = src.find("void map_build_and_send_assoc_status_notification(")
assoc_end = src.find("\n#ifdef DFS_CAC_R2", assoc_start)
need(assoc_start >= 0 and assoc_end > assoc_start, "association serializer missing")
assoc = src[assoc_start:assoc_end]
need("src += sizeof(*tlv) + entries_len" in assoc,
     "association TLV input cursor does not advance by actual BSSID count")
need("dst += sizeof(*src_tlv) + entries_len" in assoc,
     "association event cursor does not advance by actual BSSID count")
need("assoc_notify->notification_tlv[i]" not in assoc,
     "association serializer still indexes a zero-length flexible array")
need("map_event->length = (u16)assoc_status_len" in assoc,
     "association event length is not derived from serialized bytes")
caller_start = src.find("void map_send_assoc_notification(")
caller_end = src.find("\n#if 0", caller_start)
caller = src[caller_start:caller_end]
need("(struct assoc_status *)((u8 *)assoc_status_evt + sizeof(*assoc_status_evt))" in caller,
     "association builder still indexes a zero-length status member")
need("assoc_status_evt->status[" not in caller,
     "association builder still writes through the zero-length status member")
need("map_build_and_send_assoc_status_notification" in api,
     "association serializer declaration is missing")

# CAC status: allocate tail room for every possible radio and bound the driver
# counts before writing. The wire format uses 3 bytes for remain_interval.
cac_start = src.find("int map_send_cac_status(")
cac_end = src.find("\nint mapd_get_cac_capab_from_driver", cac_start)
need(cac_start >= 0 and cac_end > cac_start, "CAC status serializer missing")
cac = src[cac_start:cac_end]
need("MAP_MAX_RADIO * sizeof(struct cac_ongoing_channel)" in cac,
     "CAC ongoing flexible-array capacity is not allocated")
need("ongoing_cac_channel_num >= MAP_MAX_RADIO" in cac,
     "CAC ongoing radio count has no capacity guard")
need("op_class_num > ARRAY_SIZE(driver_cap->opcap)" in cac,
     "driver operating-class count is not bounded")
need("ch_num > ARRAY_SIZE(driver_cap->opcap[m].ch_list)" in cac,
     "driver channel count is not bounded")
need("non_allowed_channel_num >= MAX_CLASS_CHAN_NON_ALLOWED" in cac,
     "non-allowed channel capacity is not guarded")
need("allowed_channel_num >= MAX_CLASS_CHANNEL" in cac,
     "allowed channel capacity is not guarded")
need("ongoing_cac_channel_num * 5" in cac,
     "CAC event length does not use the 5-byte wire record")
ongoing_block = cac[cac.find("for (i=0; i < cac_status->ongoing_cac_channel_num; i++)") :]
need("remain_interval), 3);" in ongoing_block and "ptr += 3;" in ongoing_block,
     "CAC remain_interval copy length and cursor increment disagree")
need("*len_buf = cac_completion ? (int)(status_len - sizeof(struct evt)) : status_len;" in cac,
     "CAC completion payload length still includes an event header that is not in evt_buf")
need("cac_status.cac_ongoing_channel" not in cac,
     "CAC flexible-array record is still accessed through a fixed-size stack object")

# CAC completion: opcap is a wire tail after every radio status record.
# Address it from the report allocation, not through the zero-length member.
cac_stop_start = src.find("void wdev_handle_cac_stop(")
cac_stop_end = src.find("\n#ifdef V10_DFS_SUPPORT", cac_stop_start)
need(cac_stop_start >= 0 and cac_stop_end > cac_stop_start,
     "CAC completion handler missing")
cac_stop = src[cac_stop_start:cac_stop_end]
need(cac_stop.count("struct cac_completion_report_opcap *opcap =") == 2,
     "both CAC completion paths must calculate the opcap tail from the full radio-status prefix")
need("completion_report->cac_completion_status[0].opcap[0]" not in cac_stop,
     "CAC completion still indexes a zero-length opcap member")
need(cac_stop.count("(size_t)radio_num * sizeof(struct cac_completion_status_lib)") == 2,
     "both CAC opcap pointers must begin after the complete radio-status array")
need(cac_stop.count("(radio_num* sizeof(struct cac_completion_status_lib))") == 2,
     "both CAC report allocations must reserve the complete radio-status array")
need("opcap->ch_num" in cac_stop and "opcap->op_class" in cac_stop,
     "CAC completion does not populate the tail record through its bounded pointer")
need(cac_stop.count("op_class_num*sizeof(struct cac_completion_report_opcap)") == 2,
     "both CAC completion allocations must include the advertised opcap count")
need(cac_stop.count("if (radar_status == FALSE)\n\t\t\top_class_num = 0;") == 2,
     "both CAC completion paths must derive allocation size from radar status before allocation")

# Packed-member alignment: macro output is built in an aligned local object;
# packed interval bytes are copied by byte offset, never by taking a member address.
need(src.count("struct map_radio_identifier radio_identifier;") >= 2,
     "packed CAC radio identifiers are not staged in aligned local objects")
need("&completion_report->cac_completion_status[0].identifier" not in src,
     "address of packed CAC identifier is still taken")
need("&cac_status->cac_ongoing_channel[i].remain_interval" not in src,
     "address of packed CAC interval is still taken")

# The first real AArch64 compile must catch pointer-member typos and every
# address-taking operation on packed CAC timestamps / traffic-separation VIDs.
need("cac_status.ongoing_cac_channel_num" not in cac,
     "CAC flexible-tail index still uses pointer as a struct object")
need("&wapp->map->cac_list.last_cac_time[" not in src,
     "address of packed CAC timestamp member is still taken")

need("os_time_sub(&now, &last_cac, &delta)" in src,
     "CAC elapsed-time calculation must use an aligned timestamp copy")
need("offsetof(struct cac_run_list, last_cac_time)" in src,
     "CAC timestamp accesses are not staged through byte offsets")
need("setting->policy_vids" not in src,
     "packed traffic-separation VLAN array is still passed by address")
need("offsetof(struct ts_common_setting, policy_vids)" in src,
     "packed VLAN entries are not copied through byte offsets")
need("setting->policy_vid_num > MAX_VLAN_NUM" in src,
     "traffic-separation VLAN count is not bounded before copying")

# Deterministic protocol-size checks for the current vendor ABI.
base_cac_status = 3 + 68 * 4 + 52 * 4
need(base_cac_status == 483, "unexpected CAC status fixed-prefix size")
for ongoing in range(4):
    expected = base_cac_status + ongoing * 5
    encoded = 3 + 68 * 4 + 52 * 4 + ongoing * (1 + 1 + 3)
    need(expected == encoded, f"CAC status payload size mismatch at ongoing count {ongoing}")
for counts in ((1,), (0, 1, 3), (16, 0, 2)):
    expected = 1 + sum(1 + n * 7 for n in counts)
    encoded = 1 + sum(1 + n * (6 + 1) for n in counts)
    need(expected == encoded, "association TLV payload size mismatch")

print("PASS: WAPP MAP structure, flexible-tail capacity, association TLV lengths, CAC wire lengths, zero-opcap handling and packed alignment contracts.")