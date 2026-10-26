#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Dumps the kernel's Wi-Fi scan results (nl80211) as wpa_cli-style BSS blocks.

The output can be piped into wifi-analyze-cli:

    tools/nl80211-scan-dump.py | wifi-analyze-cli list
    tools/nl80211-scan-dump.py --iface wlp6s0 | wifi-analyze-cli decode --bss 86:78:48:9a:af:de

Reading the scan cache (NL80211_CMD_GET_SCAN dump) needs no root and works in parallel with
NetworkManager / wpa_supplicant: it only reads what the kernel already has. To refresh the
cache without root, let NetworkManager scan first:

    nmcli device wifi rescan && sleep 3 && tools/nl80211-scan-dump.py | wifi-analyze-cli list

Python standard library only (raw generic netlink).
"""

from __future__ import annotations

import argparse
import os
import socket
import struct
import sys

NETLINK_GENERIC = 16
NLM_F_REQUEST = 0x01
NLM_F_ACK = 0x04
NLM_F_DUMP = 0x300
NLMSG_ERROR = 2
NLMSG_DONE = 3
NLA_TYPE_MASK = 0x3FFF

GENL_ID_CTRL = 0x10
CTRL_CMD_GETFAMILY = 3
CTRL_ATTR_FAMILY_ID = 1
CTRL_ATTR_FAMILY_NAME = 2

# include/uapi/linux/nl80211.h
NL80211_CMD_GET_SCAN = 32
NL80211_ATTR_IFINDEX = 3
NL80211_ATTR_BSS = 47
NL80211_BSS_BSSID = 1
NL80211_BSS_FREQUENCY = 2
NL80211_BSS_TSF = 3
NL80211_BSS_BEACON_INTERVAL = 4
NL80211_BSS_CAPABILITY = 5
NL80211_BSS_INFORMATION_ELEMENTS = 6
NL80211_BSS_SIGNAL_MBM = 7
NL80211_BSS_STATUS = 9
NL80211_BSS_SEEN_MS_AGO = 10
NL80211_BSS_BEACON_IES = 11


def attrs(data: bytes) -> dict[int, bytes]:
    """Parses a sequence of netlink attributes (last occurrence wins)."""
    result: dict[int, bytes] = {}
    pos = 0
    while pos + 4 <= len(data):
        length, kind = struct.unpack_from("=HH", data, pos)
        if length < 4 or pos + length > len(data):
            break
        result[kind & NLA_TYPE_MASK] = data[pos + 4 : pos + length]
        pos += (length + 3) & ~3
    return result


def attr(kind: int, payload: bytes) -> bytes:
    data = struct.pack("=HH", 4 + len(payload), kind) + payload
    return data + b"\0" * ((4 - len(data) % 4) % 4)


class GenlSocket:
    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_GENERIC)
        self.sock.bind((0, 0))
        self.seq = 0

    def request(self, family: int, cmd: int, flags: int, payload: bytes) -> list[bytes]:
        """Sends a genetlink request and returns the payloads (after genl header) of replies."""
        self.seq += 1
        genl = struct.pack("=BBH", cmd, 1, 0) + payload
        msg = struct.pack("=IHHII", 16 + len(genl), family, NLM_F_REQUEST | flags, self.seq, 0) + genl
        self.sock.send(msg)
        replies: list[bytes] = []
        while True:
            data = self.sock.recv(1 << 20)
            pos = 0
            while pos + 16 <= len(data):
                length, kind, _flags, seq, _pid = struct.unpack_from("=IHHII", data, pos)
                if length < 16:
                    return replies
                body = data[pos + 16 : pos + length]
                pos += (length + 3) & ~3
                if seq != self.seq:
                    continue
                if kind == NLMSG_DONE:
                    return replies
                if kind == NLMSG_ERROR:
                    error = struct.unpack_from("=i", body)[0]
                    if error != 0:
                        raise OSError(-error, os.strerror(-error))
                    return replies
                replies.append(body[4:])  # skip genl header
            if not flags & NLM_F_DUMP and replies:
                return replies

    def family_id(self, name: str) -> int:
        replies = self.request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, 0,
                               attr(CTRL_ATTR_FAMILY_NAME, name.encode() + b"\0"))
        for r in replies:
            a = attrs(r)
            if CTRL_ATTR_FAMILY_ID in a:
                return struct.unpack("=H", a[CTRL_ATTR_FAMILY_ID][:2])[0]
        raise OSError(f"generic netlink family {name!r} not found")


def wireless_interfaces() -> list[str]:
    base = "/sys/class/net"
    return sorted(i for i in os.listdir(base) if os.path.isdir(os.path.join(base, i, "wireless")))


def dump(iface: str) -> list[dict]:
    index = socket.if_nametoindex(iface)
    g = GenlSocket()
    nl80211 = g.family_id("nl80211")
    replies = g.request(nl80211, NL80211_CMD_GET_SCAN, NLM_F_DUMP,
                        attr(NL80211_ATTR_IFINDEX, struct.pack("=I", index)))
    result = []
    for r in replies:
        bss_attr = attrs(r).get(NL80211_ATTR_BSS)
        if bss_attr is None:
            continue
        b = attrs(bss_attr)
        if NL80211_BSS_BSSID not in b:
            continue
        entry = {
            "bssid": ":".join(f"{x:02x}" for x in b[NL80211_BSS_BSSID][:6]),
            "freq": struct.unpack("=I", b[NL80211_BSS_FREQUENCY][:4])[0] if NL80211_BSS_FREQUENCY in b else None,
            "level": struct.unpack("=i", b[NL80211_BSS_SIGNAL_MBM][:4])[0] // 100 if NL80211_BSS_SIGNAL_MBM in b else None,
            "age": struct.unpack("=I", b[NL80211_BSS_SEEN_MS_AGO][:4])[0] // 1000 if NL80211_BSS_SEEN_MS_AGO in b else None,
            "capabilities": struct.unpack("=H", b[NL80211_BSS_CAPABILITY][:2])[0] if NL80211_BSS_CAPABILITY in b else None,
            "beacon_int": struct.unpack("=H", b[NL80211_BSS_BEACON_INTERVAL][:2])[0] if NL80211_BSS_BEACON_INTERVAL in b else None,
            "associated": NL80211_BSS_STATUS in b,
            "ie": b.get(NL80211_BSS_INFORMATION_ELEMENTS, b""),
            "beacon_ie": b.get(NL80211_BSS_BEACON_IES),
        }
        result.append(entry)
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--iface", help="wireless interface (default: all)")
    args = ap.parse_args()
    ifaces = [args.iface] if args.iface else wireless_interfaces()
    if not ifaces:
        print("error: no wireless interface found", file=sys.stderr)
        return 2
    count = 0
    for iface in ifaces:
        try:
            entries = dump(iface)
        except OSError as e:
            print(f"error: {iface}: {e}", file=sys.stderr)
            return 2
        for i, e in enumerate(entries):
            lines = [f"id={count}", f"bssid={e['bssid']}"]
            if e["freq"] is not None:
                lines.append(f"freq={e['freq']}")
            if e["beacon_int"] is not None:
                lines.append(f"beacon_int={e['beacon_int']}")
            if e["capabilities"] is not None:
                lines.append(f"capabilities=0x{e['capabilities']:04x}")
            if e["level"] is not None:
                lines.append(f"level={e['level']}")
            if e["age"] is not None:
                lines.append(f"age={e['age']}")
            lines.append(f"ie={e['ie'].hex()}")
            if e["beacon_ie"]:
                lines.append(f"beacon_ie={e['beacon_ie'].hex()}")
            lines.append(f"flags=[iface={iface}]" + ("[associated]" if e["associated"] else ""))
            print("\n".join(lines))
            print()
            count += 1
    if count == 0:
        print("warning: scan cache is empty; run 'nmcli device wifi rescan' first", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
