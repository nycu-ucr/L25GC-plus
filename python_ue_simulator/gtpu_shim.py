#!/usr/bin/env python3
import os
import fcntl
import struct
import socket
import select
import argparse
import subprocess
import time
from typing import Optional, Tuple

# ---------- Constants ----------
TUNSETIFF = 0x400454ca
IFF_TUN   = 0x0001
IFF_NO_PI = 0x1000

GTPU_PORT = 2152

# GTPv1-U flags we care about:
# 0x30 = Version=1, PT=1, E=0, S=0, PN=0 (minimal header)
# 0x34 = Version=1, PT=1, E=1 (optional fields + extension headers)
GTPU_V1_PT      = 0x30
GTPU_V1_PT_E    = 0x34
GTPU_TYPE_TPDU  = 0xff            # T-PDU

# Common extension header type used by UERANSIM for QFI
GTPU_EXT_PDU_SESSION_CONTAINER = 0x85


# ---------- Small helpers ----------
def run(cmd, check=True, quiet=False):
    if not quiet:
        print("+", " ".join(cmd))
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if check and p.returncode != 0:
        raise RuntimeError(f"cmd failed: {' '.join(cmd)}\nstdout={p.stdout}\nstderr={p.stderr}")
    return p


def tun_create(name_hint: str, mtu: int = 1450):
    """
    Create a TUN device and return (fd, ifname).
    """
    tun = os.open("/dev/net/tun", os.O_RDWR)
    ifr = struct.pack("16sH", name_hint.encode(), IFF_TUN | IFF_NO_PI)
    ifs = fcntl.ioctl(tun, TUNSETIFF, ifr)
    ifname = ifs[:16].split(b"\x00", 1)[0].decode()

    run(["ip", "link", "set", "dev", ifname, "mtu", str(mtu)])
    run(["ip", "link", "set", "dev", ifname, "up"])
    return tun, ifname


def ensure_rp_filter_off(ifname: str):
    # UERANSIM-like flows + policy routing often break with rp_filter=1.
    # Disable on the tun and (optionally) global defaults.
    paths = [
        f"/proc/sys/net/ipv4/conf/{ifname}/rp_filter",
        "/proc/sys/net/ipv4/conf/all/rp_filter",
        "/proc/sys/net/ipv4/conf/default/rp_filter",
    ]
    for p in paths:
        try:
            with open(p, "w") as f:
                f.write("0\n")
        except Exception:
            pass


def parse_rx_teids(s: Optional[str]):
    """Parse a comma-separated TEID allowlist.

    Semantics:
      - If --rx-teids is NOT provided => None (accept any)
      - If provided but blank => None (accept any)
      - If list contains 0 => None (treat 0 as wildcard / accept any)
      - Else => set of allowed TEIDs
    """
    if s is None:
        return None

    s = s.strip()
    if not s:
        return None

    out = set()
    for part in s.split(","):
        part = part.strip()
        if not part:
            continue
        out.add(int(part, 0))

    if 0 in out:
        return None

    return out



# ---------- GTP-U parsing/build ----------
def _skip_ext_headers(buf: bytes, pos: int, first_type: int) -> int:
    """
    Skip chained GTPv1-U extension headers. Return updated position (start of inner payload).

    This supports BOTH layouts:
      A) "len-only" layout (UERANSIM/common 5GC code):
         Optional fields ended with next_ext_type byte. Next bytes are:
            [len][...len*4 bytes total...][next_ext_type]
      B) "type+len" layout (less common in some stacks):
            [type][len][...][next_type]

    We'll try to interpret len-only first (because your old C code expects it),
    and fall back to type+len if it doesn't look sane.
    """
    next_type = first_type
    for _ in range(8):  # safety bound on chaining
        if next_type == 0:
            return pos

        # Layout A: len-only (pos points at length)
        if pos < len(buf):
            length = buf[pos]
            total = length * 4
            # length must be >=1 and not run out of buffer
            if length >= 1 and pos + total <= len(buf):
                # next_type is last byte of the ext header block
                next_type = buf[pos + total - 1]
                pos = pos + total
                continue

        # Layout B: type+len (pos points at type)
        if pos + 2 <= len(buf):
            etype = buf[pos]
            length = buf[pos + 1]
            total = length * 4
            if length >= 1 and pos + 2 + total <= len(buf):
                # next_type is last byte of the ext header payload
                next_type = buf[pos + 2 + total - 1]
                pos = pos + 2 + total
                continue

        # If neither parses, stop.
        return pos

    return pos


def parse_gtpu(pkt: bytes) -> Tuple[Optional[int], Optional[bytes]]:
    """
    Return (teid, inner_payload) if pkt looks like GTPv1-U T-PDU; otherwise (None, None).
    Handles both minimal and UERANSIM-style (E=1 + ext 0x85) packets.
    """
    if len(pkt) < 8:
        return None, None

    flags, msg_type, length, teid = struct.unpack("!BBHI", pkt[:8])

    # must be GTPv1-U TPDU
    if (flags & 0xE0) != 0x20:  # version=1
        return None, None
    if msg_type != GTPU_TYPE_TPDU:
        return None, None

    # payload length is bytes after the first 8 bytes
    payload = pkt[8:8 + length]
    if len(payload) < 0:
        return None, None

    E = (flags & 0x04) != 0
    S = (flags & 0x02) != 0
    PN = (flags & 0x01) != 0

    pos = 0
    if E or S or PN:
        # Optional fields: [seq:2][npdu:1][next_ext_type:1]
        if len(payload) < 4:
            return None, None
        seq = struct.unpack("!H", payload[0:2])[0]
        npdu = payload[2]
        next_ext = payload[3]
        pos = 4

        # Skip extension headers (possibly including 0x85)
        pos = _skip_ext_headers(payload, pos, next_ext)

    inner = payload[pos:]
    if not inner:
        return teid, b""
    return teid, inner


def _looks_like_ip(inner: bytes) -> bool:
    # Very lightweight check: IPv4 first nibble is 4.
    return len(inner) >= 1 and (inner[0] >> 4) == 4


def build_gtpu(teid: int, inner: bytes, mode: str = "ueransim", qfi: int = 1, seq: int = 0) -> bytes:
    """Build a GTPv1-U T-PDU.

    mode:
      - 'minimal'  : flags=0x30, no optional fields, no ext headers (8B header + inner)
      - 'ueransim' : flags=0x34 (E=1), includes optional fields + ext header 0x85
                    laid out like common UERANSIM captures:
                      [Seq(2)][N-PDU(1)][NextExtType=0x85]
                      then ext header body (len-only style):
                      [Len=1][Spare=0][QFI][NextExtType=0]
                    followed by inner IP packet
    """
    mode = (mode or "ueransim").lower()
    if mode == "minimal":
        length = len(inner)
        hdr = struct.pack("!BBHI", GTPU_V1_PT, GTPU_TYPE_TPDU, length, teid)
        return hdr + inner

    if mode == "ueransim":
        # Clamp QFI to 6 bits; UERANSIM typically uses QFI=1 for default flows.
        qfi6 = int(qfi) & 0x3f

        # Optional fields present when E/S/PN any set. With flags 0x34, only E=1.
        opt = struct.pack("!HBB", seq & 0xffff, 0, GTPU_EXT_PDU_SESSION_CONTAINER)

        # PDU Session Container ext header (len-only layout).
        # Total ext header bytes consumed must be 4 * Len.
        ext = bytes([1, 0x00, qfi6, 0x00])

        payload = opt + ext + inner
        length = len(payload)
        hdr = struct.pack("!BBHI", GTPU_V1_PT_E, GTPU_TYPE_TPDU, length, teid)
        return hdr + payload

    raise ValueError(f"unknown GTP-U mode: {mode!r}")


# ---------- Main ----------
def main():
    ap = argparse.ArgumentParser(description="Minimal UE-side GTP-U shim (TUN <-> UDP/2152)")

    ap.add_argument("--ue", required=True, help="UE IP/prefix for the TUN (e.g., 10.60.0.1/24)")
    ap.add_argument("--local-n3", required=True, help="Local N3 IP (outer src), e.g., 192.168.1.1")
    ap.add_argument("--remote-n3", required=True, help="Remote N3 IP (outer dst), e.g., 192.168.1.2 (UPF-U side)")
    ap.add_argument("--dn-ip", required=True, help="Data network IP (inner dst for ping/iperf), e.g., 192.168.1.4")
    ap.add_argument("--mtu", type=int, default=1450)
    ap.add_argument("--tun", default="uesimtun0", help="TUN name hint")

    ap.add_argument("--teid", type=int, default=1, help="Default TEID (legacy)")
    ap.add_argument("--tx-teid", type=int, default=None, help="TX TEID for uplink encapsulation (preferred)")
    ap.add_argument("--gtpu-mode", choices=["minimal", "ueransim"], default="ueransim",
                    help="How to build uplink GTP-U: minimal header or UERANSIM-like (E=1, ext=0x85)")
    ap.add_argument("--qfi", type=int, default=1, help="QFI to encode when --gtpu-mode=ueransim (0-63)")
    ap.add_argument("--tx-src-port", type=int, default=GTPU_PORT,
                    help="Outer UDP source port for uplink. 2152 mimics many gNBs; 0 uses ephemeral.")
    ap.add_argument("--seq-start", type=int, default=0, help="Starting GTP-U sequence number for uplink")

    ap.add_argument("--rx-teids",
    				default=None,
    				help="Comma-separated TEIDs to accept on RX. If omitted, accept ANY. Use '0' as wildcard for ANY."
	)

    ap.add_argument("--table", default="100", help="Policy routing table number/name for UE source routing")
    ap.add_argument("--access-if", default="", help="Interface used for N3 traffic (for static neigh), e.g., enp94s0f1")
    ap.add_argument("--n3-mac", default="", help="MAC to pin for remote-n3 (static ARP), e.g., node2 port MAC")

    ap.add_argument("--print-inner", action="store_true", help="Print basic info about inner packets")
    ap.add_argument("--keep", action="store_true", help="Do not delete TUN/ip rules on exit")

    args = ap.parse_args()

    ue_ip, ue_prefix = args.ue.split("/")
    ue_prefix = int(ue_prefix)

    tx_teid = args.tx_teid if args.tx_teid is not None else args.teid
    seq = args.seq_start & 0xffff
    rx_set = parse_rx_teids(args.rx_teids)  # None => accept any

    # Create TUN and configure
    tunfd, ifname = tun_create(args.tun, mtu=args.mtu)
    ensure_rp_filter_off(ifname)

    # Assign UE IP to TUN
    run(["ip", "addr", "flush", "dev", ifname], check=False, quiet=True)
    run(["ip", "addr", "add", f"{ue_ip}/{ue_prefix}", "dev", ifname])

    # Policy routing: traffic sourced from UE IP goes out main table (default) but we want:
    # - inner traffic injected into TUN should route to "local" (handled by this shim)
    # We'll keep it simple: add a rule to lookup a dedicated table, and a default route to dev ifname.
    run(["ip", "route", "flush", "table", args.table], check=False, quiet=True)
    run(["ip", "route", "add", "default", "dev", ifname, "table", args.table])
    run(["ip", "rule", "add", "pref", "100", "from", f"{ue_ip}/32", "lookup", args.table], check=False)

    # Optional: static neighbor entry so the kernel can send to remote_n3 even if it can't ARP (e.g., DPDK-bound peer).
    if args.n3_mac and args.access_if:
        run(["ip", "neigh", "replace", args.remote_n3, "lladdr", args.n3_mac, "dev", args.access_if, "nud", "permanent"],
            check=False)

    print(f"[shim] UE={args.ue} tun={ifname} mtu={args.mtu}")
    print(f"[shim] N3 {args.local_n3}:{args.tx_src_port} → {args.remote_n3}:{GTPU_PORT}  "
          f"TX_TEID={tx_teid} mode={args.gtpu_mode} qfi={args.qfi}  "
          f"RX_TEIDs={'ANY' if rx_set is None else sorted(rx_set)}")

    # UDP sockets
    tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    tx.bind((args.local_n3, args.tx_src_port))  # outer src (2152 by default for gNB-like behavior)

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.bind((args.local_n3, GTPU_PORT))
    rx.setblocking(False)

    tunfd_os = tunfd
    os.set_blocking(tunfd_os, False)

    poll = select.poll()
    poll.register(tunfd_os, select.POLLIN)
    poll.register(rx.fileno(), select.POLLIN)

    try:
        while True:
            events = poll.poll(1000)
            for fd, ev in events:
                if not (ev & select.POLLIN):
                    continue

                # Uplink: TUN -> GTP-U -> UDP
                if fd == tunfd_os:
                    try:
                        inner = os.read(tunfd_os, 65535)
                    except BlockingIOError:
                        continue

                    if not inner:
                        continue
                    if not _looks_like_ip(inner):
                        continue

                    if args.print_inner:
                        dst = ".".join(str(b) for b in inner[16:20]) if len(inner) >= 20 else "?"
                        print(f"[tx] inner_len={len(inner)} inner_dst={dst}")

                    pkt = build_gtpu(tx_teid, inner, args.gtpu_mode, args.qfi, seq)
                    tx.sendto(pkt, (args.remote_n3, GTPU_PORT))
                    seq = (seq + 1) & 0xffff

                # Downlink: UDP -> decap -> TUN
                elif fd == rx.fileno():
                    try:
                        data, addr = rx.recvfrom(65535)
                    except BlockingIOError:
                        continue

                    teid, inner = parse_gtpu(data)
                    if teid is None or inner is None:
                        continue

                    if rx_set is not None and teid not in rx_set:
                        continue

                    if not inner:
                        continue

                    if not _looks_like_ip(inner):
                        continue

                    if args.print_inner:
                        src = ".".join(str(b) for b in inner[12:16]) if len(inner) >= 20 else "?"
                        dst = ".".join(str(b) for b in inner[16:20]) if len(inner) >= 20 else "?"
                        print(f"[rx] teid={teid} inner_len={len(inner)} {src}->{dst}")

                    try:
                        os.write(tunfd_os, inner)
                    except OSError as e:
                        print(f"[rx] TUN write failed: {e} (len={len(inner)})")

    except KeyboardInterrupt:
        pass
    finally:
        if not args.keep:
            try:
                run(["ip", "rule", "del", "pref", "100", "from", f"{ue_ip}/32", "lookup", args.table],
                    check=False, quiet=True)
                run(["ip", "route", "flush", "table", args.table], check=False, quiet=True)
                if args.n3_mac and args.access_if:
                    run(["ip", "neigh", "del", args.remote_n3, "dev", args.access_if], check=False, quiet=True)
                run(["ip", "link", "del", ifname], check=False, quiet=True)
            except Exception:
                pass


if __name__ == "__main__":
    main()
