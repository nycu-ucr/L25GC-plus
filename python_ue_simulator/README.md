# GTP-U UE Simulator (TUN ↔ UDP Shim)

`gtpu_shim.py` is a small Linux user-space shim that simulates the **UE/gNB-side GTP-U data plane** for 5G core / UPF experiments. It creates a **TUN interface** that behaves like a UE IP stack, then encapsulates inner IPv4 packets into **GTPv1-U T-PDU** over **UDP/2152** toward a remote UPF (N3), and decapsulates downlink GTP-U back into the TUN interface.

This is intended for **research/prototyping** and functional validation (ping/iperf) when you don’t want to run a full RAN emulator (e.g., UERANSIM) but still need realistic GTP-U framing.

---

## What This Tool Does

**Uplink path (UE → DN):**
1. Kernel routes UE-originated traffic into a TUN device (e.g., `uesimtun0`).
2. The shim reads inner IPv4 packets from the TUN fd.
3. The shim builds a GTPv1-U T-PDU:
   - `--gtpu-mode minimal`: 8-byte GTP header only.
   - `--gtpu-mode ueransim`: adds optional fields + extension header type `0x85` (PDU Session Container) with QFI.
4. The shim sends the GTP-U packet via UDP to `remote-n3:2152`.

**Downlink path (DN → UE):**
1. The shim listens on `local-n3:2152` for UDP packets.
2. It parses GTPv1-U T-PDU, extracts the inner IPv4 packet, and writes it to the TUN fd.
3. The kernel delivers that packet to local apps (ping/iperf client), as if it arrived from a UE interface.

---

## When To Use It

- You have a 3-node or multi-node setup where:
  - Node1 runs this shim + a traffic generator (ping/iperf client).
  - Node2 runs the UPF dataplane (DPDK/ONVM-based UPF-U).
  - Node3 is the data network (DN) host (iperf server).
- You want to compare UPF dataplane behavior/performance without coupling to a full RAN emulator.

---

## Requirements

- Linux host with:
  - `/dev/net/tun` available
  - `ip` (iproute2) installed
- Python 3.8+ (no third-party Python dependencies)
- Root privileges (needed to create/configure TUN and routing rules):
  - run with `sudo`
- IP connectivity between `local-n3` (this host) and `remote-n3` (UPF host) on the N3/N3-like network.

---

## Files

- `gtpu_shim.py`: the shim itself.

---

## Quick Start

### 1) Pick addresses

- **UE address on TUN** (inner, UE-side): e.g. `10.60.0.1/24`
- **N3 outer source IP** on this node: `--local-n3` (must exist on a real interface)
- **N3 outer destination IP** on UPF node: `--remote-n3`
- **DN server IP**: `--dn-ip`

### 2) Run the shim (recommended defaults)

```bash
sudo python3 gtpu_shim.py \
  --ue 10.60.0.1/24 \
  --local-n3 192.168.1.1 \
  --remote-n3 192.168.1.2 \
  --dn-ip 192.168.1.4 \
  --tx-teid 2 \
  --mtu 1450 \
  --tx-src-port 0 \
  --access-if enp94s0f1 \
  --n3-mac 3c:fd:fe:b3:17:4d
```


### 3) Generate traffic

Ping the DN IP:
```bash
ping -I uesimtun0 192.168.1.4
```

Run iperf (example):
```bash
iperf3 -c 192.168.1.4 -B 10.60.0.1
```

Notes:
- `-I uesimtun0` forces ping to use the UE interface.
- `-B 10.60.0.1` binds the iperf client to the UE IP so the policy rule applies.

---

## Command-Line Options

Run `sudo ./gtpu_shim.py -h` for the authoritative help. Summary:

### Required

- `--ue <IP/prefix>`: UE address assigned to TUN (e.g., `10.60.0.2/24`)
- `--local-n3 <IP>`: local outer source IP for N3 UDP socket (must exist on the host)
- `--remote-n3 <IP>`: remote outer destination IP (UPF side)
- `--dn-ip <IP>`: data network IP (informational; used in docs/examples)

### TUN & Routing

- `--tun <name>`: TUN name hint (default: `uesimtun0`)
- `--mtu <int>`: TUN MTU (default: `1450`)
- `--table <id/name>`: policy routing table (default: `100`)
- `--keep`: don’t delete TUN/rules/routes on exit

### GTP-U Encapsulation

- `--teid <int>`: legacy/default TEID (default: `1`)
- `--tx-teid <int>`: TEID used for uplink encapsulation (preferred over `--teid`)
- `--gtpu-mode minimal|ueransim`:
  - `minimal`: 8-byte GTPv1-U header only
  - `ueransim`: includes optional header + ext header type `0x85` for QFI (PDU Session Container)
- `--qfi <0-63>`: QFI value encoded in `ueransim` mode (default: `1`)
- `--seq-start <int>`: starting GTP-U sequence number (default: `0`)

### UDP Socket Details

- `--tx-src-port <int>`:
  - UDP source port for uplink packets (default: `2152`)
  - Recommended: `2153` (or `0` for ephemeral) to avoid conflicts with the RX socket which binds to 2152
  - If set to `0`, the OS selects an available ephemeral UDP port automatically

### RX Filtering (Optional)

- `--rx-teids <list>`: comma-separated allowlist of TEIDs accepted on RX.
  - If omitted or empty: accept ANY TEID
  - If list contains `0`: treat as wildcard (accept ANY)

### DPDK/No-ARP Environments (Optional)

If your UPF is DPDK-bound and won’t respond to ARP, you can pin a static neighbor entry:

- `--access-if <ifname>`: physical interface for the N3 link on this node
- `--n3-mac <mac>`: remote MAC to use for `--remote-n3` (static ARP/neighbor)

### Debug

- `--print-inner`: print basic inner packet info (slows down throughput; disable for benchmarking)

---

## Compatibility Notes (UPF Expectations)

This shim supports two common GTP-U layouts:

- **Minimal** (`--gtpu-mode minimal`): GTPv1-U header only.
- **UERANSIM-like** (`--gtpu-mode ueransim`): sets E=1 and includes extension header type `0x85`.

Important: Different stacks interpret extension header layout differently (“len-only” vs “type+len” variants). This shim’s `ueransim` mode uses the **len-only** layout that matches many lightweight/academic parsers.

If your UPF expects a different extension header layout, use `--gtpu-mode minimal` or adjust the builder/parser accordingly.

---

## Performance Notes

This is a **pure Python** per-packet loop with a **TUN** interface. Expect throughput to be limited by:
- user/kernel copies (TUN read + UDP send)
- per-packet Python overhead
- no batching

---

## Safety / Cleanup

By default the shim:
- creates a TUN device
- adds an `ip rule` (pref 100) and a routing table entry
- optionally adds a static neighbor entry

On exit it removes these unless `--keep` is provided.


