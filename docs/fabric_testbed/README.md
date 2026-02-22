# L25GC+ Deployment on NSF FABRIC (Mellanox NICs)

This guide describes how to deploy **L25GC+ on the [NSF FABRIC testbed](https://portal.fabric-testbed.net/)** using **Mellanox NICs**. The workflow is:

1. Create a FABRIC slice using our provided artifact
2. Log into the provisioned nodes
3. Run setup scripts + install MLNX_OFED
4. Apply Mellanox-specific ONVM runtime/script settings (`--allow`, portmask, static ARP, routes)
5. Start the ONVM manager and run experiments

---

## 0. Create a FABRIC testbed using our artifact

We provide a pre-defined **FABRIC Artifact** that includes the topology and node configuration needed for L25GC+.

* Open the artifact here: **[L25GC+ FABRIC Artifact](https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7)**
* Use the artifact to create a new slice in the FABRIC portal.
* Once the slice is provisioned, SSH into the nodes from your local machine.

### Topology Notes (FABRIC)

* We have successfully deployed L25GC+ on FABRIC.
* Reference diagram:
  ![FABRIC Topology](./images/FABRIC.png)

> We add an additional bridge named `br-CNAN-CP` to enable the N2 interface connection between the gNB and AMF.

---

## 1. Install MLNX_OFED (Ubuntu 20.04 / 22.04)

Install Mellanox OFED using either NVIDIA’s official documentation or the provided script.

```bash
cd ./L25GC-plus/scripts
./install_ofed.sh
```

> The `install_ofed.sh` script supports **Ubuntu 20.04 and 22.04**.

<!-- **Recommended:** reboot after OFED installation to ensure the driver stack is loaded correctly. -->

---

## 2. Run the setup script on FABRIC nodes

Run `setup.sh` on each node (CN / UE / DN) to install L25GC+ and required packages.

* Before running the script, you may need to adjust network settings in:

  * `./L25GC-plus/scripts/set_nw_env.sh`

```bash
cd ./L25GC-plus/scripts
./setup.sh <ue|cn|dn>
```

---

## 3. Mellanox-specific ONVM runtime/script changes

On Mellanox NICs, you typically do **not** bind the NIC to a DPDK driver in the same way as some other NICs/environments, and you often need to **whitelist Mellanox PCI devices** when launching ONVM.

### 3.1 Configure `PORTMASK` for `onvm_mgr` on FABRIC CN nodes

On FABRIC, a CN node may expose **three NICs that are DPDK-usable**. For L25GC+ we typically use **two NICs for the user plane**. You must confirm which two NICs correspond to the user-plane links, and then configure the ONVM manager **port mask** accordingly.

#### Step 1: Identify DPDK-usable NICs and their ordering (index)

The **port index** used by ONVM/DPDK follows the device enumeration order. In practice, you can determine the ordering by:

* `ip a` output order (interfaces listed top-to-bottom), and/or
* `dpdk-devbind.py --status` (recommended when available)

Example commands:

```bash
ip a
# and/or
dpdk-devbind.py --status
```

Record the three candidate NICs and their indexes (0, 1, 2) according to the enumeration order.

#### Step 2: Decide which two NICs are used for the user plane

Based on your FABRIC topology (links connected to UP traffic), select **two** NICs among the three candidates.
For example, suppose the CN node has DPDK-usable NICs with indexes:

* NIC 0: `ensX` (not used for user plane)
* NIC 1: `ensY` (**user plane**)
* NIC 2: `ensZ` (**user plane**)

Then the user-plane NIC indexes are **1 and 2**.

#### Step 3: Build the portmask in binary (right-to-left), then convert to decimal

Construct a **binary portmask** where each bit indicates whether the corresponding NIC index is enabled:

* Bit for NIC index 0, then index 1, then index 2, … (from right to left as an index list)
* Use `1` for enabled NICs, `0` otherwise

Using the example above (enable NIC 1 and NIC 2, disable NIC 0):

* NIC 2 / NIC 1 / NIC 0  → `1 1 0`
* Binary portmask: `110`
* Decimal value: `6`

Another example:

* Enable NIC 0 and NIC 2: `101` (binary) = `5` (decimal)

#### Step 4: Pass the decimal portmask to ONVM manager via `-k`

Once you have the decimal portmask value, pass it to the ONVM manager startup script via `-k`.

> **If you use `--allow` (see Section 3.2):** DPDK only sees two ports (port 0 and port 1), so the correct portmask is **`-k 3`** (binary `11`). You can skip the manual calculation above.

For example (portmask decimal = 3):

```bash
# Example: add -k 3 to the onvm_mgr launch args
./scripts/run/run_onvm_mgr.sh -k 3
```

> Where to set it: depending on your workflow, `-k` may be part of `onvm/go.sh`, `run_manager.sh`, or another wrapper script that launches `onvm_mgr`. Update the script that actually invokes `onvm_mgr` so the correct `-k <PORTMASK_DECIMAL>` is always used on the CN node.

---

### 3.2 Whitelist Mellanox NICs (`--allow`) in ONVM manager launch

> **This step is optional.** The UPF-U forwarding code uses `pkt->port ^ 1` (XOR with 1) to swap packets between the access and core ports. This only works correctly when DPDK sees exactly **two** ports numbered 0 and 1. Without `--allow`, DPDK probes all three Mellanox NICs (ports 0, 1, 2), and the XOR logic sends packets to wrong ports.

First, find the PCI addresses of your **two data-plane NICs** (N3 and N6):

```bash
lspci | grep -i mell
# or
dpdk-devbind.py --status
```

Then pass them to the ONVM manager using `--allow <PCI_ADDR>` (repeat for each port), by editing the ONVM manager launch line in:

* `NFs/onvm-upf/scripts/start.sh`

Example:

```bash
ALLOW_LIST="${ONVM_ALLOW_LIST:-}"

sudo ./build/onvm/onvm_mgr/onvm_mgr -l "$cpu" -n 4 --proc-type=primary \
  ${ALLOW_LIST} ${virt_addr} -- -p ${ports} ...
```

This makes the allow-list configurable at runtime without re-editing files.

#### Runtime usage (recommended on FABRIC)

1) Export the allow-list on the **CN** node (replace PCI addresses with your N3/N6 NICs):

```bash
export ONVM_ALLOW_LIST="--allow 0000:08:00.0 --allow 0000:09:00.0"
```

2) Start ONVM manager normally (with `-k 3` when you allow exactly two ports):

```bash
./scripts/run/run_onvm_mgr.sh -k 3
```

> If you forget to export `ONVM_ALLOW_LIST`, ONVM/DPDK will launch **without** `--allow` filters and may enumerate all DPDK-usable Mellanox NICs on the node (often 3 ports: 0/1/2 on FABRIC). This can break the UPF-U `pkt->port ^ 1` port-swap assumption and may also accidentally take over a control-plane NIC.

Optional: set it inline (avoids forgetting the export):

```bash
ONVM_ALLOW_LIST="--allow 0000:08:00.0 --allow 0000:09:00.0" \
  ./scripts/run/run_onvm_mgr.sh -k 3
```

To clear it later:

```bash
unset ONVM_ALLOW_LIST
```

> Replace the PCI addresses with the actual Mellanox PCI addresses of the N3/N6 NICs on your FABRIC nodes. **Do not include the control-plane NIC** (used for N2/SCTP) — it must stay under kernel control.

---

### 3.3 Static ARP Entries on Remote Nodes (Required)

When DPDK/ONVM controls the data-plane NICs on the CN node, the Linux kernel on that node **can no longer respond to ARP requests** on those interfaces. This means Node1 (UERAN) and Node3 (DN) cannot dynamically learn the UPF's MAC addresses.

**You must add static ARP entries on Node1 and Node3** before running experiments, our setup script contain this part, but in case you setup error:

```bash
# On Node1 (UERAN): add static entry for UPF's N3 interface
sudo arp -s <UPF_N3_IP> <UPF_N3_MAC>
# Example: sudo arp -s 192.168.1.2 02:ff:9d:c8:0a:05

# On Node3 (DN): add static entry for UPF's N6 interface
sudo arp -s <UPF_N6_IP> <UPF_N6_MAC>
# Example: sudo arp -s 192.168.2.1 02:dc:be:a5:82:1d
```

To find the correct MAC addresses, run `ip link show <interface>` on the CN node **before** starting ONVM.

> Without static ARP, remote nodes send ARP requests that arrive at UPF-U and are silently dropped ("Not IP packet, ignore it"). Ping and all data-plane traffic will fail.

---

### 3.4 Add UE Subnet Route on DN Node

The DN node needs a route to send reply traffic back to UE addresses (e.g., `10.60.0.0/16`) through the UPF:

```bash
# On Node3 (DN):
sudo ip route add 10.60.0.0/16 via <UPF_N6_IP>
# Example: sudo ip route add 10.60.0.0/16 via 192.168.2.1
```

Without this route, the DN node does not know how to reach UE IP addresses and will drop reply packets.

---

### 3.5 Set MTU on FABRIC Interfaces

FABRIC links may use a non-standard MTU. Set all data-plane interfaces on every node to the same value (e.g., 1518) to avoid intermittent failures:

```bash
sudo ip link set <interface> mtu 1518
```

---

## 4. Run experiments

### Startup Order

Services on the CN node must be started in this order:

1. **ONVM Manager** — wait until port info is printed
2. **UPF-U** — wait for "NF_READY" message
3. **UPF-C** — wait for "NF_READY" message
4. **CP NFs** (`run_cp_nfs.sh`) — wait for "All NFs started"
5. (Optional) **Webconsole**

Then on Node1 (UERAN):

6. **gNB** — wait for "NG Setup procedure is successful"
7. **UE** — wait for "PDU Session establishment successful"

Other steps are similar. Please refer to:

* [Running L25GC+](https://github.com/nycu-ucr/L25GC-plus/tree/main/README.md#running-l25gc)

---

## 5. Access the CN Web Console from Your Laptop (SSH Tunnel)

If your web console service is running on the FABRIC CN node (for example on port **5000**), the recommended way to access it from your laptop is to use **SSH local port forwarding**.

### Customize for your FABRIC slice

The SSH command below includes **example values**. On your setup, the following fields will likely be different:

* **SSH private key path** (example: `.ssh/fabric_keys/slice_key`)
* **FABRIC SSH config file path** (example: `.ssh/fabric_ssh_config`)
* **CN node address** (IPv6/IPv4) and sometimes the **username**

### Option A: Forward `localhost:5000` → CN `localhost:5000`

Run the following command on your **laptop** (replace the values above with your own):

```bash
ssh -N \
  -i .ssh/fabric_keys/slice_key \
  -F .ssh/fabric_ssh_config \
  -L 5000:127.0.0.1:5000 \
  ubuntu@2001:48d0:6031:1991:f816:3eff:fe19:8d5a
```

Then open in your laptop browser:

* `http://localhost:5000`

### Option B: Use a different local port (recommended if 5000 is occupied)

If port 5000 on your laptop is already in use, map a different local port (e.g., **15000 → 5000**):

```bash
ssh -N \
  -i .ssh/fabric_keys/slice_key \
  -F .ssh/fabric_ssh_config \
  -L 15000:127.0.0.1:5000 \
  ubuntu@2001:48d0:6031:1991:f816:3eff:fe19:8d5a
```

Then browse:

* `http://localhost:15000`

### Notes

* `-N` means “do not run a remote shell” (keep the session only for the tunnel).
* `127.0.0.1` on the right-hand side forwards to the service bound on the CN node’s loopback interface.

  * If your service is bound to `0.0.0.0:5000`, this still works.
  * If your service is bound only to a specific CN interface IP, replace `127.0.0.1` with that interface IP.

---

## 6. Troubleshooting

### UPF-U prints "Not IP packet, ignore it"

ARP packets are arriving at DPDK because the remote node cannot resolve the UPF's MAC address.
**Fix:** Add static ARP entries on Node1 and Node3 (see Section 3.3).

### gNB cannot connect to AMF ("Connection refused" or timeout)

* Check that AMF is listening: `sudo ss -an | grep 38412` on Node2. You should see `LISTEN` on the correct CP address.
* Verify `ngapIpList` in `amfcfg.yaml` matches the CN node's control-plane interface IP.
* If DPDK grabbed the CP NIC by mistake, make sure your `--allow` flags only include data-plane NICs and restart ONVM.

### Control-plane ping (192.168.3.x) fails after starting ONVM

DPDK may have taken over the control-plane NIC. This happens when `--allow` is not used, causing DPDK to probe all Mellanox NICs.
**Fix:** Use `--allow` to restrict DPDK to the two data-plane NICs only (see Section 3.2).


### Ping through UE tunnel (`uesimtun0`) gets no reply

Check in order:

1. **Static ARP** on Node1 and Node3 (Section 3.3)
2. **UE subnet route** on Node3 (Section 3.4)
3. **Port indices** in `upf_u.yaml` match the actual DPDK port order (verify from ONVM manager port printout)
4. **MAC addresses** in `upf_u.yaml` (`dn_mac`, `an_mac`) match the actual neighbor interfaces