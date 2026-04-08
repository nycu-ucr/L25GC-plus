# L25GC+ Deployment on NSF FABRIC (Mellanox NICs)

This guide describes how to deploy **L25GC+ on the [NSF FABRIC testbed](https://portal.fabric-testbed.net/)** using **Mellanox NICs**. The workflow is:

1. Create a FABRIC slice using our provided artifact
2. Log into the provisioned nodes
3. Run setup scripts + install MLNX_OFED
4. Apply Mellanox-specific ONVM runtime/script settings (`--allow`, routes)
5. Start the ONVM manager and run experiments

---

## 0. Create a FABRIC testbed using our artifact

We provide a pre-defined **FABRIC Artifact** that includes the topology and node configuration needed for L25GC+.

* Open the artifact here: **[L25GC+ FABRIC Artifact](https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7)**
* Use the artifact to create a new slice in the FABRIC portal.
* Once the slice is provisioned, SSH into the nodes from your local machine.

### Reference Topology on FABRIC

  ![FABRIC Topology](./images/FABRIC.png)

---

## 1. Install MLNX_OFED

Install Mellanox OFED using either NVIDIA’s official documentation or the provided script.

```bash
cd ./L25GC-plus/scripts
./install_ofed.sh
```

> The `install_ofed.sh` script supports **Ubuntu 20.04 and 22.04**.

---

## 2. Run the setup script on FABRIC nodes

Run `setup.sh` on each node (CN / UE / DN) to install L25GC+ and required packages.

```bash
cd ./L25GC-plus/scripts
./setup.sh <ue|cn|dn>
```

---

## 3. Mellanox-specific ONVM runtime/script changes

> On Mellanox NICs, you typically do **not** bind the NIC to a DPDK driver in the same way as some other NICs/environments, and you often need to **whitelist Mellanox PCI devices** when launching ONVM.

### 3.1 Whitelist Mellanox NICs (`--allow`) in ONVM manager launch

First, find the PCI addresses of your **two user-plane NIC ports** (N3 and N6):

```bash
lspci | grep -i mell
# or
dpdk-devbind.py --status
```

Then pass them to the ONVM manager using `-a`:

* `./scripts/run/run_onvm_mgr.sh -a "0000:08:00.0 0000:09:00.0"`

> Replace the PCI addresses with the actual Mellanox PCI addresses of the N3/N6 NICs on your FABRIC nodes. **Do not include the control-plane NIC** (used for N2/SCTP) — it must stay under kernel control.

---

### 3.2 Add L3 Routes on the UERAN Node and DN Node

Since the UE and DN are in different L3 subnets, both the UERAN node and the DN node need static routes so that traffic is forwarded through the UPF-U.

On the DN node, add a route so that reply traffic to the UE subnet (or a specific UE IP such as `10.60.0.1`) is sent through the UPF-U core-side interface:

```bash
# On the DN node:
sudo ip route add <ue_ip_or_subnet> via <upf_core_ip> dev <interface>

# Example:
sudo ip route add 10.60.0.1 via 10.133.10.3 dev enp7s0
```

- Here, `10.133.10.3` is the **UPF local IP on the core-side interface**. It should match the `upf_core_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```

- `interface` is the local network interface on the DN node that is connected to the same subnet as the UPF-U core-side interface. In the example above, this interface is `enp7s0`.

Similarly, on the UERAN node, add a route so that traffic destined for the DN server is sent through the UPF-U access-side interface:

```bash
# On the UERAN node:
sudo ip route add <dn_server_ip> via <upf_access_ip> dev <interface>

# Example:
sudo ip route add 10.133.10.2 via 10.133.9.3 dev enp8s0
```

- Here, `10.133.9.3` is the **UPF local IP on the access-side interface**. It should match the `upf_access_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```
- `interface` is the local network interface on the UERAN node that is connected to the same subnet as the UPF-U access-side interface. In the example above, this interface is `enp8s0`.

---

### 3.4 Set MTU on FABRIC Interfaces

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

### gNB cannot connect to AMF ("Connection refused" or timeout)

* Check that AMF is listening: `sudo ss -an | grep 38412` on Node2. You should see `LISTEN` on the correct CP address.
* Verify `ngapIpList` in `amfcfg.yaml` matches the CN node's control-plane interface IP.
* If DPDK grabbed the CP NIC by mistake, make sure your `--allow` flags only include data-plane NICs and restart ONVM.

### Control-plane ping (192.168.3.x) fails after starting ONVM

DPDK may have taken over the control-plane NIC. This happens when `--allow` is not used, causing DPDK to probe all Mellanox NICs.
**Fix:** Use `--allow` to restrict DPDK to the two data-plane NICs only (see Section 3.2).

### Ping through UE tunnel (`uesimtun0`) gets no reply

Check in order:

1. **UE subnet route** on Node3 (Section 3.3)
2. **Port indices** in `upf_u.yaml` match the actual DPDK port order (verify from ONVM manager port printout)