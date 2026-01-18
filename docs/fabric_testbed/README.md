# L25GC+ Deployment on NSF FABRIC (Mellanox NICs)

This guide describes how to deploy **L25GC+ on the [NSF FABRIC testbed](https://portal.fabric-testbed.net/)** using **Mellanox NICs**. The workflow is:

1. Create a FABRIC slice using our provided artifact
2. Log into the provisioned nodes
3. Run setup scripts + install MLNX_OFED
4. Apply Mellanox-specific ONVM runtime/script settings (PCI whitelist, disable binding check)
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

For example (portmask decimal = 3):

```bash
# Example: add -k 3 to the onvm_mgr launch args
./scripts/run/run_onvm_mgr.sh -k 3
```

> Where to set it: depending on your workflow, `-k` may be part of `onvm/go.sh`, `run_manager.sh`, or another wrapper script that launches `onvm_mgr`. Update the script that actually invokes `onvm_mgr` so the correct `-k <PORTMASK_DECIMAL>` is always used on the CN node.

---

### 3.2 (Optional) Whitelist Mellanox NICs (PCI addresses) in ONVM manager launch

On FABRIC, Mellanox NIC PCI addresses vary by site/node. Find the NIC PCI addresses using:

```bash
lspci | grep -i mell
```

Then pass them to the ONVM manager using `-w <PCI_ADDR>` (repeat for each port), by editing the ONVM manager launch line in:

* `$HOME/onvm/onvm-upf/onvm/go.sh`

Example:

```diff
@@ -269,7 +269,7 @@ fi
 sudo rm -rf /mnt/huge/rtemap_*
 # watch out for variable expansion
 # shellcheck disable=SC2086
-sudo "$SCRIPTPATH"/onvm_mgr/"$RTE_TARGET"/onvm_mgr -l "$cpu" -n 4 --proc-type=primary ${virt_addr} -- -p ${ports} -n ${nf_cores} ${num_srvc} ${def_srvc} ${stats} ${stats_sleep_time} ${verbosity_level} ${ttl} ${packet_limit} ${shared_cpu_flag}
+sudo "$SCRIPTPATH"/onvm_mgr/"$RTE_TARGET"/onvm_mgr -l "$cpu" -n 4 --proc-type=primary -w 07:00.0 -w 09:00.0 ${virt_addr} -- -p ${ports} -n ${nf_cores} ${num_srvc} ${def_srvc} ${stats} ${stats_sleep_time} ${verbosity_level} ${ttl} ${packet_limit} ${shared_cpu_flag}
```

> Replace `07:00.0` / `09:00.0` with the actual Mellanox PCI addresses on your FABRIC nodes.

---

## 4. Run experiments

Other steps are similar to the CloudLab workflow. Please refer to:

* [Running L25GC+](https://github.com/nycu-ucr/L25GC-plus/tree/main/README.md#running-l25gc)
