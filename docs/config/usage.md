# L25GC+ Usage Guide

This guide provides step-by-step instructions for setting up and running L25GC+ from scratch and test. 

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Initial Setup](#initial-setup)
3. [Network Configuration](#network-configuration)
4. [DPDK Driver Binding](#dpdk-driver-binding)
5. [Configuration Files](#configuration-files)
6. [Running L25GC+](#running-l25gc)
7. [Running UERANSIM](#running-ueransim)
8. [End-to-End Testing](#end-to-end-testing)

---

## Prerequisites

Before starting, ensure you have:

- **Three VMs or physical machines** representing:
  - **UE/AN (Access Network)**: User Equipment and gNB node
  - **CN (Core Network)**: Core network functions (AMF, SMF, UPF, etc.)
  - **DN (Data Network)**: Data network endpoint
- **Network interfaces** configured according to your topology
- **Root/sudo access** on all machines
- **Git** installed on all machines

---

## Initial Setup

### Step 1: Clone the Repository

On **each node** (UE/AN, CN, and DN), clone the L25GC+ repository:

```bash
cd ~
git clone https://github.com/nycu-ucr/L25GC-plus.git
cd ~/L25GC-plus
```

### Step 2: Run Setup Scripts

The setup process differs depending on which node you are configuring:

#### On UE/AN Node

```bash
cd ~/L25GC-plus
./scripts/setup.sh ue
```

This script will:
- Install required dependencies (CMake, build tools, etc.)
- Clone and build UERANSIM
- Set up the UE/RAN environment

**Expected Output:**
You should see messages indicating successful installation, and at the end:
```
UERANSIM successfully built.
```

#### On CN Node

```bash
cd ~/L25GC-plus
./scripts/setup.sh cn
```

This script will:
- Install L25GC+ Network Functions (NFs)
- Install and configure MongoDB
- Build WebConsole
- Set up DPDK development tools
- Configure system settings (IP forwarding, firewall)

**Note for FABRIC/Mellanox NICs:**
If you are using Mellanox NICs (e.g., on FABRIC testbed), you need additional steps:
- Install MLNX_OFED
- Build DPDK with `librte_mlx5_pmd` support
- Modify and rebuild ONVM
- Modify ONVM startup scripts

See the [Mellanox setup guide](../mellanox/README.md) for detailed instructions.

#### On DN Node

```bash
cd ~/L25GC-plus
./scripts/setup.sh dn
```

This script will configure the data network node.

---

## Network Configuration

### Understanding Network Environment Variables

The network configuration is managed through `scripts/set_nw_env.sh`. This file defines all network interface names, IP addresses, and MAC addresses used across the system.

**Important:** Before running any network setup scripts, you must review and modify `scripts/set_nw_env.sh` to match your actual network topology.

### Step 1: Configure Network Environment

Edit the network environment file to match your setup:

```bash
cd ~/L25GC-plus
nano scripts/set_nw_env.sh
```

**Key variables to configure:**

- **UE/AN Node:**
  - `UEIF`: Interface name (e.g., `ens1f0`)
  - `UEIF_IP`: IP address for UE interface (e.g., `192.168.1.1`)
  - `UEIF_SUBNET`: Subnet for UE interface (e.g., `192.168.1.0`)

- **CN Node:**
  - `CNANIF`: Interface name for AN connection (e.g., `ens1f0`)
  - `CNANIF_IP`: IP address for AN interface (e.g., `192.168.1.2`)
  - `CNANIF_MAC`: MAC address of CN AN interface
  - `CNDNIF`: Interface name for DN connection (e.g., `ens1f1`)
  - `CNDNIF_IP`: IP address for DN interface (e.g., `10.10.1.1`)
  - `CNDNIF_MAC`: MAC address of CN DN interface

- **DN Node:**
  - `DNIF`: Interface name (e.g., `ens1f1`)
  - `DNIF_IP`: IP address for DN interface (e.g., `10.10.1.2`)
  - `DNIF_SUBNET`: Subnet for DN interface (e.g., `10.10.1.0`)

need to configuration before run setup scripts!

## DPDK Driver Binding

**Important:** On the **CN node**, network interfaces must be bound to a compatible DPDK driver (e.g., `igb_uio`) before running L25GC+.

### Step 1: Identify Network Interfaces

First, identify the PCI addresses of your network interfaces:

```bash
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -s
```

This will show all network interfaces and their current driver bindings. Look for your interfaces (e.g., `ens1f0`, `ens1f1`) and note their PCI addresses (e.g., `0000:01:00.0`).

### Step 2: Bring Interfaces Down

Before binding to DPDK, you must bring the interfaces down:

```bash
# Replace <interface> with your actual interface name (e.g., ens1f0)
sudo ifconfig <interface> down
```

For example:
```bash
sudo ifconfig ens1f0 down
sudo ifconfig ens1f1 down
```

### Step 3: Bind to DPDK Driver

Bind each interface to the DPDK driver:

```bash
# Replace <PCIe_addr> with the actual PCI address from Step 1
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -b igb_uio <PCIe_addr>
```

For example:
```bash
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -b igb_uio 0000:01:00.0
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -b igb_uio 0000:01:00.1
```

### Step 4: Verify Binding

Verify that the interfaces are bound correctly:

```bash
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -s
```

You should see your interfaces listed with `igb_uio` as the driver.

**Note:** If you need to unbind interfaces later (e.g., to restore normal networking), you can use:
```bash
sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -b <original_driver> <PCIe_addr>
```

---

## Configuration Files

Before running L25GC+, you must configure several files to match your network topology. See the [Configuration Guide](README.md) for detailed instructions.

### Quick Configuration Checklist

1. **AMF Configuration** (`config/amfcfg.yaml`):
   - Set `ngapIpList` to CN's N2 interface IP (e.g., `172.16.1.2`)

2. **SMF Configuration** (`config/smfcfg.yaml`):
   - Set N3 interface `endpoints` to CN's N3 IP (e.g., `192.168.1.2`)

3. **UPF Configuration** (`NFs/onvm-upf/5gc/upf_u_complete/upf_u.txt` or `NFs/onvm-upf/5gc/upf_u/upf_u.yaml`):
   - Set DN MAC Address
   - Set AN MAC Address
   - Set UPF ID Address

4. **UERANSIM gNB Configuration** (`UERANSIM/config/free5gc-gnb.yaml`):
   - Set `ngapIp` to UE/AN's N2 interface IP (e.g., `172.16.1.1`)
   - Set `gtpIp` to UE/AN's N3 interface IP (e.g., `192.168.1.1`)
   - Set `amfConfigs.address` to CN's AMF IP (e.g., `172.16.1.2`)

---

## Running L25GC+

L25GC+ consists of multiple components that must be run in separate terminals. **All commands below should be run on the CN node**, unless otherwise specified.

### Terminal 1: ONVM Manager

The ONVM Manager is the core infrastructure that manages network functions.

```bash
cd ~/L25GC-plus
./scripts/run/run_onvm_mgr.sh
```

**What to expect:**
- The manager will start and display initialization messages
- It will bind to DPDK ports and allocate cores
- You should see messages indicating successful startup
- **Keep this terminal open** - the manager must remain running

**Troubleshooting:**
- If you see errors about DPDK ports, verify that interfaces are bound correctly (see [DPDK Driver Binding](#dpdk-driver-binding))
- If you see permission errors, ensure you have sudo access

### Terminal 2: UPF-U (User Plane Function - User Plane)

UPF-U handles the user plane data forwarding.

```bash
cd ~/L25GC-plus
./scripts/run/run_upf_u.sh 1 ./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
```

**Parameters:**
- `1`: Service ID for this UPF-U instance
- `./NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`: Path to UPF-U configuration file

**What to expect:**
- UPF-U will connect to the ONVM Manager
- You should see initialization messages
- **Keep this terminal open**

**Troubleshooting:**
- If you see "NF cannot start without a running ONVM manager", ensure Terminal 1 is running
- Verify the configuration file path is correct

### Terminal 3: UPF-C (User Plane Function - Control Plane)

UPF-C handles the control plane signaling for the UPF.

```bash
cd ~/L25GC-plus
./scripts/run/run_upf_c.sh 2 ./NFs/onvm-upf/5gc/upf_c/config/upfcfg.yaml
```

**Parameters:**
- `2`: Service ID for this UPF-C instance
- `./NFs/onvm-upf/5gc/upf_c/config/upfcfg.yaml`: Path to UPF-C configuration file

**What to expect:**
- UPF-C will connect to the ONVM Manager
- You should see initialization messages
- **Keep this terminal open**

### Terminal 4: L25GC+ Control Plane NFs

This starts all the 5G Core Network Functions (AMF, SMF, NRF, UDM, etc.).

```bash
cd ~/L25GC-plus
source ~/.bashrc
./scripts/run/run_cp_nfs.sh
```

**What to expect:**
- Multiple NFs will start sequentially:
  - NRF (Network Repository Function)
  - AMF (Access and Mobility Management Function)
  - SMF (Session Management Function)
  - UDR (Unified Data Repository)
  - PCF (Policy Control Function)
  - UDM (Unified Data Management)
  - NSSF (Network Slice Selection Function)
  - AUSF (Authentication Server Function)
  - CHF (Charging Function)
- Each NF will start on a different CPU core
- Logs are written to `log/` directory

**Viewing Logs:**
To view logs in real-time:
```bash
cd ~/L25GC-plus
tail -f log/*.log
```

To view a specific NF's log:
```bash
tail -f log/amf.log
tail -f log/smf.log
```

**Troubleshooting:**
- If you see "command not found" errors, ensure you've run `source ~/.bashrc`
- If NFs fail to start, check the log files in `log/` directory
- If your terminal becomes corrupted (broken prompt, arrow keys not working), run:
  ```bash
  reset
  ```

### Terminal 5: WebConsole (Optional but Recommended)

The WebConsole is used to manage subscribers (UEs) and configure QoS policies.

```bash
cd ~/L25GC-plus/webconsole
./bin/webconsole
```

**Access the WebConsole:**
- Open a web browser
- Navigate to: `http://<CN_IP>:5000`
- Default credentials:
  - Username: `admin`
  - Password: `free5gc`

**Creating a Subscriber:**
1. Log in to the WebConsole
2. Navigate to the Subscriber section
3. Create a new subscriber with:
   - IMSI (International Mobile Subscriber Identity)
   - Security keys (K, OP/OPc)
   - DNN (Data Network Name)
   - S-NSSAI (Single Network Slice Selection Assistance Information)

See the [WebConsole documentation](../webconsole/README.md) for detailed usage.

---

## Running UERANSIM

UERANSIM simulates the User Equipment (UE) and gNB (base station). **All commands below should be run on the UE/AN node**.

### Terminal 1: gNB (gNodeB)

The gNB is the 5G base station that connects to the core network.

```bash
cd ~/L25GC-plus/UERANSIM
./build/nr-gnb -c config/free5gc-gnb.yaml
```

**What to expect:**
- gNB will start and attempt to connect to AMF
- You should see connection messages
- **Keep this terminal open**

**Troubleshooting:**
- If connection fails, verify:
  - AMF is running on CN node
  - `ngapIp` and `amfConfigs.address` in `config/free5gc-gnb.yaml` are correct
  - Network connectivity between UE/AN and CN nodes

### Terminal 2: UE (User Equipment)

The UE simulates a 5G device.

```bash
cd ~/L25GC-plus/UERANSIM
sudo ./build/nr-ue -c config/free5gc-ue.yaml
```

**Note:** This requires `sudo` because it needs to create network interfaces.

**What to expect:**
- UE will start and attempt to register with the network
- You should see registration messages
- A new network interface (e.g., `uesimtun0`) will be created
- **Keep this terminal open**

**Troubleshooting:**
- If registration fails, verify:
  - gNB is running
  - Subscriber is created in WebConsole with matching IMSI
  - UE configuration matches subscriber data

### Terminal 3: Client 1 (Optional - for testing)

You can run network clients for testing. This is optional and depends on your testing needs.

```bash
# Example: Run a client application
# (This depends on your specific test setup)
```

### Terminal 4: Client 2 (Optional - for testing)

Similar to Terminal 3, for additional testing.

---

## End-to-End Testing

After all components are running, you can perform end-to-end tests.

### Test 1: Verify UE Registration

1. Check gNB terminal - should show UE registration messages
2. Check AMF log on CN node:
   ```bash
   tail -f ~/L25GC-plus/log/amf.log
   ```
   Should show registration accept messages

### Test 2: Ping Test (UE to DN)

On the **UE/AN node**, ping the DN:

```bash
# Get the UE's IP address (usually assigned by SMF)
ip addr show uesimtun0

# Ping DN IP (e.g., 10.10.1.2)
ping 10.10.1.2
```

**Expected result:**
- Ping should succeed
- You should see reply packets

**Troubleshooting:**
- If ping fails, check:
  - UPF-U and UPF-C are running
  - SMF log for session establishment: `tail -f ~/L25GC-plus/log/smf.log`
  - Network routes are configured correctly
  - ARP entries are set (see network setup scripts)

### Test 3: Data Transfer Test

You can use `iperf3` for bandwidth testing:

**On DN node:**
```bash
iperf3 -s
```

**On UE/AN node:**
```bash
iperf3 -c <DN_IP> -t 30
```

### Test 4: Check Session Status

On CN node, check SMF logs for session information:
```bash
tail -f ~/L25GC-plus/log/smf.log | grep -i session
```

---

## Stopping L25GC+

To stop all L25GC+ components:

### On CN Node

```bash
cd ~/L25GC-plus
./scripts/run/stop_cn.sh
```

This will stop all control plane NFs and ONVM components.

### Manual Stop

If the stop script doesn't work, you can manually stop processes:

```bash
# Stop control plane NFs
pkill -f "nr-gnb|nr-ue|amf|smf|nrf|udm|pcf|udr|nssf|ausf|chf"

# Stop ONVM components
sudo pkill -f "onvm_mgr|upf_u|upf_c"
```

---

## Common Issues and Solutions

### Issue: "NF cannot start without a running ONVM manager"

**Solution:** Ensure ONVM Manager (Terminal 1) is running before starting UPF-U or UPF-C.

### Issue: "Permission denied" when binding DPDK interfaces

**Solution:** Use `sudo` for DPDK binding commands.

### Issue: UE cannot register

**Solution:**
1. Verify subscriber is created in WebConsole
2. Check IMSI matches between UE config and subscriber
3. Verify network connectivity between UE/AN and CN
4. Check AMF logs for error messages

### Issue: Ping fails from UE to DN

**Solution:**
1. Verify UPF-U and UPF-C are running
2. Check SMF logs for session establishment
3. Verify network routes: `ip route show`
4. Check ARP entries: `arp -a`
5. Verify UPF configuration (MAC addresses, IPs)

### Issue: Terminal becomes corrupted

**Solution:** Run `reset` command to restore terminal.

---

## Next Steps

- Review the [Configuration Guide](README.md) for detailed configuration options
- Check the [WebConsole documentation](../webconsole/README.md) for subscriber management
- See the main [README](../../README.md) for architecture details

---

## Summary

**Setup Order:**
1. Clone repository on all nodes
2. Run `./scripts/setup.sh <ue|cn|dn>` on each node
3. Configure `scripts/set_nw_env.sh` for your topology
4. Bind DPDK interfaces on CN node
5. Configure AMF, SMF, UPF, and UERANSIM config files

**Running Order (CN Node):**
1. Terminal 1: `run_onvm_mgr.sh`
2. Terminal 2: `run_upf_u.sh`
3. Terminal 3: `run_upf_c.sh`
4. Terminal 4: `run_cp_nfs.sh`
5. Terminal 5: WebConsole (optional)

**Running Order (UE/AN Node):**
1. Terminal 1: `nr-gnb`
2. Terminal 2: `nr-ue` (with sudo)

Good luck with your L25GC+ deployment!

