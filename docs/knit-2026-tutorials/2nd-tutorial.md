## Deploying L25GC+ on NSF FABRIC: Cluster Provisioning, Build, and Installation Tutorial

This tutorial provides a deployment-focused, end-to-end guide to running L25GC+ on NSF FABRIC for users who want full control over configuration and code. Participants will learn how to provision and manage a FABRIC cluster for L25GC+. We then walk through building the complete software stack—compiling dependencies, compiling and installing L25GC+. This tutorial is intended for researchers who plan to self-deploy L25GC+ for customized experiments, performance tuning, or development.

> Intended audience: advanced users, and researchers in cellular networks, people who attend Tutorial 1 and want more information to deploy dedicated core instance for experiments.

---

Here is the server information we will be using:

**Group A:**
```bash
ubuntu@2001:400:a100:3020:f816:3eff:feb4:ceb2 # (UE/RAN node)
ubuntu@2001:400:a100:3020:f816:3eff:fe6d:13c3 # (Core Network node)
ubuntu@2001:400:a100:3020:f816:3eff:fef8:6210 # (Data Network node)
```

**Group B:**
```bash
ubuntu@2001:400:a100:3020:f816:3eff:feb4:ceb2 # (UE/RAN node)
ubuntu@2001:400:a100:3020:f816:3eff:fe6d:13c3 # (Core Network node)
ubuntu@2001:400:a100:3020:f816:3eff:fef8:6210 # (Data Network node)
```

**Group C:**
```bash
ubuntu@2001:400:a100:3020:f816:3eff:feb4:ceb2 # (UE/RAN node)
ubuntu@2001:400:a100:3020:f816:3eff:fe6d:13c3 # (Core Network node)
ubuntu@2001:400:a100:3020:f816:3eff:fef8:6210 # (Data Network node)
```

You will be assigned a specific node.  Please do not use any servers not assigned to you. You may only use these servers for the tutorial; let me know if you want to keep playing with things after the session ends.


We have also released an artifact for creating clusters on Fabric: **[L25GC+ FABRIC Artifact](https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7)**

### Topology Setup
The experimental testbed consists of a UE/RAN node, a Core Network node, and a Data Network (DN) node, connected through three separate subnets. Subnet-1 is used for the N2 interface between the UE/RAN and the control-plane NFs in the 5G core. Subnet-2 is used for the N3 interface between the UE/RAN and the UPF-U. Subnet-3 is used for the N6 interface between the UPF-U and the DN.

![FABRIC Topology](./tutorial-topo.png)

### Example FABRIC Network and Interface Configuration
The screenshot below shows an example network and interface configuration after creating a cluster on the FABRIC testbed. 

In this example, `net1` corresponds to **Subnet-1**, which connects the UE/RAN and the N2 interface of the core network control plane. `net2` corresponds to **Subnet-2**, which connects the UE/RAN and the N3 interface in the core network. `net3` corresponds to **Subnet-3**, which connects the N6 interface in the core network and the DN.

Users should pay close attention to four pieces of information for each interface: 
- the node that the interface belongs to (**Node** column)
- the subnet that the interface belongs to (**Network** column)
- the name of the interface (**Physical Device** column)
- the IP address of the interface (**IP Address** column)


These details will be used later during system configuration.

![Example FABRIC Configuration](./sample-netconfig-on-fabric.png)

> The exact configuration may vary across users. For example, the subnet ranges and gateway IP addresses assigned to each network may be different in a different cluster.

---

## 1. Log into the Core Network node and Setup Environment
Open **a new terminal** and SSH into your assigned Core Network node.

After you log in, run these commands in the terminal.

### Step-1: Install MLNX_OFED on the Core Network node
```bash
cd ./L25GC-plus/scripts
./install_ofed.sh
```

### Step-2: Run the setup script to install L25GC+ on the Core Network node
```bash
cd ./L25GC-plus/scripts
./setup.sh cn
```

### Step-3: Configure AMF
> This step updates the AMF configuration in L25GC+ so that the gNB can reach the AMF over the **N2** interface. The IP configured here must match the actual N2 interface IP address on the Core Network node in your FABRIC cluster. This setting will also be used later when configuring the gNB.

The AMF configuration file is located at:
```bash
~/L25GC-plus/config/amfcfg.yaml
```

Open the file and find the `ngapIpList` field. By default, it is set to `127.0.0.1`, which must be replaced with the actual **N2 IP address** of the Core Network node. In the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration), this is the IP address assigned to `enp9s0` (i.e., `net1` interface on the node2), which is `10.133.9.3`. 

Change:

```yaml
ngapIpList:  # the IP list of N2 interfaces on this AMF
- 127.0.0.1
```

to:

```yaml
ngapIpList:  # the IP list of N2 interfaces on this AMF
- {N2_IP_ON_CN}
### Replace it with the actual N2 IP address of your own Core Network node! ###
```

> After this change, the AMF will listen on the correct N2 interface and accept NGAP connections from the gNB. If this IP is not configured correctly, the gNB will not be able to connect to the core network. 


### Step-4: Configure SMF
> This step updates the SMF configuration in L25GC+. The SMF needs to provide the correct **N3** interface IP address of the UPF-U during PDU session establishment, so that the gNB can forward user traffic to the UPF-U. The IP configured here must match the actual N3 interface IP address on the Core Network node in your FABRIC cluster.

The SMF configuration file is located at:
```bash
~/L25GC-plus/config/smfcfg.yaml
```

Open the file and find the `endpoints` field. By default, it is set to `127.0.0.8`, which must be replaced with the actual **N3 IP address** of the Core Network node. In the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration), this is the IP address assigned to `enp7s0` (i.e., `net2` interface on the node2), which is `10.133.8.3`. 

Change:

```yaml
...
  interfaces: # Interface list of the UPF-U
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3 interface on this UPF
       - 127.0.0.8
```

to:

```yaml
...
  interfaces: # Interface list of the UPF-U
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3 interface on this UPF
       - {N3_IP_ON_CN}
```

### Step-5: Configure UPF-U
> This step updates the UPF-U configuration in L25GC+. The UPF-U needs to use the correct **N3** and **N6** IP addresses, as well as the correct peer N3/N6 IP addresses for the UE/RAN node and DN node. These settings must match the actual network configuration of your FABRIC cluster.

The UPF-U configuration file is located at:
```bash
~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
```

The configuration file should look like this (based on the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration)):

```yaml
info:
  version: 1.0.0
  description: L25GC+ UPF-U Configuration

configuration:
  log_level: "warning" # trace, debug, info, warning, error, fatal, panic
  dataplane:
    upf_n3_ip: "{N3_IP_ON_CN}"    # N3 interface IP address on the Core Network node
    upf_n6_ip: "{N6_IP_ON_CN}"   # N6 interface IP address on the Core Network node
    an_peer_n3_ip: "{N3_IP_ON_UERAN_NODE}"  # N3 interface IP address on the UE/RAN node
    dn_peer_n6_ip: "{N6_IP_ON_DN}"          # N6 interface IP address on the DN node

    ports:
      n3_port: 0                     # NIC port used for N3 interface
      n6_port: 1                     # NIC port used for N6 interface
```

Make sure that all of these values match the actual interface IP addresses in your FABRIC cluster.

> **Note:** In the current implementation, `an_peer_n3_ip` and `dn_peer_n6_ip` must be set manually. We plan to improve this in a future revision so that these peer IP addresses no longer need to be configured explicitly.


## 2. Log into the UE/RAN node and Setup Environment
Open **a new terminal** and SSH into your assigned UE/RAN node.

After you log in, run these commands in the terminal.

### Step-1: Run the setup script to install UERANsim and OAI UE/RAN
```bash
cd ./L25GC-plus/scripts
./setup.sh ue
```

### Step-2: Add the L3 Route to DN server
> Since the UE and DN are in different L3 subnets, both the UERAN node and the DN node need static routes so that traffic is forwarded through the UPF-U.

On the UERAN node, add a route so that traffic destined for the DN server is sent through the UPF-U's N3 interface:

```bash
# On the UERAN node:
sudo ip route add <DN_SERVER_IP> via <N3_IP_on_UPF_U> dev <N3_INTERFACE_on_UERAN>

# Example:
sudo ip route add 10.133.10.2 via 10.133.9.3 dev enp8s0
```

- Here, `10.133.9.3` is the **UPF-U N3 IP**. It should match the `upf_n3_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```
- `N3_INTERFACE_on_UERAN` is the local network interface on the UERAN node that is connected to the **Subnet-2** as the UPF-U's N3 interface. In the example above, this interface is `enp8s0`.


### Step-3: Configure UERANsim (PDU Establishment only)
> This step updates the UERANsim gNB configuration so that the simulated gNB uses the correct **N2** and **N3** interface IP addresses and can connect to the **AMF** and **UPF-U** in the core network. These settings must match the actual network configuration of your FABRIC cluster.

The UERANsim gNB configuration file is located at:
```bash
~/L25GC-plus/UERANSIM/config/free5gc-gnb.yaml
```

In this file:
* `ngapIp` should be set to the gNB's **N2 interface IP address**. In the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration), this is the IP address assigned to `enp7s0` (i.e., `net1` interface on the **node1**), which is `10.133.9.2`. 
* `gtpIp` should be set to the gNB's **N3 interface IP address**. In the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration), this is the IP address assigned to `enp8s0` (i.e., `net2` interface on the **node1**), which is `10.133.8.2`.
* `amfConfigs.address` should be set to the **AMF's N2 interface IP address**. In the example shown in [Example FABRIC Network and Interface Configuration](#example-fabric-network-and-interface-configuration), this is the IP address assigned to `enp9s0` (i.e., `net1` interface on the **node2**), which is `10.133.9.3`.

For example, replace:

```yaml
...
  ngapIp: 127.0.0.1   # gNB's N2 Interface IP address
  gtpIp: 127.0.0.1    # gNB's N3 Interface IP address

  amfConfigs:
    - address: 127.0.0.1 # AMF's N2 interface IP address
```

with:

```yaml
...
  ngapIp: {N2_IP_ON_UERAN_NODE}   # gNB's N2 Interface IP address
  gtpIp:  {N3_IP_ON_UERAN_NODE}   # gNB's N3 Interface IP address

  amfConfigs:
    - address: {N2_IP_ON_CN}      # AMF's N2 interface IP address
```

Make sure these values match the actual interface IP addresses in your own FABRIC cluster.

### Step-4: Configure OAI UE/RAN simulator (PDU Establishment + Handover)
> This step updates the OpenAirInterface configuration files so that the gNBs, UE, and neighboring cell settings match the current testbed environment. In particular, you will configure the PLMN and slice information, set the correct N2 and N3 IP addresses, and prepare a second gNB for the N2 handover experiment.

#### 1. Edit the first gNB configuration

We first need to edit `gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf` because this file defines the gNB-side radio and network parameters used by OpenAirInterface. 

In this experiment, the gNB must be configured with the correct PLMN and slice information so that it matches the core network settings, and it must also use the correct IP addresses for the **N2** and **N3** interfaces so it can communicate with the **AMF** and **UPF-U** properly. 

Without these changes, the gNB would not be able to register to the core network or forward user traffic correctly.

Open and edit `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf`

```bash
vim ~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf
```

In this file, update the following three sections.

##### (a) Update `plmn_list` in the `gNBs` entry
<!-- We will edit three parts here, start with the entry inside `gNBs`, set `plmn_list` as follows. -->
```bash
    plmn_list = ({ mcc = 208; mnc = 93; mnc_length = 2; snssaiList = ({ sst = 0x01; sd = 0x010203; }) });
```

##### (b) Set `amf_ip_address` to the AMF's N2 interface IP address
<!-- then at around line 159, set `amf_ip_address` to AMF's N2 interface, ex: -->
```bash
    ////////// AMF parameters:
    amf_ip_address = ({ ipv4 = "192.168.3.2"; });
```

##### (c) Set the gNB's N2 and N3 interface IP addresses in `NETWORK_INTERFACES`
<!-- lastly, edit `GNB_IPV4_ADDRESS_FOR_NG_AMF` and `GNB_IPV4_ADDRESS_FOR_NGU` inside entry `NETWORK_INTERFACES` to gNB's N2 interface and gNB's N3 interface, ex: -->
```bash
    NETWORK_INTERFACES :
    {
        GNB_IPV4_ADDRESS_FOR_NG_AMF              = "192.168.3.1/24";
        GNB_IPV4_ADDRESS_FOR_NGU                 = "192.168.1.1/24";
        GNB_PORT_FOR_S1U                         = 2152; # Spec 2152
    };
```
`GNB_IPV4_ADDRESS_FOR_NG_AMF` should be the **gNB's N2 address**, and `GNB_IPV4_ADDRESS_FOR_NGU` should be the **gNB's N3 address**.

#### 2. Add IP addresses for the second gNB
Since the experiment performs an N2 handover, a **second gNB** is required. 
Assign one additional N2 IP address and one additional N3 IP address for the second gNB. For example:
```bash
# N2 interface
sudo ip a add 192.168.3.3/24 dev enp8s0

# N3 interface
sudo ip a add 192.168.1.3/24 dev enp7s0
```

#### 3. Edit the second gNB configuration
Next, edit `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci1.rfsim.conf` using the same steps as above.
<!-- After setting up second ip addresses, please follow the above edit gNB config steps and modify `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci1.rfsim.conf`.  -->

Make sure that:
- `amf_ip_address` is still set to the **AMF's N2 interface IP address**
- `GNB_IPV4_ADDRESS_FOR_NG_AMF` is set to the **second gNB's N2 address**
- `GNB_IPV4_ADDRESS_FOR_NGU` is set to the **second gNB's N3 address**

<!-- Please remember to set `GNB_IPV4_ADDRESS_FOR_NG_AMF` and `GNB_IPV4_ADDRESS_FOR_NGU` to new created addresses. -->

#### 4. Edit the neighbor cell configuration
Now edit `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/neighbour-config-rfsim.conf`
```bash
vim targets/PROJECTS/GENERIC-NR-5GC/CONF/neighbour-config-rfsim.conf
```

Inside `neighbour_list`, there are **two** `neighbour_cell_configuration` entries. Update the `plmn` field in both entries as follows:
```bash
        plmn                = { mcc = 208; mnc = 93; mnc_length = 2 };
```

##### 5. Edit the UE UICC configuration
Finally, edit `uicc0` in `~/L25GC-plus/openairinterface5g/ci-scripts/conf_files/nrue.uicc.conf`:
```bash
uicc0 = {
  imsi = "208930000000001";
  key = "8baf473f2f8fd09487cccbd7097c6862";
  opc= "8e27b6af0e692e750f32667a3b14605d";
  pdu_sessions = ({ dnn = "internet"; nssai_sst = 0x01; nssai_sd = 0x010203; });
}
```

**Notes**:
* Replace the example IP addresses above with the actual IP addresses in your FABRIC cluster.
* The subnet ranges and interface names may differ across testbeds.
* Be sure that the PLMN, slice, and UE subscription settings are consistent across the gNB, neighbor configuration, UE, and core network.

## 3. Log into the DN node and Setup Environment
Open **a new terminal** and SSH into your assigned DN node.

After you log in, run these commands in the terminal.

### Step-1: Run the setup script to install iperf3
```bash
cd ./L25GC-plus/scripts
./setup.sh dn
```

### Step-2: Add the L3 Route to UE
> Since the UE and DN are in different L3 subnets, both the UERAN node and the DN node need static routes so that traffic is forwarded through the UPF-U.

On the DN node, add a route so that reply traffic to the UE subnet (or a specific UE IP such as `10.60.0.1`) is sent through the UPF-U N6 interface:

```bash
# On the DN node:
sudo ip route add <UE_IP_or_SUBNET> via <N6_IP_on_UPF_U> dev <N6_INTERFACE_on_DN>

# Example:
sudo ip route add 10.60.0.1 via 10.133.10.3 dev enp7s0
```

- Here, `10.133.10.3` is the **UPF-U N6 IP**. It should match the `upf_n6_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```

- `N6_INTERFACE_on_DN` is the local network interface on the DN node that is connected to the **Subnet-3** as the UPF-U's N6 interface. In the example above, this interface is `enp7s0`.













## 1. Installation
Please refer to [this](https://github.com/nycu-ucr/L25GC-plus/tree/main/docs/fabric_testbed#1-install-mlnx_ofed) document section 1 to 3 for installation.

### Notes

* If you wish to perform handover experiment below, please run `./setup.sh ue oai` when installing ue.

* Make sure three nodes has interface ip like this:

    | Interface / Node | Node 1 (UE/RAN) | Node 2 (CN) | Node 3 (DN) |
    | :--- | :--- | :--- | :--- |
    | enp7s0 | 192.168.1.1 | 192.168.1.2 | 192.168.2.2 |
    | enp8s0 | 192.168.3.1 | 192.168.2.1 | x |
    | enp9s0 | x | 192.168.3.2 | x |
---

Use these commands to setup interface ip:
```bash
# add an address
sudo ip a add <IP/24> dev <interface>
# bring up an interface
sudo ip l set <interface> up
```

## 2. Configuration

### CN node
First edit `~/L25GC-plus/config/amfcfg.yaml`
```bash
cd ~/L25GC-plus
nano config/amfcfg.yaml
```
Replace ngapIpList IP from `127.0.0.1` to AMF's N2 interface, ex:
```bash
...
  ngapIpList:  # the IP list of N2 interfaces on this AMF
    - 192.168.3.2
```
Next edit `~/L25GC-plus/config/smfcfg.yaml`:
```bash
nano config/smfcfg.yaml
```
and in the entry inside `userplaneInformation / upNodes / UPF / interfaces / endpoints`, change the IP from `127.0.0.8` to UPF's N3 interface, ex:
```bash
...
  interfaces: # Interface list for this UPF
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3/N9 interface on this UPF
       - 192.168.1.2
```
Finally, edit `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`:
```bash
nano NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
```
in the entry inside `configuration / dataplane`, change `upf_access_ip`, and `upf_core_ip`, ex:
```bash
...
  dataplane:
    upf_access_ip: "192.168.1.2"    # UPF local IP on the access-facing port
    upf_core_ip: "192.168.1.2"      # UPF local IP on the core/SGi-facing port
``` 


---

## 3. Run experiments

### Startup Order

Services on the CN node must be started in this order:

1. **ONVM Manager** — wait until port info is printed
2. **UPF-U** — wait for "NF_READY" message
3. **UPF-C** — wait for "NF_READY" message
4. **CP NFs** (`run_cp_nfs.sh`) — wait for "All NFs started"
5. **Webconsole** - only need to be run once, please refer to [this](https://github.com/nycu-ucr/L25GC-plus/tree/main/docs/fabric_testbed#5-access-the-cn-web-console-from-your-laptop-ssh-tunnel).

⚠️ OAI gNB does not support multiple slice rules, please edit and remove rules make subscribers as follow image.

![subscriber](./images/subscriber.png)

Startup command please refer to:
* [Running L25GC+](https://github.com/nycu-ucr/L25GC-plus/tree/main/README.md#running-l25gc)

Then on Node1 (UERAN):

6. **gNB**:
```bash
cd ~/L25GC-plus/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-softmodem -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf --telnetsrv --telnetsrv.shrmod ci --gNBs.[0].min_rxtxtime 6 --rfsim --rfsimulator.[0].serveraddr 127.0.0.1
```
Log should shows "Received NGSetupResponse from AMF".

7. **UE**:
```bash
cd ~/L25GC-plus/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-uesoftmodem -r 106 --numerology 1 --band 78 -C 3619200000 --rfsim --uicc0.imsi 208930000000001 -O ../../../ci-scripts/conf_files/nrue.uicc.conf --rfsimulator.[0].serveraddr server
```
Log should shows "PDU Session establishment successful".

Use `ip a` to check whether the tunnel `oaitun_ue1 ` presented, if it exists, pdu session setup is success!✅

### Handover experiment

Continue with previous experiment, open another terminal on node 1 (UE/RAN) and start second gNB.
```bash
cd ~/L25GC-plus/openairinterface5g/cmake_targets/ran_build/build
sudo ./nr-softmodem -O ../../../targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci1.rfsim.conf   --rfsim --telnetsrv --telnetsrv.shrmod ci   --telnetsrv.listenport 9091   --gNBs.[0].min_rxtxtime 6   --rfsimulator.[0].serveraddr 127.0.0.1
```
On fourth terminal set oaitun_ue1 MTU
```bash
sudo ifconfig oaitun_ue1 mtu 1350
```
Then, start iperf3 on ue and dn node to observe throughput before and after handover.
```bash
# On UE/RAN Node:
iperf3 -c 192.168.2.2 -B 10.60.0.1
```
```bash
# On DN Node:
iperf3 -s -B 192.168.2.2
```
Replace `192.168.2.2` with the IP of your DN node. Assume 10.60.0.1 is the IP of UE (oaitun_ue1).

Open a fifth terminal to trigger N2 handover,
```bash
echo ci trigger_n2_ho 1,1 | nc 127.0.0.1 9090 && echo
```
If you can see traffic on second gNB and iperf3 throughput drop to 0 and recover back, then 
handover is success!✅