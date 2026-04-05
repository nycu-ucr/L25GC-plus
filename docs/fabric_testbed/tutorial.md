# Full L25GC+ Deployment on NSF FABRIC (Mellanox NICs) and experiment

This guide describes how to deploy **L25GC+ on the [NSF FABRIC testbed](https://portal.fabric-testbed.net/)** using **Mellanox NICs**, and run experiment. The workflow is:

0. Log into the provisioned nodes
1. Installation
2. Configuration
3. Start the ONVM manager and run experiments


---

## 0. Log into FABRIC testbed cluster

We provide a pre-setuped **FABRIC Cluster** that includes the topology and node configuration needed for L25GC+.

* Artifact uses to create cluster: **[L25GC+ FABRIC Artifact](https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7)**

### Topology Notes (FABRIC)

* We have successfully deployed L25GC+ on FABRIC.
* Reference diagram:
  ![FABRIC Topology](./images/FABRIC.png)

> We add an additional bridge named `br-CNAN-CP` to enable the N2 interface connection between the gNB and AMF.

---

## 1. Installation

Please refer to [this](https://github.com/nycu-ucr/L25GC-plus/tree/main/docs/fabric_testbed#1-install-mlnx_ofed) document for installation.

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

## 3. Configuration

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
### UE node

First edit `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf`

```bash
cd ~/L25GC-plus/openairinterface5g
nano targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci0.rfsim.conf
```
We will edit three parts here, start with the entry inside `gNBs`, set `plmn_list` as follows.
```bash
    plmn_list = ({ mcc = 208; mnc = 93; mnc_length = 2; snssaiList = ({ sst = 0x01; sd = 0x010203; }) });
```
then at around line 159, set `amf_ip_address` to AMF's N2 interface, ex:
```bash
    ////////// AMF parameters:
    amf_ip_address = ({ ipv4 = "192.168.3.2"; });
```
lastly, edit `GNB_IPV4_ADDRESS_FOR_NG_AMF` and `GNB_IPV4_ADDRESS_FOR_NGU` inside entry `NETWORK_INTERFACES` to gNB's N2 interface and gNB's N3 interface, ex:
```bash
    NETWORK_INTERFACES :
    {
        GNB_IPV4_ADDRESS_FOR_NG_AMF              = "192.168.3.1/24";
        GNB_IPV4_ADDRESS_FOR_NGU                 = "192.168.1.1/24";
        GNB_PORT_FOR_S1U                         = 2152; # Spec 2152
    };
```
In the following experiment we are going to perform n2 handover experiment, therefore, we need to set up another N2, N3 interface ip address for the second gNB, ex:
```bash
# N2 interface
sudo ip a add 192.168.3.3/24 dev enp8s0
# N3 interface
sudo ip a add 192.168.1.3/24 dev enp7s0
```
After setting up second ip addresses, please follow the above edit gNB config steps and modify `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/gnb.sa.band78.fr1.106PRB.pci1.rfsim.conf`. 

Please remember to set `GNB_IPV4_ADDRESS_FOR_NG_AMF` and `GNB_IPV4_ADDRESS_FOR_NGU` to new created addresses.

Next, edit `~/L25GC-plus/openairinterface5g/targets/PROJECTS/GENERIC-NR-5GC/CONF/neighbour-config-rfsim.conf`
```bash
nano targets/PROJECTS/GENERIC-NR-5GC/CONF/neighbour-config-rfsim.conf
```
inside `neighbour_list` there are **two** `neighbour_cell_configuration`, edit both `plmn` as follow:
```bash
        plmn                = { mcc = 208; mnc = 93; mnc_length = 2 };
```
Finally, edit `uicc0` inside `~/L25GC-plus/openairinterface5g/ci-scripts/conf_files/nrue.uicc.conf` like this:
```bash
uicc0 = {
  imsi = "208930000000001";
  key = "8baf473f2f8fd09487cccbd7097c6862";
  opc= "8e27b6af0e692e750f32667a3b14605d";
  pdu_sessions = ({ dnn = "internet"; nssai_sst = 0x01; nssai_sd = 0x010203; });
}
``` 

---

## 4. Run experiments

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