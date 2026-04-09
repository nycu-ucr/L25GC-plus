## Deploying L25GC+ on NSF FABRIC: Cluster Provisioning, Build, and Installation Tutorial

This tutorial provides a deployment-focused, end-to-end guide to running L25GC+ on NSF FABRIC for users who want full control over configuration and code. Participants will learn how to provision and manage a FABRIC cluster for L25GC+. We then walk through building the complete software stack—compiling dependencies, compiling and installing L25GC+. This tutorial is intended for researchers who plan to self-deploy L25GC+ for customized experiments, performance tuning, or development.

> Intended audience: advanced users, and researchers in cellular networks, people who attend Tutorial 1 and want more information to deploy dedicated core instance for experiments.

---

### Topology Setup
The experimental testbed consists of a UE/RAN node, a Core Network (CN) node, and a Data Network (DN) node, connected through three separate subnets. `subnet-1` is used for the N2 interface between the UE/RAN and the control-plane NFs in the 5G core. `subnet-2` is used for the N3 interface between the UE/RAN and the UPF-U. `subnet-3` is used for the N6 interface between the UPF-U and the DN.

![FABRIC Topology](./tutorial-topo.png)

---

### Step-0: Create and Configure Your FABRIC Cluster

Before starting the tutorial, please create your own FABRIC cluster using our artifact:

**L25GC+ FABRIC Artifact:**
[https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7](https://artifacts.fabric-testbed.net/artifacts/078e8c8d-eb8d-4279-b711-85fb217a7db7)

The artifact helps you:

- create a three-node L25GC+ cluster on FABRIC (UE/RAN, Core Network, and Data Network);
- build and submit the required topology, including the inter-node networks for N2, N3, and N6 connectivity;
- provision the nodes and configure their network interfaces automatically;
- assign IP addresses and set up the routing needed by the experiment;
- install the required software stack on each node;
- configure key L25GC+ components, including AMF, SMF, and UPF-U, using the generated network settings;
- configure UERANSIM and OAI-based UE/RAN components for PDU session establishment, handover, and end-to-end traffic experiments.

Please complete the artifact setup first, then continue with the rest of the tutorial steps on your own FABRIC cluster.

---

### Step-1: Provision UE Subscription Data in the CN's Database
> Next, we need to use the WebConsole (adapted from free5GC) to provision UE subscription data in the CN's database (MongoDB). It provides the necessary subscriber information that enables L25GC+ to authenticate the UE and establish services correctly during PDU Session Establishment.

Open **a new terminal** and SSH into your assigned Core Network node.

After you log in, run these commands in the terminal.

#### Run Webconsole server on the CN node
```bash
cd ~/L25GC-plus/webconsole/ 
./bin/webconsole
```

#### Access the Webconsole from your laptop browser
After the Webconsole service is running on the CN node, you can access it from your laptop browser by enabling **SSH local port forwarding**.

Open **a new terminal on your laptop** and run the following command to set up **SSH local port forwarding**. See the **example** below. On your setup, the following fields will likely be different, so replace them with your own values:

* **SSH private key path** (example: `.ssh/fabric_keys/slice_key`)
* **FABRIC SSH config file path** (example: `.ssh/fabric_ssh_config`)
* **CN node address**

```bash
ssh -N \
  -i .ssh/fabric_keys/slice_key \
  -F .ssh/fabric_ssh_config \
  -L 5000:127.0.0.1:5000 \
  ubuntu@<CN_NODE_ADDRESS>
```

Then open in your laptop browser:

* `http://localhost:5000`

> If port 5000 on your laptop is already in use, map a different local port (e.g., **15000 → 5000**).

#### Provision UE Subscription Data
Then follow the steps below to provision the UE subscription data.

##### (1) Log in to the Webconsole
Open the Webconsole in your browser.

Use the following default credentials:

- **Username:** `admin`
- **Password:** `free5gc`

<p align="center">
  <img src="./webconsole/webconsole-login.png" alt="WebConsole Login" width="30%">
</p>

##### (2) Go to **SUBSCRIBERS**
After logging in, use the left sidebar and click **SUBSCRIBERS**.

If no subscriber has been created yet, you will see a page showing **No Subscription**.  
Click **CREATE** to add a new UE subscriber.

<p align="center">
  <img src="./webconsole/webconsole-create-sub-button.png" alt="WebConsole Create Sub Button" width="30%">
</p>

##### (3) Remove the default flow rules
You will be taken to the subscriber creation page.

Most fields are already pre-filled for this tutorial, but you need to make one manual change.

<p align="center">
  <img src="./webconsole/webconsole-create-sub-panel.png" alt="WebConsole Create Sub Panel" width="70%">
</p>

Each subscriber includes two slices by default, and each slice contains a **Flow Rule**.  
Since the later experiments use **OAI gNB**, and **OAI gNB does not support multiple slice rules**, you need to remove the default flow rule(s) before creating the subscriber.

In the **Flow Rules** section, click the red **DELETE** button at the upper-right corner of the rule panel to remove the rule.

<p align="center">
  <img src="./webconsole/webconsole-flow-rule-1.png" alt="Delete the default flow rule" width="70%">
</p>

Do the same for the 2nd slice.

<p align="center">
  <img src="./webconsole/webconsole-flow-rule-2.png" alt="Delete the default flow rule in the other slice" width="70%">
</p>

Then scroll to the bottom of the page and click **CREATE**.

##### (4) Create the subscriber
At the bottom of the page, click **CREATE** to create the UE subscription.

<p align="center">
  <img src="./webconsole/webconsole-create-sub-final.png" alt="WebConsole Create Sub Final" width="70%">
</p>

##### (5) Confirm the creation
After the subscriber is created successfully, the Webconsole will return to the subscriber list page, where you should see the new subscriber entry.

<p align="center">
  <img src="./webconsole/webconsole-done.png" alt="WebConsole Done" width="70%">
</p>

---

### Step-1: Testing L25GC+ with UERANsim

> In this experiment, we will bring up all NFs for L25GC+ on the CN node. Then we will bring up the UERANsim's gNB and UE on the UERAN node to trigger UE Registration and PDU Session Establishment. We will next test the connectivity between the UERAN node and DN node via ping. We will finally do the throughput test between the UE (iperf3 client) and the DN server (iperf3 server).

---

## 1. Log into the Core Network node and Setup Environment
Open **a new terminal** and SSH into your assigned Core Network node.

After you log in, run these commands in the terminal.

### Clone L25GC+ Repository
```bash
cd ~/
git clone https://github.com/nycu-ucr/L25GC-plus.git
```

### Step-1: Install MLNX_OFED on the Core Network node
```bash
cd ~/L25GC-plus/scripts
yes y | bash ./install_ofed.sh
```

### Step-2: Run the setup script to install L25GC+ on the Core Network node
```bash
cd ~/L25GC-plus/
yes y | ./scripts/setup.sh cn
```



## 2. Log into the UE/RAN node and Setup Environment
Open **a new terminal** and SSH into your assigned UE/RAN node.

After you log in, run these commands in the terminal.

### Clone L25GC+ Repository
```bash
cd ~/
git clone https://github.com/nycu-ucr/L25GC-plus.git
```

### Step-1: Run the setup script to install UERANsim and OAI UE/RAN
```bash
cd ~/L25GC-plus/
yes y | ./scripts/setup.sh ue
```

## 3. Log into the DN node and Setup Environment
Open **a new terminal** and SSH into your assigned DN node.

After you log in, run these commands in the terminal.

### Clone L25GC+ Repository
```bash
cd ~/
git clone https://github.com/nycu-ucr/L25GC-plus.git
```

### Step-1: Run the setup script to install iperf3
```bash
cd ~/L25GC-plus/
yes y | ./scripts/setup.sh dn
```

---



## 4. Testing L25GC+ with OAI UE/RAN (PDU Session Establishment + Handover)

### Startup Order

Services on the CN node must be started in this order:

1. **ONVM Manager** — wait until port info is printed
2. **UPF-U** — wait for "NF_READY" message
3. **UPF-C** — wait for "NF_READY" message
4. **CP NFs** (`run_cp_nfs.sh`) — wait for "All NFs started"
5. **Webconsole** - only need to be run once, please refer to [this](https://github.com/nycu-ucr/L25GC-plus/tree/main/docs/fabric_testbed#5-access-the-cn-web-console-from-your-laptop-ssh-tunnel).

⚠️ OAI gNB does not support multiple slice rules, please edit and remove rules make subscribers as follow image.

![subscriber](./subscriber.png)

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

Use `ip a` to check whether the tunnel `oaitun_ue1` presented, if it exists, pdu session setup is success!✅

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