# L25GC+: A Low-latency, 3GPP-compliant 5G Core Network
## About

**L25GC+** is a re-architected 5G Core (5GC) that reduces latency and improves user experience by minimizing control plane impact on the data plane and optimizing packet processing. Built on [free5GC](https://free5gc.org/forum/) and [OpenNetVM](https://sdnfv.github.io/onvm/), L25GC+ uses [X-IO](https://shixiongqi.github.io/_pages/papers/xio-netsoft23.pdf) to eliminate message serialization and HTTP overheads in 3GPP SBI, enabling fast, synchronous communication between NFs. L25GC+ integrates with free5GC NFs via compatible SBI APIs from X-IO, easing adoption with minimal code changes. In testbed evaluations, L25GC+ achieves 2× lower data plane latency during paging and handover compared to free5GC.

For more design details, please refer to:
- SIGCOMM 2022: [L25GC: A Low Latency 5G Core Network based on High-Performance NFV Platforms](docs/papers/l25gc.pdf)
- CloudNet 2023: [L25GC+: An Improved, 3GPP-compliant 5G Core for Low-latency Control Plane Operations](docs/papers/l25gc+.pdf)


## Build and Installation
- **Tested OS**: See [Tested OS Distributions](#tested-os-distributions)
- **NIC Requirement**: You need at least **two** [DPDK-compatible NICs](https://core.dpdk.org/supported/nics/) to run L25GC+. 

- Reference topology:
    ![ref_architecture](./docs/config/ref_architecture.png)

### Experiment Setup

1. Configure `N2`, `N3`, and `UPF-U` on the CN node.
2. Configure `UERANSIM` on the UE/AN node.
3. Update IP routes and ARP settings in `scripts/set_nw_env.sh` for both UE/AN and DN nodes.
4. Refer to our [setup guide](./docs/config/README.md) and instructional [video]() for step-by-step instructions.

---

### Installation
1. Run the setup script on target machine
    ```bash
    ./scripts/setup.sh <ue|cn|dn>
    ```

2. NIC interface on `CN` node must be bound to a [compatible DPDK driver](https://core.dpdk.org/supported/nics/) (e.g., `igb_uio`).  
    > *Note:* In some environments, the interface must be brought down before binding.

    ```bash
    sudo ifconfig <interface> down
    sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -s
    sudo ~/L25GC-plus/NFs/onvm-upf/subprojects/dpdk/usertools/dpdk-devbind.py -b igb_uio <PCIe addr>
    ```

---

## Running L25GC+
You can use our provided [scripts](scripts/run/) to launch onvm_mgr and L25GC+ NFs. This script assumes the `L25GC-plus` folder is your working directory.

1. **Run ONVM Manager**
    ```bash
    ./scripts/run/run_onvm_mgr.sh
    ```
2. **Run UPF-U** (new terminal)
    ```bash
    ./scripts/run/run_upf_u.sh 1 ./NFs/onvm-upf/5gc/upf_u_complete/upf_u.txt
    ```
3. **Run UPF-C** (new terminal)
    ```bash
    ./scripts/run/run_upf_c.sh 2 ./NFs/onvm-upf/5gc/upf_c_complete/config/upfcfg.yaml
    ```
4. **Run 5GC Network Functions (NFs)** (new terminal)
    ```bash
    source ~/.bashrc
    ./scripts/run/run_cp_nfs.sh
    ```
5. **Run Webconsole** (new terminal)
    > The webconsole is used to pre-store UE info in MongoDB for authentication and configure QoS.
    ```bash
    cd webconsole/ 
    ./bin/webconsole
    ```
    See this [video]() or [doc](docs/webconsole/README.md) for usage instructions.
6. **Stop L25GC+**
    ```bash
    ./scripts/run/stop_cn.sh
    ```

## Running UERANSIM
This script assumes the `L25GC-plus/UERANSIM` folder is your working directory.

1. **Run gNB**
    ```bash
    ./build/nr-gnb -c config/free5gc-gnb.yaml
    ```
2. **Run UE** (new terminal)
    ```bash
    sudo ./build/nr-ue -c config/free5gc-ue.yaml
    ```

## Unit test
1. **Ping Test (UE to DN)**
    ```bash
    # on UE/RAN node
    ping -I uesimtun0 192.168.1.4
    ```
    Replace `192.168.1.4` with the IP of your DN node.
2. **iperf3 Throughput Test**
    ```bash
    # On DN Node:
    iperf3 -s -B 192.168.1.4
    ```

    ```bash
    # On UE/RAN Node:
    iperf3 -c 192.168.1.4 -B 10.60.0.1
    ```
    Replace `192.168.1.4` with the IP of your DN node. Assume `10.60.0.1` is the IP of `UE` (`uesimtun0`).
## Tested OS Distributions

| OS Distribution | Status                        | Notes                                                                                |
| --------------- | ----------------------------- | ------------------------------------------------------------------------------------ |
| Ubuntu 24.04    | ⚠️ Untested                   | All dependencies available via `apt` or `pip` |
| Ubuntu 22.04    | ✅ Works out of the box        | All dependencies available via `apt` or `pip`                                        |
| Ubuntu 20.04    | ⚠️ Requires extra setup       | `numa.pc` must be manually added for Meson; may require newer GCC or Meson from pip  |
| Ubuntu 18.04    | ⚠️ Untested                   | Likely requires upgrading GCC, Python, and installing recent Meson manually |

> 💡 For Ubuntu 20.04: See [MANUAL_INSTALL.md](./MANUAL_INSTALL.md#additional-setups-on-ubuntu-2004) to install a `pkg-config` file for `libnuma` and upgrade `meson`.

---

## Dependency Versions

| Component       | Version          | Installation Notes                               |
| --------------- | ---------------- | ------------------------------------------------ |
| **DPDK**        | `24.07.0`        | Built from source using Meson                    |
| **Pktgen-DPDK** | `24.07.0`        | Compatible with the same DPDK version            |
| **dpdk-kmods**  | `commit@9b182be` | Required only for `igb_uio` (optional)           |
| **Meson**       | `>=0.58.0`       | Recommended: `0.61.2+`; use `pip3 install meson` |
| **Ninja**       | `>=1.10.0`       | Usually installed via `apt`                      |

---

## Submodules in `L25GC-plus/NFs/`

The `NFs/` directory contains X-IO and all the L25GC+ NFs.

| Module      | Description                                                                 | Language | Commit   |
|-------------|-----------------------------------------------------------------------------|----------|----------|
| `amf`       | Access and Mobility Management Function — handles UE registration and mobility | Go       | [a186198](https://github.com/nycu-ucr/amf/tree/a18619862a3b97170e02563f53374407481dcded) |
| `ausf`      | Authentication Server Function — performs UE authentication procedures     | Go       | [0cb2ece](https://github.com/nycu-ucr/ausf/tree/0cb2ece6cfca7e1f0ccbbdafc9dd366d270b6ef9) |
| `chf`       | Charging Function — manages charging-related interfaces (if implemented)   | Go       | [088bd10](https://github.com/nycu-ucr/chf/tree/088bd10a8c26e147d8a8d2985d0a68e12085471d) |
| `nrf`       | Network Repository Function — supports service registration/discovery      | Go       | [e4c12be](https://github.com/nycu-ucr/nrf/tree/e4c12be661f5cc8f42b4870446e52bb8ad76de9b) |
| `nssf`      | Network Slice Selection Function — selects network slice per UE session    | Go       | [a6b6472](https://github.com/nycu-ucr/nssf/tree/a6b6472d5e1e86e6ea6ddb778daa278e5c60a472) |
| `onvm-upf`  | User Plane Function — data plane packet handling implemented via ONVM      | C        | [f4423e8](https://github.com/nycu-ucr/onvm-upf/tree/f4423e85a24ea65f2d8445499a06c054ea835a57) |
| `pcf`       | Policy Control Function — enforces policy rules for QoS, access, charging  | Go       | [1de2b6c](https://github.com/nycu-ucr/pcf/tree/1de2b6c8e83fe7cbc46a66ea18df799d7078661f) |
| `smf`       | Session Management Function — handles PDU sessions and tunnel setup        | Go       | [fbb1e3e](https://github.com/nycu-ucr/smf/tree/fbb1e3ea058c0f8c5649e0560f54c765ab057da5) |
| `udm`       | Unified Data Management — manages user identity and subscription access    | Go       | [147cabe](https://github.com/nycu-ucr/udm/tree/147cabe7f06dec8245242f72c0c220bf381bae78) |
| `udr`       | Unified Data Repository — stores structured user data                      | Go       | [fce77b3](https://github.com/nycu-ucr/udr/tree/fce77b3b89099cdc09aef227fc509829bbb575d3) |
| `xio`       | Unified I/O interface between Golang NFs and ONVM stack                    | Go/C     | [464d9d5](https://github.com/nycu-ucr/onvmpoller/tree/464d9d55591fc0a820afde70c70bc0bb1f621c75) |


---

## New feature 
- QoS implementation is achieved using token bucket and trTCM to support GBR and MBR.
- You can view the content and QoS settings through the following link: 
    1. [QoS Configuration in Webconsole](./docs/webconsole/README.md).
    2. [QoS Design Document](./docs/qos/README.md)


---

## Contact

For questions, feedback, or collaboration inquiries:

Email: [l25gc@googlegroups.com](mailto:l25gc@googlegroups.com)\
Join our [Google Group](https://groups.google.com/g/l25gc/)

---

## License
L25GC+ is released under the [Apache 2.0 License](LICENSE).
