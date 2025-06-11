<!--``` diff
- We kindly note that L25GC+ is not yet completely ready because the installation script needs some refinement.
- Please stay tuned for an official release from us.
```  -->

# L25GC+: A Low-latency, 3GPP-compliant 5G Core Network
## About

In this work, we develop L25GC+. L25GC+ is a re-architected 5G Core (5GC) network, aimed at reducing latency and improving user experience. L25GC+ focuses on minimizing the impact of control plane operations on the data plane, while also enhancing data plane processing. It achieves this by exploiting shared memory (based on OpenNetVM), eliminating message serialization and HTTP processing overheads in 3GPP SBI, and using scalable packet classifiers for forwarding-rule lookups. L25GC+ re-designs OpenNetVM's shared-memory-based networking stack to support synchronous I/O between control plane functions, which allows it to distinguish different user sessions and maintains strict 3GPP compliance. L25GC+ also offers seamless integration with existing 5GC microservice implementations through equivalent SBI APIs, reducing code refactoring and porting efforts. Additionally, L25GC+ implements paging and an intelligent handover scheme to reduce delays and data loss. It also offers integrated failure resiliency for faster recovery from failures compared to standard 3GPP procedures.

L25GC+ is built on the open-source kernel-based 5GC implementation called free5GC. By leveraging shared memory I/O, L25GC+ optimizes the 5G control plane, enhancing latency, scalability, and overall user experience. L25GC+ achieves 2X lower data plane latency for paging and handover events compared to free5GC. We demonstrate the improved performance of L25GC+ on a 5G testbed with commercial basestations and UEs. 

<!-- $L^25GC$ is a re-architected 5G Core (5GC) network, aimed at reducing latency and improving user experience. $L^25GC$ focuses on minimizing control plane operations' impact on the data plane and enhancing data plane processing. It achieves this by exploiting shared memory (based on [OpenNetVM](docs/ONVM.md)), eliminating message serialization and HTTP processing overheads in 3GPP SBI, and using scalable packet classifiers for forwarding-rule lookups. Additionally, $L^25GC$ implements paging and an intelligent handover scheme to reduce delays and data loss. It also offers integrated failure resiliency for faster recovery from failures compared to standard 3GPP procedures. $L^25GC$ is built on the open-source kernel-based 5GC implementation called [free5GC](docs/free5GC.md). In tests, $L^25GC$ showed approximately 50% faster event completion time for control plane events and 2X improved data packet latency during paging and handover events compared to free5GC. However, $L^25GC$ has limitations in supporting multiple user sessions and has programming language incompatibilities with 5GC implementations, e.g., free5GC, using modern languages such as GoLang. This unfortunately increases the complexity of code development and the difficulty of code maintenance and updates of $L^25GC$. -->

<!-- To address these challenges, we develop $L^25GC+$, a significant enhancement to $L^25GC$. $L^25GC+$ re-designs the shared-memory-based networking stack to support synchronous I/O between control plane functions. $L^25GC+$ distinguishes different user sessions and maintains strict 3GPP compliance. $L^25GC+$ also offers seamless integration with existing 5GC microservice implementations through equivalent SBI APIs, reducing code refactoring and porting efforts. By leveraging shared memory I/O and overcoming $L^25GC$’s limitations, $L^25GC+$ provides an improved solution to optimize the 5G control plane, enhancing latency, scalability, and overall user experience. We demonstrate the improved performance of $L^25GC+$ on a 5G testbed with commercial basestations and multiple UEs. -->

For more design details, please refer to:
- SIGCOMM 2022: [L25GC: A Low Latency 5G Core Network based on High-Performance NFV Platforms](docs/papers/l25gc.pdf)
- CloudNet 2023: [L25GC+: An Improved, 3GPP-compliant 5G Core for Low-latency Control Plane Operations](docs/papers/l25gc+.pdf)


<!--
## Installation guideline and SIGCOMM artifact evaluation ##
To reproduce the experiment in [our paper](docs/papers/l25gc-sigcomm22.pdf), please refer to [artifact documentation](docs/ARTIFACTS.md).
## Publication ##
~~~
@inproceedings{l25gc-sigcomm22,
author = {Jain, Vivek and Chu, Hao-Tse and Qi, Shixiong and Lee, Chia-An and Chang, Hung-Cheng and Hsieh, Cheng-Ying and Ramakrishnan, K. K. and Chen, Jyh-Cheng},
title = {L25GC: A Low Latency 5G Core Network Based on High-Performance NFV Platforms},
year = {2022},
isbn = {9781450394208},
publisher = {Association for Computing Machinery},
address = {New York, NY, USA},
url = {https://doi.org/10.1145/3544216.3544267},
doi = {10.1145/3544216.3544267},
booktitle = {Proceedings of the ACM SIGCOMM 2022 Conference},
pages = {143–157},
numpages = {15},
keywords = {cellular core, NFV, low latency 5G core, 5G cellular networks},
location = {Amsterdam, Netherlands},
series = {SIGCOMM '22}
}
~~~
-->

## Installation
- **Tested OS**: `Ubuntu 20.04`
- If your environment is Ubuntu 22.04, please refer to [this documentation](./docs/ubuntu-22.04/README.md).
-  **NIC Requirement**; You need at least **two** DPDK-compatible NICs to run L25GC+. These interfaces must be bound to a supported DPDK driver (e.g., `igb_uio`).  
    > *Note:* In some environments, the interface must be brought down before binding.
    ```bash
    sudo ip link set <interface> down
    sudo ~/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py -s
    sudo ~/onvm/onvm-upf/dpdk/usertools/dpdk-devbind.py -b igb_uio <PCI>
    ```

### Environment Setup
- You can setup the experiment environment by running the provided scripts.
    - For details about configuration files, please refer to this [link](./docs/config/README.md).

### Setup Steps
1. Adjust the parameters in `scripts/set_nw_env.sh`
    - Reference architecture:
        ![ref_architecture](./docs/config/ref_architecture.png)
2. Run the setup script on target machine
    ```bash
    cd scripts
    ./setup.sh <ue|cn|dn>
    ```
3. Follow the steps in the [Running L25GC+](#running-l25gc) section below to start L25GC+.


## Running L25GC+
1. **Run ONVM Manager**
    ```bash
    cd ~/onvm
    ./run_manager.sh
    ```
2. **Run UPF-U** (new terminal)
    ```bash
    cd ~/onvm/onvm-upf/5gc/upf_u_complete
    sudo ./go.sh 1
    ```
3. **Run UPF-C** (new terminal)
    ```bash
    cd ~/onvm/onvm-upf/5gc/upf_c_complete
    sudo ./go.sh 2
    ```
4. **Run 5GC Network Functions (NFs)** (new terminal)

    ```bash
    cd ~/L25GC-plus
    ./run.sh
    ```
5. **Stop L25GC+**

    ```bash
    cd ~/onvm
    ./force_kill.sh
    ```

## New feature 
- QoS implementation is achieved using token bucket and trTCM to support GBR and MBR.
- You can view the content and QoS settings through the following link: 
    1. [QoS Configuration in Webconsole](./docs/webconsole/README.md).
    2. [QoS Design Document](./docs/qos/README.md)

## Communication ##
If you have any questions or comments, please feel free to email us (l25gc@googlegroups.com) or join our [Google group](https://groups.google.com/g/l25gc/).

## License
L25GC+ is now under [Apache 2.0](https://github.com/nycu-ucr/L25GC-plus/blob/main/LICENSE) license.
