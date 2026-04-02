## System Architecture ##

![Architecture.png](ref_architecture.png)


### Setting L25GC-plus Parameters (CN node)
On CN node, we need to edit three files:

- `~/L25GC-plus/config/amfcfg.yaml`
- `~/L25GC-plus/config/smfcfg.yaml`
- `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/upf_u.yaml`

First SSH into the CN node, and change `~/L25GC-plus/config/amfcfg.yaml`:
```
cd ~/L25GC-plus
nano config/amfcfg.yaml
```

Replace ngapIpList IP from `127.0.0.1` to `128.105.144.114`, namely from:
```
...
  ngapIpList:  # the IP list of N2 interfaces on this AMF
  - 127.0.0.1
```
into:
```
...
  ngapIpList:  # the IP list of N2 interfaces on this AMF
  - 128.105.144.114
```

Next edit `~/L25GC-plus/config/smfcfg.yaml`:
```
nano config/smfcfg.yaml
```
and in the entry inside `userplaneInformation / upNodes / UPF / interfaces / endpoints`, change the IP from `127.0.0.8` to `192.168.1.2`, namely from:
```yaml
...
  interfaces: # Interface list for this UPF
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3/N9 interface on this UPF
       - 127.0.0.8
```
into:
```yaml
...
  interfaces: # Interface list for this UPF
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3/N9 interface on this UPF
       - 192.168.1.2
```

Next edit `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`:

```yaml
info:
  version: 1.0.0
  description: L25GC+ UPF-U Configuration

configuration:
  log_level: "warning" # trace, debug, info, warning, error, fatal, panic
  dataplane:
    upf_access_ip: "192.168.1.2"    # UPF local IP on the access-facing port
    upf_core_ip: "10.10.1.1"        # UPF local IP on the core/SGi-facing port
    an_peer_ip: "192.168.1.1"       # Next-hop IP of the AN/gNB peer
    dn_peer_ip: "10.10.1.2"         # Next-hop IP of the DN/upstream router peer

    ports:
      access: 0                     # ACCESS-facing DPDK port
      core: 1                       # CORE-facing DPDK port
```

Set the fields as follows:

* `upf_access_ip`: the UPF local IP on the access-side interface
* `upf_core_ip`: the UPF local IP on the core-side interface
* `an_peer_ip`: the IP of the AN/gNB peer connected to the UPF access side
* `dn_peer_ip`: the IP of the DN/upstream peer connected to the UPF core side
* `ports.access`: the DPDK port connected to the access side
* `ports.core`: the DPDK port connected to the core side

For the example above:

* `an_peer_ip: 192.168.1.1` corresponds to **UE/AN `ens1f0` IP**
* `upf_access_ip: 192.168.1.2` corresponds to the **UPF-U access-side local IP on CN**
* `upf_core_ip: 10.10.1.1` corresponds to the **UPF-U core-side local IP on CN**
* `dn_peer_ip: 10.10.1.2` corresponds to **DN `ens1f1` IP**

### Setting UERANSIM Parameters
In the UERAN node, there are two files related to L25GC-plus：

- `~/L25GC-plus/UERANSIM/config/free5gc-gnb.yaml`
- `~/L25GC-plus/UERANSIM/config/free5gc-ue.yaml`

The second file is for UE, which we don’t have to change if the data inside is consistent with the (default) registration data we set using WebConsole previously.

First SSH into ueransim, and edit the file `~/UERANSIM/config/free5gc-gnb.yaml`, and change the ngapIp IP from `127.0.0.1` to `128.105.144.107`, gtpIp IP from `127.0.0.1` to `192.168.56.102`，and also change the IP in amfConfigs into `128.105.144.114`, that is, from:
```yaml
...
  ngapIp: 127.0.0.1   # gNB's local IP address for N2 Interface (Usually same with local IP)
  gtpIp: 127.0.0.1    # gNB's local IP address for N3 Interface (Usually same with local IP)

  # List of AMF address information
  amfConfigs:
    - address: 127.0.0.1
```
into:
```yaml
...
  ngapIp: 128.105.144.107 # gNB's local IP address for N2 Interface (Usually same with local IP)
  gtpIp: 192.168.1.1      # gNB's local IP address for N3 Interface (Usually same with local IP)

  # List of AMF address information
  amfConfigs:
    - address: 128.105.144.114
```

---

### Add L3 Routes on the UERAN Node and DN Node

On the DN node, add a route so that reply traffic to the UE subnet (or a specific UE IP such as `10.60.0.1`) is sent through the UPF-U core-side interface:

```bash
# On the DN node:
sudo ip route add <ue_ip_or_subnet> via <upf_core_ip> dev <interface>

# Example:
sudo ip route add 10.60.0.1 via 10.10.1.1 dev ens1f1
```

- Here, `10.10.1.1` is the **UPF local IP on the core-side interface**. It should match the `upf_core_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```

- `interface` is the local network interface on the DN node that is connected to the same subnet as the UPF-U core-side interface. In the example above, this interface is `ens1f1`.

Similarly, on the UERAN node, add a route so that traffic destined for the DN server is sent through the UPF-U access-side interface:

```bash
# On the UERAN node:
sudo ip route add <dn_server_ip> via <upf_access_ip> dev <interface>

# Example:
sudo ip route add 10.10.1.2 via 192.168.1.2 dev ens1f0
```

- Here, `192.168.1.2` is the **UPF local IP on the access-side interface**. It should match the `upf_access_ip` configured in:

  ```bash
  ~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml
  ```
- `interface` is the local network interface on the UERAN node that is connected to the same subnet as the UPF-U access-side interface. In the example above, this interface is `ens1f0`.
