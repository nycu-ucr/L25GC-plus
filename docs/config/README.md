## System Architecture ##

![Architecture.png](ref_architecture.png)


### Setting L25GC-plus Parameters
In L25GC-plus VM, we need to edit three files:

- `~/L25GC-plus/config/amfcfg.yaml`
- `~/L25GC-plus/config/smfcfg.yaml`
- `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/upf_u.yaml`

First SSH into L25GC-plus VM, and change `~/L25GC-plus/config/amfcfg.yaml`:
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
  - 128.105.144.114  # 127.0.0.1
```

Next edit `~/L25GC-plus/config/smfcfg.yaml`:
```
nano config/smfcfg.yaml
```
and in the entry inside `userplaneInformation / upNodes / UPF / interfaces / endpoints`, change the IP from `127.0.0.8` to `192.168.1.2`, namely from:
```
...
  interfaces: # Interface list for this UPF
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3/N9 interface on this UPF
       - 127.0.0.8
```
into:
```
...
  interfaces: # Interface list for this UPF
   - interfaceType: N3 # the type of the interface (N3 or N9)
     endpoints: # the IP address of this N3/N9 interface on this UPF
       - 192.168.1.2  # 127.0.0.8
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
    upf_core_ip: "192.168.1.2"      # UPF local IP on the core/SGi-facing port
    an_peer_ip: "192.168.1.1"       # Next-hop IP of the AN/gNB peer
    dn_peer_ip: "192.168.1.4"       # Next-hop IP of the DN/upstream router peer

    ports:
      access: 1                     # ACCESS-facing DPDK port
      core: 0                       # CORE-facing DPDK port
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
* `upf_access_ip: 192.168.1.2` corresponds to the **UPF access-side local IP on Host2**
* `dn_peer_ip: 10.10.1.1` corresponds to **DN `ens1f1` IP**

### Setting UERANSIM Parameters
In the ueransim VM, there are two files related to L25GC-plus：

- `~/UERANSIM/config/free5gc-gnb.yaml`
- `~/UERANSIM/config/free5gc-ue.yaml`

The second file is for UE, which we don’t have to change if the data inside is consistent with the (default) registration data we set using WebConsole previously.

First SSH into ueransim, and edit the file `~/UERANSIM/config/free5gc-gnb.yaml`, and change the ngapIp IP from `127.0.0.1` to `128.105.144.107`, gtpIp IP from `127.0.0.1` to `192.168.56.102`，and also change the IP in amfConfigs into `128.105.144.114`, that is, from:
```
...
  ngapIp: 127.0.0.1   # gNB's local IP address for N2 Interface (Usually same with local IP)
  gtpIp: 127.0.0.1    # gNB's local IP address for N3 Interface (Usually same with local IP)

  # List of AMF address information
  amfConfigs:
    - address: 127.0.0.1
```
into:
```
...
  ngapIp: 128.105.144.107  # 127.0.0.1   # gNB's local IP address for N2 Interface (Usually same with local IP)
  gtpIp: 192.168.1.1  # 127.0.0.1    # gNB's local IP address for N3 Interface (Usually same with local IP)

  # List of AMF address information
  amfConfigs:
    - address: 128.105.144.114  # 127.0.0.1
```
