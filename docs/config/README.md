## System Architecture ##

![Architecture.png](ref_architecture.png)


### 1. Setting L25GC-plus Parameters (CN node): AMF, SMF, UPF-U
On CN node, we need to edit three files:

- `~/L25GC-plus/config/amfcfg.yaml`
- `~/L25GC-plus/config/smfcfg.yaml`
- `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/upf_u.yaml`

#### AMF Configuration:
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

#### SMF Configuration:
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

#### UPF-U Configuration:
Next edit `~/L25GC-plus/NFs/onvm-upf/5gc/upf_u/config/upf_u.yaml`:

```yaml
info:
  version: 1.0.0
  description: L25GC+ UPF-U Configuration

configuration:
  log_level: "warning"  # trace, debug, info, warning, error, fatal, panic
  dataplane:
    upf_n3_ip: "192.168.1.2"        # N3 interface IP address on the Core Network node
    upf_n6_ip: "10.10.1.1"          # N6 interface IP address on the Core Network node
    an_peer_n3_ip: "192.168.1.1"    # N3 interface IP address on the UE/RAN node
    dn_peer_n6_ip: "10.10.1.2"      # N6 interface IP address on the DN node

    ports:
      n3_port: 0                     # NIC port used for N3 interface
      n6_port: 1                     # NIC port used for N6 interface
```

### 2. Setting UERANSIM Parameters
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

### 3. Add L3 Routes on the UERAN Node and DN Node

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
