# ONVM NF Configurations

This directory contains configuration files for NFs that are executed within the **OpenNetVM (ONVM)** runtime. These configs are distinct from the `config/` directory, which contains 5GC service-layer configurations (e.g., SBI, NRF URIs, UE profiles, etc.).

---

## Purpose

Each `.json` file in this directory provides ONVM-specific runtime settings for a corresponding NF. These settings control:

- **DPDK lcore allocation**
- **DPDK memory channels**
- **NIC port bitmask**
- **ONVM service IDs**
- **Logging/output options**

These files are parsed during the NF initialization phase, by ONVM wrappers in X-IO.

---

## Sample: `nrf.json`

```json
{
    "dpdk": {
        "corelist": "5",           // Logical core(s) to use
        "memory_channels": 3,      // Number of DPDK memory channels
        "portmask": 2              // Network interface bitmask
    },
    "onvm": {
        "output": "stdout",        // Output mode: 'stdout', 'file', etc.
        "serviceid": 6,            // ONVM service ID (unique)
        "instanceid": 6            // ONVM instance ID (per service type)
    }
}
```

---

## IPID Files

* `ipid.yaml`, `ipid.txt`: Used to **map IP addresses to ONVM service IDs**
* These mappings help NFs route packets to the correct downstream or upstream service via ONVM's service chain

### 🔍 Sample Mapping (`ipid.yaml`)

```yaml
# IP Address: Service ID
IPIDMap:
  127.0.0.1:  11  # AMF, NGAP
  127.0.0.18: 11  # AMF, port 8000
  127.0.0.9:  12  # AUSF, port 8000
  127.0.0.10: 6   # NRF, port 8000
  127.0.0.31: 4   # NSSF
  127.0.0.7:  5   # PCF, port 8000
  127.0.0.2:  3   # SMF
  127.0.0.4:  7   # UDR, port 8000
  127.0.0.3:  8   # UDM, port 8000
  127.0.0.5:  9   # TMP, test script use
  127.0.0.8:  2   # UPF-C, N4 interface
  127.0.0.113: 13 # CHF

```

These mappings are consumed by ONVM NFs (e.g., UPF, SMF, NRF) to **determine how to forward packets or messages across service chains**.

---

## 📄 File Descriptions

| File               | Description                      |
| ------------------ | -------------------------------- |
| `amf.json`         | ONVM config for AMF NF           |
| `ausf.json`        | ONVM config for AUSF NF          |
| `chf.json`         | ONVM config for CHF NF           |
| `client.json`      | Generic ONVM client config       |
| `http_client.json` | HTTP-based ONVM NF (client mode) |
| `http_server.json` | HTTP-based ONVM NF (server mode) |
| `nrf.json`         | ONVM config for NRF NF           |
| `nssf.json`        | ONVM config for NSSF NF          |
| `onvmConfig.json`  | Global or fallback ONVM config   |
| `pcf.json`         | ONVM config for PCF NF           |
| `server.json`      | Generic ONVM server config       |
| `smf.json`         | ONVM config for SMF NF           |
| `tester.json`      | Test NF configuration            |
| `tmp.json`         | Temporary or test configs        |
| `tp_client.json`   | Third-party or test client NF    |
| `tp_server.json`   | Third-party or test server NF    |
| `udm.json`         | ONVM config for UDM NF           |
| `udr.json`         | ONVM config for UDR NF           |
| `upf.json`         | ONVM config for UPF NF           |

---

## Notes

* `serviceid` must be unique across all running ONVM NFs.
* `instanceid` distinguishes between multiple instances of the same service.
* Keep DPDK settings aligned with CPU core and NIC configurations.
* The `portmask` value is a bitmask representing the NICs used (e.g., `2` = port 1 only, `3` = ports 0 and 1).
