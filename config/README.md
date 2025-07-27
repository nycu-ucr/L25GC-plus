# Configuration Directory

This directory contains YAML configuration files for the NFs used in the L25GC+. Each YAML file defines runtime settings for a specific NF (at Golang layer), including service exposure, SBI interface binding, security credentials, logging, and inter-NF connectivity.

---

## Structure

- `multiAMF/`, `multiUPF/`  
  Subdirectories containing variant configurations to run multiple instances of AMF or UPF (e.g., for slicing or scaling experiments).

---

## Configuration Files

Each file corresponds to a specific NF or subsystem:

| File | Description |
|------|-------------|
| `amfcfg.yaml` | Configuration for the Access and Mobility Management Function (AMF) |
| `ausfcfg.yaml` | Configuration for the Authentication Server Function (AUSF) |
| `chfcfg.yaml` | Configuration for the Charging Function (CHF), if implemented |
| `n3iwfcfg.yaml` | Configuration for the N3IWF (Non-3GPP Interworking Function) |
| `n3iwfcfg.test.yaml` | Test version of the N3IWF config |
| `nefcfg.yaml` | Configuration for the Network Exposure Function (NEF) |
| `nrfcfg.yaml` | Configuration for the Network Repository Function (NRF) |
| `nssfcfg.yaml` | Configuration for the Network Slice Selection Function (NSSF) |
| `pcfcfg.yaml` | Configuration for the Policy Control Function (PCF) |
| `smfcfg.yaml` | Configuration for the Session Management Function (SMF) |
| `tngfcfg.yaml` | Configuration for the TNGF (Trusted Non-3GPP Gateway Function), if used |
| `tngfcfg.test.yaml` | Test configuration for TNGF |
| `udcfg.yaml` | Configuration for the Unified Data Repository (UDR) |
| `udmcfg.yaml` | Configuration for the Unified Data Management (UDM) |
| `uerouting.yaml` | Routing rules between UEs and UPFs, possibly used by SMF or UPF |
| `upfcfg.yaml` | Configuration for the free5GC's User Plane Function (UPF) |
| `upfcfg.test.yaml` | Test variant of free5GC's UPF configuration |
| `upfcfg.testulcl.yaml` | Test free5GC's UPF configuration for Uplink Classifier (ULCL) scenarios |
| `webuicfg.yaml` | Configuration for the WebUI or frontend service |

---

## Testing Configs

Files with `.test.yaml` or `.testulcl.yaml` suffixes are intended for testing purposes and may include:
- Mock data
- Reduced service sets
- Alternate SBI bindings or loopback interfaces

---

## Usage

Each 5GC NF loads its configuration via a command-line argument or environment variable. For example:

```bash
./udm --config ./config/udmcfg.yaml
