# L25GC+ Test Suite

Test suite for validating control plane events in L25GC+.

## Test Status

| Test File | Status | Description | Notes |
|-----------|--------|-------------|-------|
| `registration_test.go` | ✅ **Working** | UE registration procedure (Initial Registration, Authentication, Security Mode) | Fully functional |
| `handover_test.go` | ✅ **Working** | N2 Handover procedure (Preparation Phase, Execution Phase) | Fully functional |
| `paging_test.go` | ✅ **Working** | Paging procedure for mobile-terminated services | Fully functional |
| `non3gpp_test.go` | 🚧 **WIP** | Non-3GPP access procedures (e.g., WLAN) | WIP |

## Quick Start

### Prerequisites

- Please deploy L25GC+ according to the [README](L25GC-plus/README.md).
- MongoDB running and accessible
- L25GC+ NFs (AMF, UDM, AUSF, NRF, SMF, UDR) running
- Go 1.19+ installed

### How to run the tests

```bash
cd onvm_test

# Run registration test (requires handover_test.go for shared logger declarations)
go test -v handover_test.go registration_test.go -run TestRegistration

# Run handover test
go test -v handover_test.go registration_test.go -run TestN2Handover

# Run paging test (requires PAGING_TYPE environment variable and UPF connectivity)
PAGING_TYPE=L25GC go test -v handover_test.go registration_test.go paging_test.go -run TestPaging

# NOTE: Both handover_test.go and registration_test.go must be included together because:
# - handover_test.go declares the shared logger variables that all tests use
# - registration_test.go provides shared functions like EstablishPduSession
```

### Network Configuration

Customize network IP addresses and TEID via environment variables:

```bash
# Set custom IP addresses and TEID (The defaults are shown below)
export RAN_N2_IP="127.0.0.1"      # RAN N2 interface (NGAP)
export AMF_N2_IP="127.0.0.18"     # AMF N2 interface (NGAP) this is in L25GC-plus/config/amfcfg.yaml
export RAN_N3_IP="10.100.200.1"   # RAN N3 interface (GTP-U)
export RAN_TEID="1"               # RAN Tunnel Endpoint ID (GTP-U)

# Example: testing with custom IPs and TEID
AMF_N2_IP="192.168.1.100" RAN_N2_IP="192.168.1.50" RAN_TEID="1" \
  go test -v handover_test.go registration_test.go -run TestRegistration
```

### Helper Script

We provide a helper script `run_test.sh` to abstract away the complexity:

```bash
# Run with defaults
./run_test.sh TestRegistration

# Run with custom IPs and TEID (optional)
./run_test.sh TestRegistration 127.0.0.18 127.0.0.1 10.100.200.1 100

# Run handover test
./run_test.sh TestN2Handover
```


## Notes

- **Important**: Both `handover_test.go` and `registration_test.go` must be included together when running tests
- Tests use MongoDB for subscription data management
- All tests must clean up MongoDB data after execution
- `handover.txt`, `pdu_latency.txt`, and `reg_latency.txt` files are generated for logging purposes

