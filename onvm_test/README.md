# L25GC+ Test Suite

Test suite for validating L25GC+ 5G Core Network Functions.

## Test Status

| Test File | Status | Description | Notes |
|-----------|--------|-------------|-------|
| `registration_test.go` | ✅ **Working** | UE registration procedure (Initial Registration, Authentication, Security Mode) | Fully functional |
| `handover_test.go` | ✅ **Working** | N2 Handover procedure (Preparation Phase, Execution Phase) | Fully functional |
| `paging_test.go` | ✅ **Working** | Paging procedure for mobile-terminated services | Fully functional |
| `non3gpp_test.go` | 🚧 **WIP** | Non-3GPP access procedures (e.g., WLAN) | WIP |

## Quick Start

### Prerequisites

- MongoDB running and accessible
- L25GC+ NFs (AMF, UDM, AUSF, NRF, SMF, UDR) running
- Go 1.19+ installed

### Running Tests

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
# Set custom IP addresses and TEID (defaults shown)
export RAN_N2_IP="127.0.0.1"      # RAN N2 interface (NGAP)
export AMF_N2_IP="127.0.0.18"     # AMF N2 interface (NGAP) this is in ./will_lin/L25GC-plus/config/amfcfg.yaml
export RAN_N3_IP="10.100.200.1"   # RAN N3 interface (GTP-U)
export RAN_TEID="1"               # RAN Tunnel Endpoint ID (GTP-U)

# Example: Run test with custom IPs and TEID
AMF_N2_IP="192.168.1.100" RAN_N2_IP="192.168.1.50" RAN_TEID="1" \
  go test -v handover_test.go registration_test.go -run TestRegistration
```

### Convenience Script

Use the helper script for easier test execution:

```bash
# Run with defaults
./run_test.sh TestRegistration

# Run with custom IPs and TEID (optional)
./run_test.sh TestRegistration 127.0.0.18 127.0.0.1 10.100.200.1 100

# Run handover test
./run_test.sh TestN2Handover
```


## Notes

- **Important**: Both `handover_test.go` and `registration_test.go` must be included together when running tests:
  - `handover_test.go` declares shared logger variables (`_log`, `RegLogger`, `HandoverLogger`, `PagingLogger`)
  - `registration_test.go` provides shared functions (`EstablishPduSession`, `MobileIdentityGroup`, etc.)
- Tests use MongoDB for subscription data management
- All tests clean up MongoDB data after execution

