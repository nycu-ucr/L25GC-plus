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


## Notes

- **Important**: Both `handover_test.go` and `registration_test.go` must be included together when running tests:
  - `handover_test.go` declares shared logger variables (`_log`, `RegLogger`, `HandoverLogger`, `PagingLogger`)
  - `registration_test.go` provides shared functions (`EstablishPduSession`, `MobileIdentityGroup`, etc.)
- Tests use MongoDB for subscription data management
- All tests clean up MongoDB data after execution

