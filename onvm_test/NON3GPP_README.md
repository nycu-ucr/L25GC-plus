# Non-3GPP Access Testing (N3IWF)

Tests UE connection via untrusted Wi-Fi networks through N3IWF.

## Quick Start

```bash
# Start N3IWF
sudo ./start_n3iwf.sh

# Run test
sudo ./RUN_NON3GPP_TEST.sh

# Stop N3IWF
sudo ./stop_n3iwf.sh
```

## Test Flow

1. **IKE_SA_INIT** - Establish security association
2. **IKE_AUTH** - Certificate + EAP-5G authentication
3. **NAS Registration** - Over TCP with 2-byte length envelope
4. **PDU Session** - Establish data bearer
5. **Control Plane Validation** - All procedures complete

## Expected Result

```
✅ IKE signaling working
✅ EAP-5G authentication successful
✅ Registration complete
✅ PDU Session established
✅ PASSED
```

## Key Files

- `non3gpp_test.go` - Test implementation
- `start_n3iwf.sh` - Start N3IWF service
- `RUN_NON3GPP_TEST.sh` - Run test
- `config/n3iwfcfg_test.yaml` - N3IWF configuration

## Architecture

```
UE (Test) ←→ N3IWF ←→ AMF ←→ SMF ←→ UPF
   │           │
   └─ IKE ─────┘
   └─ IPsec ───┘
   └─ NAS/TCP ─┘
```

## Technical Details

### NAS Message Format
Messages use 3GPP TS 24.502 envelope:
- 2-byte length (big-endian)
- NAS message payload

### Authentication
- EAP-5G over IKE
- Certificate-based N3IWF authentication
- 5G-AKA for UE authentication

### Troubleshooting

**N3IWF not responding:**
```bash
ps aux | grep n3iwf
sudo ./start_n3iwf.sh
```

**Port conflicts:**
```bash
sudo netstat -tulpn | grep 500
# Kill conflicting process if needed
```

**Test timeout:**
- Check N3IWF logs: `journalctl -u n3iwf -f`
- Verify all NFs running (AMF, SMF, UPF, etc.)

## Duration
~21-25 seconds
