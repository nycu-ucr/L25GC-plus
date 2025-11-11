# SUCI Encoding Format

## SUCI Length Calculation

The SUCI (Subscription Concealed Identifier) length in NAS MobileIdentity5GS is calculated as:

```
Total Length = 1 + 3 + 2 + 1 + 1 + MSIN_bytes
              │   │   │   │   │   └─ MSIN in BCD (variable)
              │   │   │   │   └─ Public Key ID (1 byte)
              │   │   │   └─ Protection Scheme ID (1 byte)
              │   │   └─ Routing Indicator (2 bytes, BCD)
              │   └─ MCC + MNC (3 bytes, BCD)
              └─ Type (1 byte: 0x01 = SUCI)
```

## Buffer Format

### Byte 0: Type
- `0x01` = SUCI type

### Bytes 1-3: MCC + MNC (BCD encoding)
- **Byte 1**: MCC digits 2,1 (reversed BCD)
- **Byte 2**: 
  - High nibble: MCC digit 3
  - Low nibble: MNC digit 3 (if 3-digit MNC) or `0xf` (if 2-digit MNC)
- **Byte 3**: MNC digits 2,1 (reversed BCD)

**Example for MCC=208, MNC=93 (2-digit)**:
- Byte 1: `0x02` (MCC digits 2,0 → reversed: 0,2)
- Byte 2: `0xf8` (MCC digit 3=8 in high nibble, MNC filler=0xf in low nibble)
- Byte 3: `0x39` (MNC digits 9,3 → reversed: 3,9)

### Bytes 4-5: Routing Indicator (BCD encoding)
- **Byte 4**: Routing Indicator digits 2,1 (reversed BCD)
- **Byte 5**: Routing Indicator digits 4,3 (reversed BCD) or filler

**Example for Routing Indicator = "0"**:
- Bytes 4-5: `0xf0, 0xff` 
  - This encodes "0" and when decoded by GetSUCI(), it becomes "0" (not "0000")
- **Example for Routing Indicator = "0000"**:
- Bytes 4-5: `0x00, 0x00`
  - This encodes "0000" when decoded

### Byte 6: Protection Scheme ID
- `0x00` = NULL scheme (unencrypted)

### Byte 7: Home Network Public Key Identifier
- `0x00` = No public key (when using NULL scheme)

### Bytes 8+: Scheme Output (MSIN in BCD)
- For NULL scheme (Protection Scheme = 0): MSIN is encoded in BCD format
- Each byte encodes 2 digits (reversed within the byte)
- Leading zeros are preserved

**Example for MSIN = "00007488"** (8 digits):
- Bytes 8-11: `0x00, 0x00, 0x47, 0x88`
  - `0x00` = "00"
  - `0x00` = "00"
  - `0x47` = "74" (reversed: 7,4)
  - `0x88` = "88" (reversed: 8,8)

**Example for MSIN = "7488"** (4 digits):
- Bytes 8-9: `0x47, 0x88`
  - `0x47` = "74" (reversed: 7,4)
  - `0x88` = "88" (reversed: 8,8)

## Complete Example

For IMSI: `imsi-2089300007488`
- MCC = 208, MNC = 93 (2-digit), MSIN = 00007488

```
Buffer: [0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00, 0x00, 0x47, 0x88]
Length: 12 bytes
```

This produces SUCI string: `suci-0-208-93-0-0-0-00007488`

## Location in UDM

The UDM parses SUCI in:
- **File**: `NFs/udm/pkg/suci/suci.go`
- **Function**: `ToSupi()` - Converts SUCI string to SUPI (IMSI)
- **Function**: `parseSuci()` - Parses SUCI string format: `suci-0-MCC-MNC-RoutingInd-ProtectionScheme-PublicKeyID-SchemeOutput`

The UDM expects the SUCI in string format (e.g., `suci-0-208-93-0-0-0-7487`), not the raw bytes. The AMF converts the NAS MobileIdentity5GS bytes to a SUCI string before sending to UDM.

## Testing SUCI Encoding

You can test SUCI encoding using:

```go
mobileIdentity5GS := nasType.MobileIdentity5GS{
    Len:    uint16(len(buffer)),
    Buffer: buffer,
}
suci := mobileIdentity5GS.GetSUCI()
fmt.Printf("SUCI: %s\n", suci)
```

This will show you the SUCI string that the UDM will receive.


