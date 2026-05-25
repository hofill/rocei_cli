# rocei

Sign PDFs and files with the Romanian eID card on macOS/Linux. **No IDPlugManager needed.**

Talks directly to the card over PC/SC. The private key never leaves the chip.

> **Note:** Only tested on macOS. Linux and Windows builds are provided but have not been verified against real hardware.

---

## What's in here

```
rocei_pkcs11/   PKCS#11 module — drop-in for any PKCS#11-aware app
rocei_cli/      CLI tool — sign files, read identity data
rocei_sign.py   PDF signer (pyHanko)
```

---

## Build

### macOS / Linux

```bash
# PKCS#11 module
cd rocei_pkcs11 && make

# CLI
cd rocei_cli && make
```

**macOS** needs Xcode command-line tools (ships with clang + PC/SC).  
**Linux** needs `libpcsclite-dev`, `libssl-dev`, and `pkg-config`.

### Python PDF signer

```bash
pip install -r requirements.txt
```

---

## Usage

### CLI

```bash
./rocei list                    # list card objects
./rocei read-cert               # dump signing cert (DER) to stdout
./rocei read-id                 # read identity data (prompts for 4-digit PIN)
./rocei sign contract.txt       # → contract.txt.token
./rocei sign document.pdf       # → signed_document.pdf
./rocei sign --no-x5c file.txt  # omit cert from token
./rocei sign --embed file.txt   # embed file contents in token payload
./rocei sign-hash <hex>         # sign a raw hash, print base64url signature
```

Non-PDF files get a `.token` — a compact JWT-like structure:

```
<base64url(header)>.<base64url(payload)>.<base64url(signature)>
```

Header includes `alg: ES384` and the signing cert (`x5c`).  
Payload includes the filename, SHA-256 hash, and timestamp.  
Signature is 96-byte raw ECDSA P-384 r‖s.

### Python PDF signer

```bash
python3 rocei_sign.py input.pdf
python3 rocei_sign.py input.pdf -o output.pdf
python3 rocei_sign.py input.pdf --reason "Aprobare" --location "București"
python3 rocei_sign.py input.pdf --no-visible
python3 rocei_sign.py input.pdf --pin 123456 # not recommended
```

### Use as a PKCS#11 library

```python
import pkcs11
from pyhanko.sign.pkcs11 import PKCS11Signer

lib = pkcs11.lib("rocei_pkcs11/rocei_pkcs11.dylib")
session = lib.get_slots(token_present=True)[0].get_token().open(user_pin="YOUR_PIN")

signer = PKCS11Signer(
    pkcs11_session=session,
    cert_label="Certificate ECC Advanced Signature",
    key_label="Private Key ECC Advanced Signature",
)
```

---

## Environment variables

### rocei_pkcs11

| Variable | Default | Description |
|----------|---------|-------------|
| `ROCEI_DEBUG` | unset | Print every APDU |
| `ROCEI_KEY_REF` | `0x8E` | Signing key reference |
| `ROCEI_PIN_REF` | `0x05` | PIN reference |
| `ROCEI_CERT_FID` | `0xCE8E` | Certificate EF file ID |
| `ROCEI_SIGN_APP` | `pki` | Set to `qscd` to use the ESIGN applet |

### rocei_cli

| Variable | Description |
|----------|-------------|
| `ROCEI_PIN` | Signing PIN (skips prompt) |
| `ROCEI_DATA_PIN` | Data PIN for `read-id` |
| `ROCEI_SIGN_PY` | Path to `rocei_sign.py` |

---

## macOS: smart card conflict

macOS grabs exclusive PC/SC access when a card is inserted. Both tools handle this automatically. If you still see `SCARD_E_SHARING_VIOLATION`:

```bash
sudo pkill -x ctkd ctkahp
```

---

## Legal

Clean-room implementation — no IDEMIA source code used. Protocol derived by reverse-engineering `libidplug-pkcs11.dylib` (permitted for interoperability under EU Directive 2009/24/EC Art. 6).

PKCS#11 headers are from the OASIS standard — see `include/` for their license.

Reverse engineering and implementation were performed by the author with AI-assisted tooling.
