#!/usr/bin/env python3
"""
rocei_sign — sign a PDF with the Romanian eID card via rocei_pkcs11.dylib

Usage:
    rocei_sign.py INPUT.pdf [-o OUTPUT.pdf] [--reason TEXT] [--location TEXT]
                            [--contact TEXT] [--no-visible] [--lib PATH]
                            [--slot N] [--pin PIN]
"""

import argparse
import getpass
import os
import subprocess
import sys
from io import BytesIO
from pathlib import Path

_here = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIB = os.path.join(_here, "rocei_pkcs11", "rocei_pkcs11.dylib")
CERT_LABEL = "Certificate ECC Advanced Signature"
KEY_LABEL  = "Private Key ECC Advanced Signature"


def kill_ctkd():
    for proc in ("ctkd", "ctkahp"):
        try:
            subprocess.run(["pkill", "-x", proc], capture_output=True)
        except Exception:
            pass


def sign(input_path: Path, output_path: Path, pin: str, *,
         lib_path: str, slot_index: int,
         reason: str, location: str, contact: str,
         visible: bool) -> None:

    import pkcs11
    from pyhanko.sign.pkcs11 import PKCS11Signer
    from pyhanko.sign.fields import SigFieldSpec, append_signature_field
    from pyhanko.sign import PdfSignatureMetadata
    from pyhanko.sign.signers.pdf_signer import PdfSigner
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.text import TextBoxStyle

    kill_ctkd()

    lib = pkcs11.lib(lib_path)
    slots = lib.get_slots(token_present=True)
    if not slots:
        sys.exit("No token slots found — is the card inserted?")
    if slot_index >= len(slots):
        sys.exit(f"Slot {slot_index} not found (only {len(slots)} slot(s) available)")

    token = slots[slot_index].get_token()
    session = token.open(user_pin=pin)

    try:
        signer = PKCS11Signer(
            pkcs11_session=session,
            cert_label=CERT_LABEL,
            key_label=KEY_LABEL,
        )

        sig_meta = PdfSignatureMetadata(
            field_name="Signature1",
            reason=reason or None,
            location=location or None,
            contact_info=contact or None,
        )

        pdf_data = input_path.read_bytes()
        reader = PdfFileReader(BytesIO(pdf_data), strict=False)
        writer = IncrementalPdfFileWriter.from_reader(reader)

        if visible:
            # Place in the bottom-right corner of the first page
            page_obj = reader.root["/Pages"]["/Kids"][0]
            media_box = page_obj.get("/MediaBox", [0, 0, 612, 792])
            pw = float(media_box[2]) - float(media_box[0])
            ph = float(media_box[3]) - float(media_box[1])
            bw, bh = 200.0, 55.0
            bx = pw - bw - 20
            by = 20.0
            append_signature_field(writer, SigFieldSpec(
                sig_field_name="Signature1",
                on_page=0,
                box=(bx, by, bx + bw, by + bh),
            ))

        stamp = TextStampStyle(
            stamp_text="SEMNAT DIGITAL\n%(signer)s\n%(ts)s",
            text_box_style=TextBoxStyle(font_size=9),
            border_width=1,
        )

        pdf_out = BytesIO()
        PdfSigner(sig_meta, signer=signer, stamp_style=stamp).sign_pdf(writer, output=pdf_out)

        output_path.write_bytes(pdf_out.getvalue())
        print(f"Signed PDF written to: {output_path}  ({len(pdf_out.getvalue())} bytes)")
    finally:
        session.close()


def main():
    ap = argparse.ArgumentParser(
        description="Sign a PDF with the Romanian eID card (rocei_pkcs11)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("input", type=Path, help="Input PDF file")
    ap.add_argument("-o", "--output", type=Path, default=None,
                    help="Output PDF (default: signed_<input>)")
    ap.add_argument("--reason",   default="", help="Signature reason")
    ap.add_argument("--location", default="", help="Signature location")
    ap.add_argument("--contact",  default="", help="Signer contact info")
    ap.add_argument("--no-visible", action="store_true",
                    help="Embed signature without a visible stamp")
    ap.add_argument("--lib", default=os.environ.get("PKCS11_LIB", DEFAULT_LIB),
                    help="Path to rocei_pkcs11.dylib")
    ap.add_argument("--slot", type=int, default=0,
                    help="PKCS#11 slot index (default: 0)")
    ap.add_argument("--pin", default=None,
                    help="Signing PIN (omit to be prompted)")

    args = ap.parse_args()

    if not args.input.exists():
        sys.exit(f"Input file not found: {args.input}")

    output = args.output or args.input.parent / f"signed_{args.input.name}"

    if not Path(args.lib).exists():
        sys.exit(f"PKCS#11 library not found: {args.lib}\n"
                 f"Set --lib or export PKCS11_LIB=<path>")

    pin = args.pin or getpass.getpass("Signing PIN: ")
    if not pin:
        sys.exit("PIN is required")

    sign(
        args.input, output, pin,
        lib_path=args.lib,
        slot_index=args.slot,
        reason=args.reason,
        location=args.location,
        contact=args.contact,
        visible=not args.no_visible,
    )


if __name__ == "__main__":
    main()
