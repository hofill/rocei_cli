#!/usr/bin/env python3
"""
rocei_sign — sign a PDF with the Romanian eID card via rocei_pkcs11.dylib

Usage:
    rocei_sign.py INPUT.pdf [-o OUTPUT.pdf] [--reason TEXT] [--location TEXT]
                            [--contact TEXT] [--no-visible] [--place]
                            [--lib PATH] [--slot N] [--pin PIN]
"""

import argparse
import getpass
import json as _json
import os
import socket
import subprocess
import sys
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from pathlib import Path

_here = os.path.dirname(os.path.abspath(__file__))
DEFAULT_LIB = os.path.join(_here, "rocei_pkcs11", "rocei_pkcs11.dylib")
CERT_LABEL = "Certificate ECC Advanced Signature"
KEY_LABEL  = "Private Key ECC Advanced Signature"

# ── placement UI ─────────────────────────────────────────────────────────────

_PLACEMENT_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<title>Place Signature — rocei</title>
<style>
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
  background: #f0f0f0;
  height: 100vh;
  display: flex;
  flex-direction: column;
  overflow: hidden;
}
header {
  background: #1c1c1e;
  color: #fff;
  padding: 10px 18px;
  display: flex;
  align-items: center;
  gap: 14px;
  flex-shrink: 0;
  user-select: none;
}
.title { font-size: 14px; font-weight: 600; letter-spacing: -.2px; }
.hint  { font-size: 12px; color: #999; flex: 1; }
.nav   { display: flex; align-items: center; gap: 8px; }
.nav span { font-size: 12px; color: #aaa; min-width: 80px; text-align: center; }
button {
  padding: 5px 13px;
  border: none;
  border-radius: 6px;
  font-size: 12px;
  font-weight: 500;
  cursor: pointer;
}
.btn-nav  { background: #3a3a3c; color: #fff; }
.btn-nav:hover  { background: #48484a; }
.btn-nav:disabled { opacity: .35; cursor: default; }
.btn-sign { background: #0a84ff; color: #fff; padding: 5px 18px; }
.btn-sign:hover { background: #0070d8; }
.btn-sign:disabled { background: #3a3a3c; color: #666; cursor: default; }
.scroll {
  flex: 1;
  overflow: auto;
  display: flex;
  justify-content: center;
  align-items: flex-start;
  padding: 24px;
  background: #e8e8e8;
}
.wrap {
  position: relative;
  box-shadow: 0 2px 20px rgba(0,0,0,.2);
  line-height: 0;
}
#pdf-canvas { display: block; background: #fff; }
#hit {
  position: absolute;
  inset: 0;
  cursor: crosshair;
}
#sel {
  position: absolute;
  border: 2px solid #0a84ff;
  background: rgba(10,132,255,.12);
  pointer-events: none;
  display: none;
}
.done-overlay {
  display: none;
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,.55);
  align-items: center;
  justify-content: center;
  z-index: 99;
}
.done-card {
  background: #fff;
  border-radius: 14px;
  padding: 36px 40px;
  text-align: center;
  max-width: 280px;
}
.done-card .icon { font-size: 40px; }
.done-card h3 { margin-top: 14px; font-size: 17px; }
.done-card p  { margin-top: 8px; font-size: 13px; color: #666; }
</style>
</head>
<body>
<header>
  <span class="title">rocei — Place Signature</span>
  <span class="hint" id="hint">Draw a rectangle where you want the signature stamp</span>
  <div class="nav">
    <button class="btn-nav" id="prev" onclick="go(-1)" disabled>‹</button>
    <span id="pinfo">Page 1</span>
    <button class="btn-nav" id="next" onclick="go(1)" disabled>›</button>
  </div>
  <button class="btn-sign" id="signBtn" disabled onclick="submit()">Place &amp; Sign</button>
</header>
<div class="scroll">
  <div class="wrap" id="wrap">
    <canvas id="pdf-canvas"></canvas>
    <div id="hit"
      onmousedown="md(event)"
      onmousemove="mm(event)"
      onmouseup="mu(event)"></div>
    <div id="sel"></div>
  </div>
</div>
<div class="done-overlay" id="doneOverlay">
  <div class="done-card">
    <div class="icon">✓</div>
    <h3>Signing&hellip;</h3>
    <p>You can close this tab.</p>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.min.js"></script>
<script>
pdfjsLib.GlobalWorkerOptions.workerSrc =
  'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';

const SCALE = 1.6;
let pdf, page = 1, vp, dragging = false;
let sx, sy, ex, ey, placed = false;
const canvas  = document.getElementById('pdf-canvas');
const ctx     = canvas.getContext('2d');
const hit     = document.getElementById('hit');
const sel     = document.getElementById('sel');
const signBtn = document.getElementById('signBtn');
const hint    = document.getElementById('hint');
const pinfo   = document.getElementById('pinfo');
const prevBtn = document.getElementById('prev');
const nextBtn = document.getElementById('next');

pdfjsLib.getDocument('/pdf').promise.then(d => {
  pdf = d;
  prevBtn.disabled = true;
  nextBtn.disabled = pdf.numPages === 1;
  render(1);
});

async function render(n) {
  page = n;
  pinfo.textContent = `Page ${n} of ${pdf.numPages}`;
  prevBtn.disabled = n === 1;
  nextBtn.disabled = n === pdf.numPages;
  const pg = await pdf.getPage(n);
  vp = pg.getViewport({ scale: SCALE });
  canvas.width = vp.width; canvas.height = vp.height;
  await pg.render({ canvasContext: ctx, viewport: vp }).promise;
  clearSel();
}

function go(d) { render(page + d); }

function clearSel() {
  placed = false;
  sel.style.display = 'none';
  signBtn.disabled = true;
  hint.textContent = 'Draw a rectangle where you want the signature stamp';
}

function md(e) {
  const r = hit.getBoundingClientRect();
  sx = e.clientX - r.left; sy = e.clientY - r.top;
  dragging = true; clearSel();
  sel.style.display = 'block';
  sel.style.left = sx + 'px'; sel.style.top = sy + 'px';
  sel.style.width = sel.style.height = '0';
}

function mm(e) {
  if (!dragging) return;
  const r = hit.getBoundingClientRect();
  ex = Math.max(0, Math.min(e.clientX - r.left, vp.width));
  ey = Math.max(0, Math.min(e.clientY - r.top,  vp.height));
  const x = Math.min(sx,ex), y = Math.min(sy,ey);
  sel.style.left = x+'px'; sel.style.top = y+'px';
  sel.style.width  = Math.abs(ex-sx)+'px';
  sel.style.height = Math.abs(ey-sy)+'px';
}

function mu() {
  if (!dragging) return;
  dragging = false;
  if (Math.abs(ex-sx) > 20 && Math.abs(ey-sy) > 10) {
    placed = true;
    signBtn.disabled = false;
    hint.textContent = 'Ready — click “Place & Sign” to continue';
  }
}

async function submit() {
  if (!placed) return;
  signBtn.disabled = true;
  signBtn.textContent = 'Signing…';
  // Convert canvas (top-left origin) → PDF (bottom-left origin)
  const x1c = Math.min(sx,ex), y1c = Math.min(sy,ey);
  const x2c = Math.max(sx,ex), y2c = Math.max(sy,ey);
  const h = vp.height;
  const box = [
    x1c / SCALE,
    (h - y2c) / SCALE,
    x2c / SCALE,
    (h - y1c) / SCALE,
  ];
  await fetch('/place', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ page: page - 1, box }),
  });
  document.getElementById('doneOverlay').style.display = 'flex';
}
</script>
</body>
</html>
"""


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def pick_placement(pdf_path: Path):
    """Open a browser UI; block until the user draws a placement box.
    Returns (page_0idx, (x1, y1, x2, y2)) in PDF coordinates."""
    result: dict = {}
    done = threading.Event()
    port = _free_port()
    pdf_bytes = pdf_path.read_bytes()

    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass

        def do_GET(self):
            if self.path == "/":
                self._send(200, "text/html; charset=utf-8", _PLACEMENT_HTML.encode())
            elif self.path == "/pdf":
                self._send(200, "application/pdf", pdf_bytes)
            else:
                self.send_response(404); self.end_headers()

        def do_POST(self):
            if self.path == "/place":
                n = int(self.headers.get("Content-Length", 0))
                data = _json.loads(self.rfile.read(n))
                result["page"] = data["page"]
                result["box"]  = tuple(data["box"])
                self._send(200, "application/json", b'{"ok":true}')
                done.set()

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", len(body))
            self.end_headers()
            self.wfile.write(body)

    srv = HTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"Opening placement UI at http://127.0.0.1:{port} …", file=sys.stderr)
    webbrowser.open(f"http://127.0.0.1:{port}")
    done.wait()
    srv.shutdown()
    return result["page"], result["box"]


# ── signing ──────────────────────────────────────────────────────────────────

def kill_ctkd():
    for proc in ("ctkd", "ctkahp"):
        try:
            subprocess.run(["pkill", "-x", proc], capture_output=True)
        except Exception:
            pass


def sign(input_path: Path, output_path: Path, pin: str, *,
         lib_path: str, slot_index: int,
         reason: str, location: str, contact: str,
         visible: bool, place: bool) -> None:

    import pkcs11
    from pyhanko.sign.pkcs11 import PKCS11Signer
    from pyhanko.sign.fields import SigFieldSpec, append_signature_field
    from pyhanko.sign import PdfSignatureMetadata
    from pyhanko.sign.signers.pdf_signer import PdfSigner
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.reader import PdfFileReader
    from pyhanko.stamp import TextStampStyle
    from pyhanko.pdf_utils.text import TextBoxStyle

    # Resolve placement before touching the card
    sig_page = 0
    sig_box  = None
    if place:
        sig_page, sig_box = pick_placement(input_path)
        visible = True

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
            if sig_box:
                box = sig_box
            else:
                # Default: bottom-right corner of first page
                page_obj = reader.root["/Pages"]["/Kids"][0]
                media_box = page_obj.get("/MediaBox", [0, 0, 612, 792])
                pw = float(media_box[2]) - float(media_box[0])
                bw, bh = 200.0, 55.0
                box = (pw - bw - 20, 20.0, pw - 20, 20.0 + bh)

            append_signature_field(writer, SigFieldSpec(
                sig_field_name="Signature1",
                on_page=sig_page,
                box=box,
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


# ── CLI ───────────────────────────────────────────────────────────────────────

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
    ap.add_argument("--place", action="store_true",
                    help="Open browser to pick signature placement visually")
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
        place=args.place,
    )


if __name__ == "__main__":
    main()
