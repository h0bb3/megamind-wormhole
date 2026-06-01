"""megamind-wormhole gateway client — runs on the on-prem box.

Dials OUT to the relay (no inbound ports), authenticates with an enrollment token, and:
  - 'print'      : render text -> PostScript -> PDF (ghostscript) -> lp -o raw.
  - 'print_file' : decode base64; if PDF -> lp -o raw directly; if text/markdown -> render.
The client-supplied filename is NEVER used as a filesystem path (tempfile only).
Auto-reconnects. Config via env (never the repo).
"""
import os
import json
import asyncio
import subprocess
import tempfile
import logging
import base64

import websockets

RELAY = os.environ["RELAY_WS_URL"]                       # wss://<host>/ws
TOKEN = os.environ["RELAY_ENROLL_TOKEN"]
GWID = os.environ.get("GATEWAY_ID", "gw-office-001")
PRINTER = os.environ.get("PRINTER", "Brother")

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("gw")


def ps_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_and_print(title, body):
    """Text/markdown -> PostScript -> PDF -> lp -o raw (proven recipe). First page only."""
    lines = body.split("\n")
    ps = ["%!PS-Adobe-3.0",
          "/Helvetica-Bold findfont 16 scalefont setfont",
          f"72 750 moveto ({ps_escape(title)}) show",
          "/Courier findfont 11 scalefont setfont"]
    y = 722
    for ln in lines:
        ps.append(f"72 {y} moveto ({ps_escape(ln)}) show")
        y -= 15
        if y < 54:
            break
    ps.append("showpage")
    with tempfile.TemporaryDirectory() as d:
        psf, pdf = os.path.join(d, "job.ps"), os.path.join(d, "job.pdf")
        with open(psf, "w") as f:
            f.write("\n".join(ps))
        subprocess.run(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=pdfwrite",
                        f"-sOutputFile={pdf}", psf], check=True)
        size = os.path.getsize(pdf)
        if size < 200:
            raise RuntimeError(f"rendered PDF too small ({size}b)")
        subprocess.run(["lp", "-d", PRINTER, "-o", "raw", pdf], check=True)
        return f"printed {size}b PDF to {PRINTER}"


def print_pdf_bytes(data):
    """Send a real PDF straight to the printer's RIP (lp -o raw)."""
    if len(data) < 5 or data[:4] != b"%PDF":
        raise RuntimeError("not a PDF (missing %PDF header)")
    with tempfile.TemporaryDirectory() as d:
        pdf = os.path.join(d, "job.pdf")          # our own temp name — never the client's filename
        with open(pdf, "wb") as f:
            f.write(data)
        subprocess.run(["lp", "-d", PRINTER, "-o", "raw", pdf], check=True)
        return f"printed {len(data)}b PDF (raw) to {PRINTER}"


def handle_print_file(filename, kind, content_b64):
    raw = base64.b64decode(content_b64, validate=True)
    fn, kind = filename.lower(), (kind or "").lower()
    if raw[:4] == b"%PDF" or fn.endswith(".pdf") or kind == "pdf":
        return print_pdf_bytes(raw)
    if fn.endswith((".txt", ".md", ".markdown", ".text")) or kind in ("text", "md", "markdown", "txt"):
        return render_and_print(filename, raw.decode("utf-8", "replace"))
    raise RuntimeError(f"unsupported file type for '{filename}'; send a PDF or text/markdown")


async def serve(ws):
    await ws.send(json.dumps({"type": "hello", "token": TOKEN, "gateway_id": GWID}))
    log.info(f"relay said: {json.loads(await ws.recv())}")
    async for raw in ws:
        msg = json.loads(raw)
        t, cid = msg.get("type"), msg.get("id")
        if t not in ("print", "print_file"):
            continue
        try:
            if t == "print":
                detail = render_and_print(msg.get("title", "megamind"), msg.get("body", ""))
            else:
                detail = handle_print_file(msg.get("filename", "document"), msg.get("kind", ""),
                                           msg.get("content_b64", ""))
            await ws.send(json.dumps({"type": "result", "id": cid, "status": "ok", "detail": detail}))
            log.info(f"{t} {cid}: {detail}")
        except Exception as e:
            await ws.send(json.dumps({"type": "result", "id": cid, "status": "error", "detail": str(e)}))
            log.info(f"{t} {cid} FAILED: {e}")


async def main():
    log.info(f"gateway '{GWID}' -> {RELAY}")
    while True:
        try:
            async with websockets.connect(RELAY, ping_interval=20, ping_timeout=25,
                                          open_timeout=20, max_size=16 * 1024 * 1024) as ws:
                log.info("connected")
                await serve(ws)
        except Exception as e:
            log.info(f"disconnected: {type(e).__name__}: {e}; reconnect in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
