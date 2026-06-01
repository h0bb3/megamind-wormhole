"""megamind-wormhole gateway client — runs on the on-prem box.

Dials OUT to the relay (no inbound ports), authenticates with an enrollment token,
and on a 'print' command renders text -> PostScript -> PDF (ghostscript) -> lp -o raw
(the proven 2026-05-29 recipe). Auto-reconnects. Config via env (never the repo).
"""
import os
import json
import asyncio
import subprocess
import tempfile
import logging

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
        if size < 200:                                   # verify artifact before printing
            raise RuntimeError(f"rendered PDF too small ({size}b)")
        subprocess.run(["lp", "-d", PRINTER, "-o", "raw", pdf], check=True)
        return f"printed {size}b PDF to {PRINTER}"


async def serve(ws):
    await ws.send(json.dumps({"type": "hello", "token": TOKEN, "gateway_id": GWID}))
    log.info(f"relay said: {json.loads(await ws.recv())}")
    async for raw in ws:
        msg = json.loads(raw)
        if msg.get("type") == "print":
            cid = msg.get("id")
            try:
                detail = render_and_print(msg.get("title", "megamind"), msg.get("body", ""))
                await ws.send(json.dumps({"type": "result", "id": cid, "status": "ok", "detail": detail}))
                log.info(f"print {cid}: {detail}")
            except Exception as e:
                await ws.send(json.dumps({"type": "result", "id": cid, "status": "error", "detail": str(e)}))
                log.info(f"print {cid} FAILED: {e}")


async def main():
    log.info(f"gateway '{GWID}' -> {RELAY}")
    while True:
        try:
            async with websockets.connect(RELAY, ping_interval=20, ping_timeout=25, open_timeout=20) as ws:
                log.info("connected")
                await serve(ws)
        except Exception as e:
            log.info(f"disconnected: {type(e).__name__}: {e}; reconnect in 5s")
            await asyncio.sleep(5)


if __name__ == "__main__":
    asyncio.run(main())
