"""megamind-wormhole gateway client — the on-prem BODY of the (cloud) mind.

Dials OUT to the relay (no inbound ports), authenticates with an enrollment token, and
executes what the mind asks via a small set of GENERIC primitives:
  - exec      : run a shell command -> {stdout, stderr, exit_code}.  (the generic body)
  - put_file  : write base64 bytes to a path on the box.
  - get_file  : read a path -> base64.
  - print / print_file : convenience wrappers (print = exec 'lp -o raw').
Commands run as THIS (non-root) user. Every command is appended to ~/wormhole/audit.log.
Config via env (never the repo). Creds for LAN/resources live on the box, not the cloud.
"""
import os
import json
import asyncio
import subprocess
import tempfile
import logging
import base64
import datetime

import websockets

RELAY = os.environ["RELAY_WS_URL"]
TOKEN = os.environ["RELAY_ENROLL_TOKEN"]
GWID = os.environ.get("GATEWAY_ID", "gw-office-001")
PRINTER = os.environ.get("PRINTER", "Brother")
AUDIT = os.path.expanduser("~/wormhole/audit.log")
MAX_OUT = 1024 * 1024            # 1 MB cap on returned stdout/stderr
MAX_GET = 9 * 1024 * 1024        # 9 MB cap on get_file

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("gw")


def _now():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(msg):
    try:
        with open(AUDIT, "a") as f:
            f.write(f"{_now()} {msg}\n")
    except Exception:
        pass


# ---- generic primitives ----
def do_exec(command, timeout):
    audit(f"EXEC cmd={command!r}")
    try:
        p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        audit(f"EXEC TIMEOUT after {timeout}s cmd={command!r}")
        return "error", f"timed out after {timeout}s", None
    audit(f"EXEC exit={p.returncode} out={len(p.stdout)}b err={len(p.stderr)}b")
    data = {"exit_code": p.returncode, "stdout": p.stdout[:MAX_OUT], "stderr": p.stderr[:MAX_OUT],
            "truncated": len(p.stdout) > MAX_OUT or len(p.stderr) > MAX_OUT}
    return "ok", f"exit={p.returncode}, {len(p.stdout)}b stdout / {len(p.stderr)}b stderr", data


def do_put_file(path, content_b64):
    raw = base64.b64decode(content_b64, validate=True)
    path = os.path.expanduser(path)
    parent = os.path.dirname(path)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "wb") as f:
        f.write(raw)
    audit(f"PUT {path} {len(raw)}b")
    return "ok", f"wrote {len(raw)}b to {path}", {"path": path, "bytes": len(raw)}


def do_get_file(path):
    path = os.path.expanduser(path)
    size = os.path.getsize(path)
    if size > MAX_GET:
        raise RuntimeError(f"file too large ({size}b > {MAX_GET}b cap)")
    with open(path, "rb") as f:
        raw = f.read()
    audit(f"GET {path} {len(raw)}b")
    return "ok", f"read {len(raw)}b from {path}", {"path": path, "bytes": len(raw),
                                                   "content_b64": base64.b64encode(raw).decode()}


# ---- print convenience ----
def ps_escape(s):
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def render_and_print(title, body):
    lines = body.split("\n")
    ps = ["%!PS-Adobe-3.0", "/Helvetica-Bold findfont 16 scalefont setfont",
          f"72 750 moveto ({ps_escape(title)}) show", "/Courier findfont 11 scalefont setfont"]
    y = 722
    for ln in lines:
        ps.append(f"72 {y} moveto ({ps_escape(ln)}) show")
        y -= 15
        if y < 54:
            break
    ps.append("showpage")
    with tempfile.TemporaryDirectory() as d:
        psf, pdf = os.path.join(d, "j.ps"), os.path.join(d, "j.pdf")
        with open(psf, "w") as f:
            f.write("\n".join(ps))
        subprocess.run(["gs", "-q", "-dNOPAUSE", "-dBATCH", "-sDEVICE=pdfwrite", f"-sOutputFile={pdf}", psf], check=True)
        if os.path.getsize(pdf) < 200:
            raise RuntimeError("rendered PDF too small")
        subprocess.run(["lp", "-d", PRINTER, "-o", "raw", pdf], check=True)
        return f"printed {os.path.getsize(pdf)}b PDF to {PRINTER}"


def print_pdf_bytes(data):
    if len(data) < 5 or data[:4] != b"%PDF":
        raise RuntimeError("not a PDF")
    with tempfile.TemporaryDirectory() as d:
        pdf = os.path.join(d, "j.pdf")
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
        data = None
        try:
            if t == "exec":
                status, detail, data = do_exec(msg.get("command", ""), int(msg.get("timeout", 120)))
            elif t == "put_file":
                status, detail, data = do_put_file(msg["path"], msg["content_b64"])
            elif t == "get_file":
                status, detail, data = do_get_file(msg["path"])
            elif t == "print":
                status, detail = "ok", render_and_print(msg.get("title", "megamind"), msg.get("body", ""))
            elif t == "print_file":
                status, detail = "ok", handle_print_file(msg.get("filename", "document"),
                                                          msg.get("kind", ""), msg.get("content_b64", ""))
            else:
                continue
        except Exception as e:
            status, detail = "error", f"{type(e).__name__}: {e}"
        frame = {"type": "result", "id": cid, "status": status, "detail": detail}
        if data is not None:
            frame["data"] = data
        await ws.send(json.dumps(frame))
        log.info(f"{t} {cid}: {status} — {detail}")


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
