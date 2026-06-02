"""megamind-wormhole gateway client — the on-prem BODY of the (cloud) mind.

Generic primitives the mind composes (no pre-programmed commands):
  - exec      : run a shell command -> {stdout, stderr, exit_code}.
  - put_file  : write base64 bytes to a path (defaults under ~/wormhole/files).
  - get_file  : read a path -> base64 (defaults under ~/wormhole/files).
  - print / print_file : convenience wrappers.
Hardening (h0bb3's box; light, bypassable-by-design speed-bumps, not a customer fence):
  - runs as the non-root service user; every command appended to ~/wormhole/audit.log
    AND the relay logs each command off-box; audit failure is LOUD (audit_ok in the frame).
  - catastrophic-pattern tripwire (exec) + sensitive-path guard (put_file), fail-closed
    unless the caller sets "confirm": true.
  - put_file/get_file scoped to ~/wormhole/files by default; "allow_outside": true to override.
Config via env (never the repo). LAN/resource creds live on the box, not the cloud.
"""
import os
import re
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
WORKDIR = os.path.realpath(os.path.expanduser("~/wormhole/files"))
MAX_OUT = 1024 * 1024
MAX_GET = 9 * 1024 * 1024

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("gw")

# Catastrophic exec patterns — bypassable speed-bump vs one-shot injection / footguns.
CATASTROPHIC = [
    r"\bsudo\b",                                       # privilege escalation (passwordless sudo on this box -> exec is effectively root)
    r"\|\s*(sudo\s+)?(sh|bash|zsh)\b",                 # curl … | sh  /  base64 -d | bash
    r"(>>?|tee)\s+[^\n|]*(\.bashrc|\.bash_profile|\.profile|\.zshrc)",
    r"(>>?|tee)\s+[^\n|]*\.ssh/",                       # writes into ~/.ssh
    r"authorized_keys",
    r"\.config/systemd",                                # systemd user units
    r"\bcrontab\b",
    r"\bchattr\s+[+-]i",                                # immutability games on the audit log
    r"\bshred\b[^\n]*audit\.log",
    r">\s*[^\n|]*audit\.log",                           # truncate the audit log
]
SENSITIVE_SEGMENTS = ("/.ssh/", "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc",
                      "/.config/systemd/", "/.config/autostart/", "authorized_keys", "/.gnupg/")


def _now():
    return datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit(msg):
    """Append to the on-box log. Returns False on failure and logs LOUDLY (-> journal/gw.log)."""
    try:
        with open(AUDIT, "a") as f:
            f.write(f"{_now()} {msg}\n")
        return True
    except Exception as e:
        log.error(f"AUDIT WRITE FAILED ({e}) for: {msg}")
        return False


def _dangerous_rm(cmd):
    """Recursive rm targeting root/home/broad globs. Catches what a single regex missed (#6):
    separate flags (`-r -f`), combined (`-rf`), `--recursive`, and `/*`/bare-`*` targets — while
    leaving specific paths (`rm -rf /tmp/build`) alone."""
    for seg in re.split(r"[;\n|&]", cmd):
        if not re.search(r"\brm\b", seg):
            continue
        recursive = bool(re.search(r"(?:^|\s)-{1,2}[a-zA-Z]*[rR]", seg)) or "--recursive" in seg
        if not recursive and "--no-preserve-root" not in seg:
            continue
        if re.search(r"(?:^|\s)(/\*?|~|\$HOME|\*)(?:\s|/|$)", seg) or "--no-preserve-root" in seg:
            return True
    return False


def _catastrophic_hits(cmd):
    hits = [p for p in CATASTROPHIC if re.search(p, cmd)]
    if _dangerous_rm(cmd):
        hits.append("recursive rm of root/home/glob")
    return hits


def _resolve(path, allow_outside):
    """Resolve a put/get path; default-scope to WORKDIR unless allow_outside."""
    if os.path.isabs(path) or path.startswith("~"):
        full = os.path.realpath(os.path.expanduser(path))
    else:
        full = os.path.realpath(os.path.join(WORKDIR, path))
    inside = full == WORKDIR or full.startswith(WORKDIR + os.sep)
    if not inside and not allow_outside:
        raise PermissionError(f"path resolves outside {WORKDIR}; set allow_outside=true to override")
    return full


def _is_sensitive(full):
    low = full.lower()
    return any(seg in low for seg in SENSITIVE_SEGMENTS)


# ---- generic primitives ----
def do_exec(command, timeout, confirm):
    hits = _catastrophic_hits(command)
    if hits and not confirm:
        audit(f"EXEC BLOCKED (catastrophic, unconfirmed) hits={hits} cmd={command!r}")
        return "blocked", f"blocked: matches catastrophic pattern(s) {hits}; re-send with \"confirm\":true if truly intended", None
    audit(f"EXEC{' [CONFIRMED]' if confirm else ''} cmd={command!r}")
    try:
        p = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        audit(f"EXEC TIMEOUT {timeout}s cmd={command!r}")
        return "error", f"timed out after {timeout}s", None
    audit(f"EXEC exit={p.returncode} out={len(p.stdout)}b err={len(p.stderr)}b")
    data = {"exit_code": p.returncode, "stdout": p.stdout[:MAX_OUT], "stderr": p.stderr[:MAX_OUT],
            "truncated": len(p.stdout) > MAX_OUT or len(p.stderr) > MAX_OUT}
    return "ok", f"exit={p.returncode}, {len(p.stdout)}b stdout / {len(p.stderr)}b stderr", data


def do_put_file(path, content_b64, allow_outside, confirm):
    full = _resolve(path, allow_outside)
    if _is_sensitive(full) and not confirm:
        audit(f"PUT BLOCKED (sensitive, unconfirmed) {full}")
        return "blocked", f"blocked: {full} is a sensitive/persistence path; re-send with \"confirm\":true if intended", None
    raw = base64.b64decode(content_b64, validate=True)
    parent = os.path.dirname(full)
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(full, "wb") as f:
        f.write(raw)
    audit(f"PUT {full} {len(raw)}b")
    return "ok", f"wrote {len(raw)}b to {full}", {"path": full, "bytes": len(raw)}


def do_get_file(path, allow_outside):
    full = _resolve(path, allow_outside)
    size = os.path.getsize(full)
    if size > MAX_GET:
        raise RuntimeError(f"file too large ({size}b > {MAX_GET}b cap)")
    with open(full, "rb") as f:
        raw = f.read()
    audit(f"GET {full} {len(raw)}b")
    return "ok", f"read {len(raw)}b from {full}", {"path": full, "bytes": len(raw),
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
                status, detail, data = do_exec(msg.get("command", ""), int(msg.get("timeout", 120)), bool(msg.get("confirm")))
            elif t == "put_file":
                status, detail, data = do_put_file(msg["path"], msg["content_b64"], bool(msg.get("allow_outside")), bool(msg.get("confirm")))
            elif t == "get_file":
                status, detail, data = do_get_file(msg["path"], bool(msg.get("allow_outside")))
            elif t == "print":
                status, detail = "ok", render_and_print(msg.get("title", "megamind"), msg.get("body", ""))
            elif t == "print_file":
                status, detail = "ok", handle_print_file(msg.get("filename", "document"), msg.get("kind", ""), msg.get("content_b64", ""))
            else:
                continue
        except Exception as e:
            status, detail = "error", f"{type(e).__name__}: {e}"
        audit_ok = audit(f"RESULT {t} {cid} status={status}")
        frame = {"type": "result", "id": cid, "status": status, "detail": detail, "audit_ok": audit_ok}
        if data is not None:
            frame["data"] = data
        await ws.send(json.dumps(frame))
        log.info(f"{t} {cid}: {status} — {detail}")


async def main():
    os.makedirs(WORKDIR, exist_ok=True)
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
