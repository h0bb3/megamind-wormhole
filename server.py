"""megamind-wormhole relay — single-tenant (trusted-relay) Stage 1 + generic body.

One launcher pod, listeners:
  - WS /ws         : the gateway dials OUT and holds this; auth = enrollment token.
  - POST /exec     : run a shell command on the box -> {stdout, stderr, exit_code}.
  - POST /put_file : write base64 bytes to a path on the box.
  - POST /get_file : read a path on the box -> base64.
  - POST /print    : convenience — print TEXT ({title, body}).
The relay FORWARDS to the connected gateway and returns its result. It ALSO logs every command
+ result to its own stdout -> this is the OFF-BOX audit copy (the box-user can't rewrite it).
Auth = constant-time-compared bearer with TWO scopes: RELAY_CLOUD_TOKEN (full — every endpoint)
and RELAY_PRINT_TOKEN (/print + /print_file ONLY -> 403 on exec/put/get). The print scope is the
MECHANICAL fence for the untrusted Slack wake path: a hijacked print-scoped mind provably cannot
exec or move files. Per-command keyflow ES256 is the multi-tenant gate. Secrets from env
(launcher set_env), never the repo.
"""
import os
import json
import hmac
import asyncio
import logging
import uuid

from starlette.applications import Starlette
from starlette.routing import Route, WebSocketRoute
from starlette.responses import PlainTextResponse, JSONResponse
from starlette.websockets import WebSocket, WebSocketDisconnect
import uvicorn

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("relay")

ENROLL_TOKEN = os.environ.get("RELAY_ENROLL_TOKEN", "")
CLOUD_TOKEN = os.environ.get("RELAY_CLOUD_TOKEN", "")      # FULL scope: every endpoint (human/laptop path)
PRINT_TOKEN = os.environ.get("RELAY_PRINT_TOKEN", "")      # PRINT scope: /print + /print_file ONLY (the Slack wake path) — 403 elsewhere
MAX_FILE_B64 = 12 * 1024 * 1024

gw = {"ws": None, "id": None}
pending = {}


async def health(request):
    return PlainTextResponse("ok")


async def status_ep(request):
    return JSONResponse({"gateway_connected": gw["ws"] is not None, "gateway_id": gw["id"]})


def _auth_scope(request):
    """Privilege of the presented bearer: 'cloud' (full), 'print' (print-only), or None.
    Two tokens so the untrusted Slack wake path can hold one that mechanically CANNOT reach exec/put/get.
    Both compares are constant-time; an unset env token can never match (guarded by the `and`)."""
    h = request.headers.get("authorization", "")
    if CLOUD_TOKEN and hmac.compare_digest(h, f"Bearer {CLOUD_TOKEN}"):
        return "cloud"
    if PRINT_TOKEN and hmac.compare_digest(h, f"Bearer {PRINT_TOKEN}"):
        return "print"
    return None


async def _dispatch(cmd, timeout=130):
    # OFF-BOX audit: the relay sees every command; log it pod-side (-> launcher logs, box-user can't wipe).
    summary = {k: cmd[k] for k in ("type", "id", "command", "path", "filename", "confirm", "allow_outside") if k in cmd}
    log.info(f"AUDIT-IN {json.dumps(summary)}")
    fut = asyncio.get_event_loop().create_future()
    pending[cmd["id"]] = fut
    try:
        await gw["ws"].send_text(json.dumps(cmd))
        result = await asyncio.wait_for(fut, timeout=timeout)
        log.info(f"AUDIT-OUT id={cmd['id']} status={result.get('status')} audit_ok={result.get('audit_ok')} detail={result.get('detail')}")
        return JSONResponse({"ok": result.get("status") == "ok", "result": result})
    except asyncio.TimeoutError:
        log.info(f"AUDIT-OUT id={cmd['id']} status=timeout")
        return JSONResponse({"error": "gateway timeout"}, status_code=504)
    finally:
        pending.pop(cmd["id"], None)


async def _prepare(request, allow=("cloud",)):
    """Authenticate + authorize scope (401 unknown token / 403 wrong scope), then parse JSON (400).
    `allow` = scopes permitted on this endpoint (default: full 'cloud' only). Returns (body, None) or (None, error)."""
    scope = _auth_scope(request)
    if scope is None:
        return None, JSONResponse({"error": "unauthorized"}, status_code=401)
    if scope not in allow:
        return None, JSONResponse({"error": "forbidden: token scope may not call this endpoint"}, status_code=403)
    try:
        body = await request.json()
    except Exception:
        return None, JSONResponse({"error": "invalid JSON body"}, status_code=400)
    if not isinstance(body, dict):
        return None, JSONResponse({"error": "JSON body must be an object"}, status_code=400)
    return body, None


def _need_gateway():
    if gw["ws"] is None:
        return JSONResponse({"error": "no gateway connected"}, status_code=503)
    return None


async def exec_ep(request):
    body, err = await _prepare(request)
    if err is not None:
        return err
    if (r := _need_gateway()) is not None:
        return r
    command = body.get("command", "")
    if not command:
        return JSONResponse({"error": "command required"}, status_code=400)
    t = int(body.get("timeout", 120))
    return await _dispatch({"type": "exec", "id": str(uuid.uuid4()), "command": command,
                            "timeout": t, "confirm": bool(body.get("confirm"))}, timeout=t + 15)


async def put_file_ep(request):
    body, err = await _prepare(request)
    if err is not None:
        return err
    if (r := _need_gateway()) is not None:
        return r
    content_b64, path = body.get("content_b64", ""), body.get("path", "")
    if not content_b64 or not path:
        return JSONResponse({"error": "path and content_b64 required"}, status_code=400)
    if len(content_b64) > MAX_FILE_B64:
        return JSONResponse({"error": "file too large"}, status_code=413)
    return await _dispatch({"type": "put_file", "id": str(uuid.uuid4()), "path": path, "content_b64": content_b64,
                            "allow_outside": bool(body.get("allow_outside")), "confirm": bool(body.get("confirm"))})


async def get_file_ep(request):
    body, err = await _prepare(request)
    if err is not None:
        return err
    if (r := _need_gateway()) is not None:
        return r
    path = body.get("path", "")
    if not path:
        return JSONResponse({"error": "path required"}, status_code=400)
    return await _dispatch({"type": "get_file", "id": str(uuid.uuid4()), "path": path,
                            "allow_outside": bool(body.get("allow_outside"))})


async def print_ep(request):
    body, err = await _prepare(request, allow=("cloud", "print"))
    if err is not None:
        return err
    if (r := _need_gateway()) is not None:
        return r
    return await _dispatch({"type": "print", "id": str(uuid.uuid4()),
                            "title": body.get("title", "megamind"), "body": body.get("body", "")})


async def print_file_ep(request):
    body, err = await _prepare(request, allow=("cloud", "print"))
    if err is not None:
        return err
    if (r := _need_gateway()) is not None:
        return r
    content_b64 = body.get("content_b64", "")
    if not content_b64:
        return JSONResponse({"error": "content_b64 required"}, status_code=400)
    if len(content_b64) > MAX_FILE_B64:
        return JSONResponse({"error": "file too large"}, status_code=413)
    return await _dispatch({"type": "print_file", "id": str(uuid.uuid4()),
                            "filename": body.get("filename", "document"),
                            "kind": body.get("kind", ""), "content_b64": content_b64})


async def ws_endpoint(ws: WebSocket):
    await ws.accept()
    try:
        hello = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=10))
    except Exception:
        await ws.close(code=4001)
        return
    tok = hello.get("token", "") or ""
    if not ENROLL_TOKEN or hello.get("type") != "hello" or not hmac.compare_digest(tok, ENROLL_TOKEN):
        log.info("WS auth FAIL")
        await ws.close(code=4003)
        return
    gw["ws"], gw["id"] = ws, hello.get("gateway_id", "gw")
    log.info(f"gateway '{gw['id']}' CONNECTED")
    await ws.send_text(json.dumps({"type": "welcome"}))
    try:
        while True:
            msg = json.loads(await ws.receive_text())
            if msg.get("type") == "result":
                fut = pending.get(msg.get("id"))
                if fut and not fut.done():
                    fut.set_result(msg)
    except WebSocketDisconnect:
        log.info(f"gateway '{gw['id']}' DISCONNECTED")
    except Exception as e:
        log.info(f"ws error: {type(e).__name__}: {e}")
    finally:
        if gw["ws"] is ws:
            gw["ws"], gw["id"] = None, None


app = Starlette(routes=[
    Route("/health", health),
    Route("/status", status_ep),
    Route("/exec", exec_ep, methods=["POST"]),
    Route("/put_file", put_file_ep, methods=["POST"]),
    Route("/get_file", get_file_ep, methods=["POST"]),
    Route("/print", print_ep, methods=["POST"]),
    Route("/print_file", print_file_ep, methods=["POST"]),
    WebSocketRoute("/ws", ws_endpoint),
])

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")),
                ws_ping_interval=20, ws_ping_timeout=25, ws_max_size=16 * 1024 * 1024)
