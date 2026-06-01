"""megamind-wormhole relay — single-tenant (trusted-relay) Stage 1 + generic body.

One launcher pod, listeners:
  - WS /ws         : the gateway dials OUT and holds this; auth = enrollment token.
  - POST /exec     : run a shell command on the box -> {stdout, stderr, exit_code}. The generic body.
  - POST /put_file : write base64 bytes to a path on the box (move a file TO the box).
  - POST /get_file : read a path on the box -> base64 (move a file FROM the box).
  - POST /print    : convenience — print TEXT ({title, body}).
The relay only FORWARDS to the connected gateway and returns its result; it never inspects
payloads. The box runs commands as a NON-ROOT user and keeps an append-only audit log.
Single-tenant, in-memory, no DB. Per-command ES256 capability auth (keyflow.py) is the
multi-tenant gate. Secrets come from env (launcher set_env), never the repo.
"""
import os
import json
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
CLOUD_TOKEN = os.environ.get("RELAY_CLOUD_TOKEN", "")
MAX_FILE_B64 = 12 * 1024 * 1024     # ~9 MB decoded cap (DoS guard)

gw = {"ws": None, "id": None}
pending = {}


async def health(request):
    return PlainTextResponse("ok")


async def status_ep(request):
    return JSONResponse({"gateway_connected": gw["ws"] is not None, "gateway_id": gw["id"]})


def _authed(request):
    return bool(CLOUD_TOKEN) and request.headers.get("authorization", "") == f"Bearer {CLOUD_TOKEN}"


async def _dispatch(cmd, timeout=130):
    fut = asyncio.get_event_loop().create_future()
    pending[cmd["id"]] = fut
    try:
        await gw["ws"].send_text(json.dumps(cmd))
        result = await asyncio.wait_for(fut, timeout=timeout)
        return JSONResponse({"ok": result.get("status") == "ok", "result": result})
    except asyncio.TimeoutError:
        return JSONResponse({"error": "gateway timeout"}, status_code=504)
    finally:
        pending.pop(cmd["id"], None)


def _guard(request):
    if not _authed(request):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if gw["ws"] is None:
        return JSONResponse({"error": "no gateway connected"}, status_code=503)
    return None


async def exec_ep(request):
    if (r := _guard(request)) is not None:
        return r
    body = await request.json()
    command = body.get("command", "")
    if not command:
        return JSONResponse({"error": "command required"}, status_code=400)
    t = int(body.get("timeout", 120))
    return await _dispatch({"type": "exec", "id": str(uuid.uuid4()), "command": command, "timeout": t}, timeout=t + 15)


async def put_file_ep(request):
    if (r := _guard(request)) is not None:
        return r
    body = await request.json()
    content_b64, path = body.get("content_b64", ""), body.get("path", "")
    if not content_b64 or not path:
        return JSONResponse({"error": "path and content_b64 required"}, status_code=400)
    if len(content_b64) > MAX_FILE_B64:
        return JSONResponse({"error": "file too large"}, status_code=413)
    return await _dispatch({"type": "put_file", "id": str(uuid.uuid4()), "path": path, "content_b64": content_b64})


async def get_file_ep(request):
    if (r := _guard(request)) is not None:
        return r
    body = await request.json()
    path = body.get("path", "")
    if not path:
        return JSONResponse({"error": "path required"}, status_code=400)
    return await _dispatch({"type": "get_file", "id": str(uuid.uuid4()), "path": path})


async def print_ep(request):
    if (r := _guard(request)) is not None:
        return r
    body = await request.json()
    return await _dispatch({"type": "print", "id": str(uuid.uuid4()),
                            "title": body.get("title", "megamind"), "body": body.get("body", "")})


async def print_file_ep(request):
    if (r := _guard(request)) is not None:
        return r
    body = await request.json()
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
    if not ENROLL_TOKEN or hello.get("type") != "hello" or hello.get("token") != ENROLL_TOKEN:
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
