"""Local integration test for the relay: mock gateway + /print and /print_file round-trips."""
import asyncio
import json
import urllib.request
import urllib.error
import base64

import websockets

BASE = "http://127.0.0.1:8091"
WS = "ws://127.0.0.1:8091/ws"


def post(path, token, data):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(data).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


async def one(ws, loop, path, data):
    fut = loop.run_in_executor(None, post, path, "testcloud", data)
    cmd = json.loads(await asyncio.wait_for(ws.recv(), timeout=10))
    print(f"gateway got: type={cmd.get('type')} file={cmd.get('filename','-')}")
    await ws.send(json.dumps({"type": "result", "id": cmd["id"], "status": "ok", "detail": "mock ok"}))
    st, body = await fut
    print(f"{path} -> HTTP {st}: {body}")
    assert st == 200 and '"ok":true' in body, f"{path} FAILED"


async def main():
    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({"type": "hello", "token": "testenroll", "gateway_id": "mock"}))
        print("welcome:", await ws.recv())
        loop = asyncio.get_event_loop()
        await one(ws, loop, "/print", {"title": "t", "body": "hi\nthere"})
        await one(ws, loop, "/print_file",
                  {"filename": "x.pdf", "content_b64": base64.b64encode(b"%PDF-1.4 fake").decode()})
    print("LOCAL RELAY TEST: PASS")


asyncio.run(main())
