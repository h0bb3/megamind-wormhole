"""Local integration test for the relay: mock gateway + /print round-trip."""
import asyncio
import json
import urllib.request
import urllib.error

import websockets

BASE = "http://127.0.0.1:8091"
WS = "ws://127.0.0.1:8091/ws"


def http_post(path, token, data):
    req = urllib.request.Request(
        BASE + path, data=json.dumps(data).encode(),
        headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


async def main():
    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({"type": "hello", "token": "testenroll", "gateway_id": "mock"}))
        print("welcome:", await ws.recv())
        loop = asyncio.get_event_loop()
        post_fut = loop.run_in_executor(None, http_post, "/print", "testcloud",
                                        {"title": "hi", "body": "hello\nworld"})
        raw = await asyncio.wait_for(ws.recv(), timeout=10)
        m = json.loads(raw)
        print("gateway got cmd:", m)
        assert m["type"] == "print" and m.get("body") == "hello\nworld"
        await ws.send(json.dumps({"type": "result", "id": m["id"], "status": "ok", "detail": "mock printed"}))
        status, body = await post_fut
        print(f"/print -> HTTP {status}: {body}")
        assert status == 200 and '"ok":true' in body, "PRINT ROUNDTRIP FAILED"
    print("LOCAL RELAY TEST: PASS")


asyncio.run(main())
