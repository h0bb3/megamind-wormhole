"""Relay request-validation regression test (issue #1: malformed body must be 400, not 500).

Self-contained: starts server.py in a subprocess with test tokens, connects a mock gateway,
and checks auth / malformed-JSON / non-object-body / happy-path. Run: python test_relay_validation.py
(needs the venv with starlette/uvicorn/websockets). Exits non-zero on any failure.
"""
import asyncio
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

import websockets

PORT = int(os.environ.get("TEST_PORT", "8093"))
BASE = f"http://127.0.0.1:{PORT}"
WS = f"ws://127.0.0.1:{PORT}/ws"
HERE = os.path.dirname(os.path.abspath(__file__))

fails = []
SENTINEL = "SENTINEL-REPLY-TEXT-MUST-NOT-BE-LOGGED-7f3a9"  # verbatim reply text; must never hit the off-box audit


def check(label, got, want):
    ok = got == want
    print(f"  [{'PASS' if ok else 'FAIL <<<'}] {label}: expected {want}, got {got}")
    if not ok:
        fails.append(label)


def post(path, token, raw):
    """POST raw bytes; return HTTP status code (HTTPError carries the real code)."""
    h = {"Content-Type": "application/json"}
    if token is not None:
        h["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(BASE + path, data=raw, headers=h, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


async def mock_gateway(connected):
    async with websockets.connect(WS) as ws:
        await ws.send(json.dumps({"type": "hello", "token": "testenroll", "gateway_id": "mock"}))
        await ws.recv()  # welcome
        connected.set_result(True)
        async for raw in ws:
            msg = json.loads(raw)
            await ws.send(json.dumps({"type": "result", "id": msg["id"], "status": "ok",
                                      "detail": "mock ok", "audit_ok": True}))


async def run_checks():
    loop = asyncio.get_event_loop()

    async def P(path, token, raw):
        return await loop.run_in_executor(None, post, path, token, raw)

    print("== auth precedes body parsing ==")
    check("wrong token + malformed body -> 401", await P("/exec", "WRONG", b"{not json"), 401)

    print("== malformed body BEFORE a gateway connects (must 400, not 503/500) ==")
    check("malformed JSON, no gateway -> 400", await P("/exec", "testcloud", b"{not json"), 400)

    print("== with a connected gateway ==")
    connected = loop.create_future()
    gw = asyncio.ensure_future(mock_gateway(connected))
    try:
        await asyncio.wait_for(connected, timeout=5)
        check("malformed JSON, gateway up -> 400", await P("/exec", "testcloud", b"{not json"), 400)
        check("non-object JSON body (5) -> 400", await P("/exec", "testcloud", b"5"), 400)
        check("empty body -> 400", await P("/exec", "testcloud", b""), 400)
        # happy path still works
        check("valid exec -> 200", await P("/exec", "testcloud", json.dumps({"command": "echo hi"}).encode()), 200)
        # field validation still 400
        check("missing command -> 400", await P("/exec", "testcloud", json.dumps({}).encode()), 400)

        print("== PRINT-SCOPE token (the Slack fence): print endpoints OK, exec/put/get 403 ==")
        check("print-token /print -> 200", await P("/print", "testprint", json.dumps({"title": "t", "body": "b"}).encode()), 200)
        check("print-token /print_file -> 200", await P("/print_file", "testprint", json.dumps({"content_b64": "aGk="}).encode()), 200)
        check("print-token /exec -> 403", await P("/exec", "testprint", json.dumps({"command": "echo hi"}).encode()), 403)
        check("print-token /put_file -> 403", await P("/put_file", "testprint", json.dumps({"path": "x", "content_b64": "aGk="}).encode()), 403)
        check("print-token /get_file -> 403", await P("/get_file", "testprint", json.dumps({"path": "x"}).encode()), 403)
        check("print-token /exec + malformed body -> 403 (scope BEFORE body parse)", await P("/exec", "testprint", b"{not json"), 403)

        print("== CLOUD-SCOPE token unchanged: full access ==")
        check("cloud-token /print -> 200", await P("/print", "testcloud", json.dumps({"title": "t", "body": "b"}).encode()), 200)
        check("cloud-token /print_file -> 200", await P("/print_file", "testcloud", json.dumps({"content_b64": "aGk="}).encode()), 200)
        check("cloud-token /exec -> 200 (still full)", await P("/exec", "testcloud", json.dumps({"command": "echo hi"}).encode()), 200)

        print("== unknown token -> 401 even on a print endpoint ==")
        check("unknown token /print -> 401", await P("/print", "nope", json.dumps({"title": "t"}).encode()), 401)

        print("== SLACK endpoints: print-scoped, fence still holds ==")
        check("print-token /slack_print -> 200", await P("/slack_print", "testprint", json.dumps({"file_id": "F123"}).encode()), 200)
        check("print-token /slack_reply -> 200", await P("/slack_reply", "testprint", json.dumps({"channel": "C1", "thread_ts": "1.2", "text": SENTINEL}).encode()), 200)
        check("print-token /exec STILL 403 (fence holds w/ slack routes added)", await P("/exec", "testprint", json.dumps({"command": "echo hi"}).encode()), 403)
        check("cloud-token /slack_print -> 200", await P("/slack_print", "testcloud", json.dumps({"file_id": "F123"}).encode()), 200)
        check("slack_print missing file_id -> 400", await P("/slack_print", "testprint", json.dumps({}).encode()), 400)
        check("slack_reply missing thread_ts -> 400", await P("/slack_reply", "testprint", json.dumps({"channel": "C1", "text": "x"}).encode()), 400)
        check("bad token /slack_print -> 401", await P("/slack_print", "nope", json.dumps({"file_id": "F1"}).encode()), 401)
    finally:
        gw.cancel()


def main():
    env = dict(os.environ, RELAY_ENROLL_TOKEN="testenroll", RELAY_CLOUD_TOKEN="testcloud",
               RELAY_PRINT_TOKEN="testprint", PORT=str(PORT))
    srv = subprocess.Popen([sys.executable, os.path.join(HERE, "server.py")], env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    out = ""
    try:
        # wait for the relay to bind
        for _ in range(50):
            try:
                with urllib.request.urlopen(BASE + "/health", timeout=1) as r:
                    if r.status == 200:
                        break
            except Exception:
                time.sleep(0.2)
        else:
            raise RuntimeError("relay did not come up")
        asyncio.run(run_checks())
    finally:
        srv.terminate()
        try:
            out = srv.communicate(timeout=5)[0].decode("utf-8", "replace")
        except subprocess.TimeoutExpired:
            srv.kill()
            out = srv.communicate()[0].decode("utf-8", "replace")
    print("== off-box AUDIT-LEAK regression (slack_reply verbatim text must NOT be logged) ==")
    check("SENTINEL reply text ABSENT from relay audit log", SENTINEL not in out, True)
    check("slack_reply logs text_len (length only) instead", "text_len" in out, True)
    if fails:
        print(f"\nRELAY VALIDATION TEST: FAIL ({len(fails)} failed: {fails})")
        sys.exit(1)
    print("\nRELAY VALIDATION TEST: PASS")


if __name__ == "__main__":
    main()
