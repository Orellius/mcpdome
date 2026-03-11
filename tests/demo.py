#!/usr/bin/env python3
"""
MCPDome Live Demo — sends real MCP traffic through the proxy and verifies everything works.

Usage:
    python3 tests/demo.py

This spawns MCPDome wrapping the echo test server, sends a full MCP session
through it, and reports results.
"""

import json
import subprocess
import sys
import time
import os

# Colors
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"

def send_and_receive(proc, request):
    """Send a JSON-RPC request and read the response."""
    raw = json.dumps(request) + "\n"
    proc.stdin.write(raw)
    proc.stdin.flush()

    line = proc.stdout.readline()
    if not line:
        return None
    return json.loads(line.strip())


def main():
    print(f"\n{BOLD}{CYAN}  ╔══════════════════════════════════════╗{RESET}")
    print(f"{BOLD}{CYAN}  ║     MCPDome v0.1.0 — Live Demo       ║{RESET}")
    print(f"{BOLD}{CYAN}  ║     Protective Dome for AI Agents           ║{RESET}")
    print(f"{BOLD}{CYAN}  ╚══════════════════════════════════════╝{RESET}\n")

    # Find the mcpdome binary
    project_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    binary = os.path.join(project_dir, "target", "debug", "mcpdome")
    echo_server = os.path.join(project_dir, "tests", "fixtures", "echo_server.py")

    if not os.path.exists(binary):
        print(f"{RED}Binary not found at {binary}. Run 'cargo build' first.{RESET}")
        sys.exit(1)

    # Spawn MCPDome wrapping the echo server
    print(f"{DIM}  Starting MCPDome proxy...{RESET}")
    print(f"{DIM}  Upstream: python3 {echo_server}{RESET}\n")

    proc = subprocess.Popen(
        [binary, "proxy", "--upstream", f"python3 {echo_server}", "--log-level", "debug"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,  # capture logs
        text=True,
        bufsize=1,
    )

    time.sleep(0.3)  # let it start

    tests = []
    passed = 0
    failed = 0

    # ── Test 1: Initialize ──
    print(f"  {BOLD}Test 1: MCP Initialize{RESET}")
    resp = send_and_receive(proc, {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"capabilities": {}}
    })

    if resp and resp.get("result", {}).get("serverInfo", {}).get("name") == "echo-test-server":
        print(f"  {GREEN}✓ Server identified as 'echo-test-server'{RESET}")
        print(f"  {DIM}  Protocol: {resp['result'].get('protocolVersion', '?')}{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Unexpected response: {resp}{RESET}")
        failed += 1

    # ── Test 2: Tools List ──
    print(f"\n  {BOLD}Test 2: Tools List{RESET}")
    resp = send_and_receive(proc, {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    })

    tools = resp.get("result", {}).get("tools", []) if resp else []
    if tools and tools[0].get("name") == "echo":
        print(f"  {GREEN}✓ Found tool: 'echo' — {tools[0].get('description', '')}{RESET}")
        print(f"  {DIM}  Schema: {json.dumps(tools[0].get('inputSchema', {}), indent=None)}{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Unexpected response: {resp}{RESET}")
        failed += 1

    # ── Test 3: Tool Call (echo) ──
    print(f"\n  {BOLD}Test 3: Tool Call — echo{RESET}")
    test_message = "Hello from MCPDome!"
    resp = send_and_receive(proc, {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": test_message}
        }
    })

    content = resp.get("result", {}).get("content", [{}]) if resp else [{}]
    echoed = content[0].get("text", "") if content else ""
    if echoed == test_message:
        print(f"  {GREEN}✓ Sent: '{test_message}' → Got: '{echoed}'{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Expected '{test_message}', got '{echoed}'{RESET}")
        failed += 1

    # ── Test 4: Unknown tool (error handling) ──
    print(f"\n  {BOLD}Test 4: Unknown Tool — error handling{RESET}")
    resp = send_and_receive(proc, {
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {
            "name": "hack_the_planet",
            "arguments": {}
        }
    })

    err = resp.get("error") if resp else None
    if err and err.get("code") == -32601:
        print(f"  {GREEN}✓ Correctly rejected: '{err.get('message', '')}'{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Expected error, got: {resp}{RESET}")
        failed += 1

    # ── Test 5: Rapid fire (5 sequential requests) ──
    print(f"\n  {BOLD}Test 5: Rapid Fire — 5 sequential tool calls{RESET}")
    rapid_ok = True
    start = time.time()
    for i in range(5):
        resp = send_and_receive(proc, {
            "jsonrpc": "2.0",
            "id": 100 + i,
            "method": "tools/call",
            "params": {
                "name": "echo",
                "arguments": {"message": f"burst-{i}"}
            }
        })
        content = resp.get("result", {}).get("content", [{}]) if resp else [{}]
        if content[0].get("text") != f"burst-{i}":
            rapid_ok = False
            break

    elapsed_ms = (time.time() - start) * 1000
    if rapid_ok:
        print(f"  {GREEN}✓ 5/5 requests returned correctly in {elapsed_ms:.0f}ms{RESET}")
        print(f"  {DIM}  Avg: {elapsed_ms/5:.1f}ms per roundtrip through dome{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Rapid fire failed{RESET}")
        failed += 1

    # ── Test 6: Large payload ──
    print(f"\n  {BOLD}Test 6: Large Payload — 10KB message{RESET}")
    big_message = "X" * 10_000
    resp = send_and_receive(proc, {
        "jsonrpc": "2.0",
        "id": 200,
        "method": "tools/call",
        "params": {
            "name": "echo",
            "arguments": {"message": big_message}
        }
    })

    content = resp.get("result", {}).get("content", [{}]) if resp else [{}]
    got = content[0].get("text", "") if content else ""
    if got == big_message:
        print(f"  {GREEN}✓ 10,000 byte payload passed through intact{RESET}")
        passed += 1
    else:
        print(f"  {RED}✗ Payload corrupted (got {len(got)} bytes){RESET}")
        failed += 1

    # ── Cleanup ──
    proc.stdin.close()
    proc.terminate()
    proc.wait(timeout=3)

    # Read proxy logs
    stderr_output = proc.stderr.read()
    log_lines = [l for l in stderr_output.strip().split("\n") if l.strip()]

    # ── Results ──
    print(f"\n  {'─' * 40}")
    total = passed + failed
    if failed == 0:
        print(f"\n  {GREEN}{BOLD}  ALL {total} TESTS PASSED{RESET}")
        print(f"  {GREEN}  MCPDome proxy is working correctly.{RESET}")
    else:
        print(f"\n  {RED}{BOLD}  {failed}/{total} TESTS FAILED{RESET}")

    print(f"\n  {DIM}Proxy log lines captured: {len(log_lines)}{RESET}")

    # Show a sample of proxy logs
    if log_lines:
        print(f"\n  {BOLD}Sample proxy logs:{RESET}")
        for line in log_lines[:8]:
            print(f"  {DIM}  {line}{RESET}")
        if len(log_lines) > 8:
            print(f"  {DIM}  ... and {len(log_lines) - 8} more{RESET}")

    print()
    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
