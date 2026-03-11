#!/usr/bin/env python3
"""
Minimal MCP server over stdio for integration testing.

Reads newline-delimited JSON-RPC 2.0 from stdin, writes responses to stdout.

Handles:
  - "initialize"  -> returns server capabilities
  - "tools/list"  -> returns a single fake tool ("echo")
  - "tools/call"  -> returns the arguments passed to it
  - anything else -> echoes the request back as a result
"""

import json
import sys


def make_response(request_id, result):
    return json.dumps({"jsonrpc": "2.0", "id": request_id, "result": result})


def make_error(request_id, code, message):
    return json.dumps({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    })


def handle_message(raw_line):
    try:
        msg = json.loads(raw_line)
    except json.JSONDecodeError:
        # Can't parse, can't respond without an id
        return None

    msg_id = msg.get("id")
    method = msg.get("method")
    params = msg.get("params", {})

    # Notifications (no id) get no response per JSON-RPC spec
    if msg_id is None:
        return None

    if method == "initialize":
        return make_response(msg_id, {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {"listChanged": False},
            },
            "serverInfo": {
                "name": "echo-test-server",
                "version": "0.1.0",
            },
        })

    if method == "tools/list":
        return make_response(msg_id, {
            "tools": [
                {
                    "name": "echo",
                    "description": "Echoes back whatever you send",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "message": {"type": "string", "description": "The message to echo"},
                        },
                        "required": ["message"],
                    },
                }
            ]
        })

    if method == "tools/call":
        tool_name = params.get("name", "unknown")
        arguments = params.get("arguments", {})

        if tool_name == "echo":
            echo_msg = arguments.get("message", "")
            return make_response(msg_id, {
                "content": [
                    {"type": "text", "text": echo_msg}
                ]
            })

        return make_error(msg_id, -32601, f"unknown tool: {tool_name}")

    # Fallback: echo the whole request back as the result
    return make_response(msg_id, {"echo": msg})


def main():
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue

        response = handle_message(line)
        if response is not None:
            sys.stdout.write(response + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
