#!/usr/bin/python3
"""Owned native fixture only: exact original MC commands, no network."""

from __future__ import annotations

import json
import sys
from pathlib import Path

root = Path(__file__).resolve().parent
state_path = root / "iam.json"
state = json.loads(state_path.read_text())
args = sys.argv[1:]
assert len(args) >= 5
assert args[0] == "admin"
assert args[3:5] == ["--json", "local"]
command = " ".join(args[1:3])
with (root / "commands.jsonl").open("a") as log:
    log.write(json.dumps({"command": command}) + "\n")
result: dict[str, object] = {"status": "success"}
missing = None
if command == state.get("fault"):
    sys.exit(7)
if command == "policy info":
    assert args[5:] == ["daybook-voice-memo-attention-read"]
    if state["policy"] is None:
        missing = "XMinioAdminNoSuchPolicy"
    else:
        result["policyInfo"] = {"Policy": state["policy"]}
elif command == "user info":
    assert args[5:] == [state["access"]]
    if state["user"] is None:
        missing = "XMinioAdminNoSuchUser"
    else:
        result.update(state["user"])
elif command == "policy entities":
    assert args[5:] == ["--user", state["access"]]
    result["result"] = state["mappings"]
elif command == "policy create":
    assert args[5] == "daybook-voice-memo-attention-read"
    assert len(args) == 7
    state["policy"] = json.loads(Path(args[6]).read_text())
elif command == "user add":
    assert args[5:] == []
    assert sys.stdin.read().splitlines() == [state["access"], state["secret"]]
    assert state["user"] is None
    state["user"] = {"accessKey": state["access"], "userStatus": "enabled", "memberOf": [], "policyName": ""}
elif command == "policy attach":
    assert args[5:] == ["daybook-voice-memo-attention-read", "--user", state["access"]]
    state["user"]["policyName"] = "daybook-voice-memo-attention-read"
    state["mappings"] = {"userMappings": [{"user": state["access"], "policies": ["daybook-voice-memo-attention-read"]}]}
else:
    raise AssertionError("Unpermitted fixture command")
if missing:
    print(json.dumps({"error": {"cause": {"error": {"Code": missing}}}}))
    sys.exit(1)
if command in {"policy create", "user add", "policy attach"}:
    state_path.write_text(json.dumps(state))
print(json.dumps(result))
