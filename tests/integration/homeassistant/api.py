"""Fixture-only actual HA user/token API, with no credential/body logging."""

from __future__ import annotations

import asyncio
import json
import runpy
import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import aiohttp

DEADLINE_SECONDS = 120


def loopback_url(url: str) -> str:
    parts = urlsplit(url)
    if (
        parts.scheme != "http"
        or parts.hostname != "127.0.0.1"
        or parts.username
        or parts.password
        or parts.path not in ("", "/")
        or parts.query
        or parts.fragment
    ):
        raise ValueError("owned API must use literal loopback HTTP")
    return url.rstrip("/")


async def seed_user(url: str) -> str:
    """Original2026.10.2 user onboarding -> token exchange -> actual WS token."""
    url = loopback_url(url)
    client_id = url + "/"
    timeout = aiohttp.ClientTimeout(total=90)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.post(
            url + "/api/onboarding/users",
            json={
                "name": "Owned synthetic operator",
                "username": "owned-native",
                "password": secrets.token_urlsafe(32),
                "client_id": client_id,
                "language": "en",
            },
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise RuntimeError("owned user onboarding failed")
            code = (await response.json())["auth_code"]
        async with session.post(
            url + "/auth/token",
            data={
                "client_id": client_id,
                "grant_type": "authorization_code",
                "code": code,
            },
            allow_redirects=False,
        ) as response:
            if response.status != 200:
                raise RuntimeError("owned token exchange failed")
            token = (await response.json())["access_token"]
        async with session.ws_connect(
            url + "/api/websocket", timeout=aiohttp.ClientWSTimeout(ws_receive=30, ws_close=10)
        ) as ws:
            if (await ws.receive_json())["type"] != "auth_required":
                raise RuntimeError("owned websocket auth challenge missing")
            await ws.send_json({"type": "auth", "access_token": token})
            if (await ws.receive_json())["type"] != "auth_ok":
                raise RuntimeError("owned websocket authentication failed")
            await ws.send_json(
                {
                    "id": 1,
                    "type": "auth/long_lived_access_token",
                    "client_name": "Owned native qualification",
                    "lifespan": 1,
                }
            )
            result = await ws.receive_json()
            if result.get("id") != 1 or result.get("success") is not True or not isinstance(result.get("result"), str):
                raise RuntimeError("owned long-lived token creation failed")
            selected = result["result"]
            assert isinstance(selected, str)
            if len(selected) < 32:
                raise RuntimeError("owned access token too short")
            return selected


async def websocket(url: str, token: str, command: dict[str, Any]) -> Any:
    url = loopback_url(url)
    async with (
        aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=60)) as session,
        session.ws_connect(url + "/api/websocket", timeout=aiohttp.ClientWSTimeout(ws_receive=30, ws_close=10)) as ws,
    ):
        if (await ws.receive_json())["type"] != "auth_required":
            raise RuntimeError("owned websocket auth challenge missing")
        await ws.send_json({"type": "auth", "access_token": token})
        if (await ws.receive_json())["type"] != "auth_ok":
            raise RuntimeError("owned websocket authentication failed")
        await ws.send_json({**command, "id": 1})
        for _ in range(32):
            result = await ws.receive_json()
            if result.get("id") != 1:
                continue
            if result.get("success") is not True:
                raise RuntimeError("owned websocket operation failed")
            return result.get("result")
        raise RuntimeError("owned websocket operation did not finish")


async def _execute(value: dict[str, Any]) -> dict[str, Any]:
    url = loopback_url(value["url"])
    if value["action"] == "seed":
        return {"token": await seed_user(url)}  # Parent captures in RAM, never evidence/stdout forwarding.
    if value["action"] == "ws":
        return {"result": await websocket(url, value["token"], value["command"])}
    if value["action"] == "confirm-http-baseline":
        if urlsplit(url).port != 10020:
            raise ValueError("HTTP confirmation requires the owned fixture port")
        # Fixed reviewed fixture source; -I intentionally excludes ambient
        # import paths. No request/provider path selects executable source.
        helper = runpy.run_path(str(Path(__file__).with_name("http_baseline.py")))

        async def request(command: dict[str, Any]) -> Any:
            return await websocket(url, value["token"], command)

        result = await helper["complete"](request, value["command"]["ipv4"])
        if not isinstance(result, dict):
            raise ValueError("invalid owned HTTP baseline result")
        return result
    if value["action"] == "health":
        async with (
            aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=30)) as session,
            session.get(
                url + "/api/", headers={"Authorization": "Bearer " + value["token"]}, allow_redirects=False
            ) as response,
        ):
            return {"status": response.status}
    raise ValueError("unknown owned API action")


async def execute(value: dict[str, Any]) -> dict[str, Any]:
    # ClientTimeout does not bound an authenticated websocket's receive lifetime.
    async with asyncio.timeout(DEADLINE_SECONDS):
        return await _execute(value)


if __name__ == "__main__":
    try:
        value = json.load(sys.stdin)
        result = asyncio.run(execute(value))
    except Exception as error:
        # Never print exception text, auth response, request or token on failure.
        print(json.dumps({"error_type": type(error).__name__}))
        raise SystemExit(1) from None
    print(json.dumps(result))
