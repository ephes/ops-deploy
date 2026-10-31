"""Actual protected LocalConnector live-registry TLS policy; synthetic only."""

from __future__ import annotations

import asyncio
import json
import ssl
import subprocess
import sys
from importlib.resources import files
from pathlib import Path

from tests.test_homeassistant_pipelines import TOKEN, endpoint, initial

CHILD = r"""
import json,shlex,sys
from pydantic import SecretStr
from pyinfra.api import Config,Inventory,State,OperationError
from pyinfra.api.connect import connect_all,disconnect_all
from ops_deploy.services.homeassistant import live_registry
from ops_deploy.services.homeassistant.integration_flows import HomeAssistantApiConfig
from ops_deploy.services.homeassistant.runtime_config import HomeAssistantRuntimeConfig
v=json.load(sys.stdin)
state=State(Inventory((['@local'],{})),Config())
live_registry.registry_command=lambda runtime:shlex.join([sys.executable,'-I','-B',v['program']])
try:
    connect_all(state)
    api=HomeAssistantApiConfig(url=SecretStr(v['url']),token=SecretStr(v['credential']),
        timeout=2,retries=0,retry_delay=0,validate_certs=v['validate_certs'])
    try:
        result=live_registry.read_live_registry(state.inventory.get_host('@local'),HomeAssistantRuntimeConfig(),
            api,8123,SecretStr(json.dumps({'entry_id':'owned-entry','kinds':['stt']})))
    except OperationError:
        print(json.dumps({'success':False}))
    else:
        assert 'unmatched-private' not in result.get_secret_value()
        print(json.dumps({'success':True,'count':len(json.loads(result.get_secret_value()))}))
finally:
    disconnect_all(state)
"""


def test_actual_localconnector_tls_rejection_and_explicit_acceptance(tmp_path: Path) -> None:
    key, certificate = tmp_path / "owned.key", tmp_path / "owned.crt"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=owned-registry.invalid",
            "-keyout",
            str(key),
            "-out",
            str(certificate),
        ],
        check=True,
        capture_output=True,
        timeout=20,
    )
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certificate, key)

    async def scenario() -> None:
        registry = initial()
        registry["entities"] = [
            {
                "entity_id": "stt.owned",
                "platform": "wyoming",
                "config_entry_id": "owned-entry",
                "disabled_by": None,
                "options": {"private": "unmatched-private"},
            }
        ]
        async with endpoint(registry, ssl_context=context) as (url, calls):
            for verify in (True, False):
                value = {
                    "url": url,
                    "credential": TOKEN,
                    "validate_certs": verify,
                    "program": str(files("ops_deploy.services.homeassistant").joinpath("files/live_registry.py")),
                }
                proc = await asyncio.create_subprocess_exec(
                    sys.executable,
                    "-c",
                    CHILD,
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                try:
                    out, err = await asyncio.wait_for(proc.communicate(json.dumps(value).encode()), 15)
                finally:
                    if proc.returncode is None:
                        proc.kill()
                        await proc.communicate()
                assert proc.returncode == 0, err.decode()
                assert json.loads(out) == ({"success": False} if verify else {"success": True, "count": 1})
                assert TOKEN.encode() not in out + err
                assert b"unmatched-private" not in out + err
            assert [item["type"] for item in calls] == ["config/entity_registry/list"]

    asyncio.run(scenario())
