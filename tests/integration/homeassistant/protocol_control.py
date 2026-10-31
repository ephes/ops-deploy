"""Actual upstream clients against synthetic peers; not an HA application run.

Caller installs exact original manifest dependencies in an ephemeral environment:
openai3.10.0, wyoming1.10.2 and python-otbr-api3.0.0. No production endpoint/auth.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.metadata
import json
import threading

import aiohttp

from .model_server import MODEL, ModelServer
from .otbr_server import OtbrServer
from .wyoming_server import WyomingServer

# Optional exact upstream client dependencies belong to this explicit control
# invocation, not the deployed controller or the repository's default imports.
openai = importlib.import_module("openai")
python_otbr_api = importlib.import_module("python_otbr_api")
tlv_parser = importlib.import_module("python_otbr_api.tlv_parser")
wyoming_event = importlib.import_module("wyoming.event")
wyoming_info = importlib.import_module("wyoming.info")


async def control(model: int, wyoming: int, otbr: int) -> None:
    async with openai.AsyncOpenAI(
        api_key="synthetic-only", base_url=f"http://127.0.0.1:{model}/v1", timeout=5, max_retries=0
    ) as client:
        models = await client.models.list()
        assert [item.id for item in models.data] == [MODEL]
        payload = [{"role": "user", "content": "Reply OK."}]
        answer = await client.chat.completions.create(model=MODEL, messages=payload)
        assert answer.choices[0].message.content == "OK"
        stream = await client.chat.completions.create(model=MODEL, messages=payload, stream=True)
        chunks = [chunk async for chunk in stream]
        assert "".join(chunk.choices[0].delta.content or "" for chunk in chunks) == "OK"
        assert chunks[-1].choices[0].finish_reason == "stop"
    reader, writer = await asyncio.open_connection("127.0.0.1", wyoming)
    try:
        await wyoming_event.async_write_event(wyoming_info.Describe().event(), writer)
        event = await asyncio.wait_for(wyoming_event.async_read_event(reader), 5)
        assert event is not None
        info = wyoming_info.Info.from_event(event)
        assert info.asr[0].models[0].languages == ["en"]
        assert info.tts[0].voices[0].name == "owned-native-voice"
    finally:
        writer.close()
        await writer.wait_closed()
    async with aiohttp.ClientSession() as session:
        api = python_otbr_api.OTBR(f"http://127.0.0.1:{otbr}", session, 5)
        assert len(await api.get_border_agent_id()) == 16
        assert len(await api.get_extended_address()) == 8
        data = await api.get_active_dataset_tlvs()
        assert data is not None
        parsed = tlv_parser.parse_tlv(data.hex())
        assert parsed[tlv_parser.MeshcopTLVType.CHANNEL].channel == 15
        assert await api.get_api_version() == "1.0.0"
        assert await api.get_coprocessor_version() == "OPENTHREAD/owned-native-synthetic"


def socket_binding_control() -> None:
    import socket

    # A UDP connect selects our own routed IPv4 without sending any packet.
    # macOS does not necessarily route the unassigned127.0.0.2 alias locally.
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as route:
        route.connect(("192.0.2.1", 9))
        own_address = route.getsockname()[0]
    assert not own_address.startswith("127.")

    def reachable(bind: str) -> bool:
        with socket.socket() as server:
            server.bind((bind, 0))
            server.listen(1)
            try:
                with socket.create_connection((own_address, server.getsockname()[1]), timeout=0.2):
                    accepted, _ = server.accept()
                    accepted.close()
                    return True
            except OSError:
                return False

    assert not reachable("127.0.0.1")
    assert reachable("0.0.0.0")


def main() -> None:
    socket_binding_control()
    versions = {name: importlib.metadata.version(name) for name in ("openai", "wyoming", "python-otbr-api")}
    assert versions == {"openai": "3.10.0", "wyoming": "1.10.2", "python-otbr-api": "3.0.0"}
    with ModelServer(0) as model, WyomingServer(0) as wyoming, OtbrServer(0) as otbr:
        servers = (model, wyoming, otbr)
        threads = [threading.Thread(target=server.serve_forever, daemon=True) for server in servers]
        for thread in threads:
            thread.start()
        try:
            asyncio.run(control(model.server_port, wyoming.server_address[1], otbr.server_port))
            assert otbr.writes == 0
            assert wyoming.unexpected_count == 0
            print(
                json.dumps(
                    {
                        "scope": "actual upstream clients / synthetic loopback only / no HA qualification",
                        "versions": versions,
                        "openai": dict(model.calls),
                        "wyoming_describe": wyoming.describe_count,
                        "otbr_reads": otbr.reads,
                        "otbr_writes": otbr.writes,
                        "success": True,
                    }
                )
            )
        finally:
            for server in servers:
                server.shutdown()
            for thread in threads:
                thread.join(timeout=5)
                assert not thread.is_alive()


if __name__ == "__main__":
    main()
