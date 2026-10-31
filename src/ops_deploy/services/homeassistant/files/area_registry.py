"""Owned area fields through the original HA WebSocket protocol.

Bodies/identifiers remain in target RAM; only fixed phase/count reports leave it.
The caller owns original HTTP readiness and execution ordering. No result file.
"""
import asyncio
import json
import sys
from urllib.parse import urlparse, urlunparse

import aiohttp


def websocket_url(api_url):
    parsed = urlparse(api_url)
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('unsupported scheme')
    path = (parsed.path.rstrip('/') if parsed.path else '') + '/api/websocket'
    return urlunparse(('wss' if parsed.scheme == 'https' else 'ws', parsed.netloc, path, '', '', ''))


def normalize_aliases(raw_aliases):
    if not isinstance(raw_aliases, list):
        return []
    aliases, seen = [], set()
    for item in raw_aliases:
        if not isinstance(item, str):
            continue
        alias = item.strip()
        if not alias or alias.casefold() in seen:
            continue
        seen.add(alias.casefold())
        aliases.append(alias)
    return aliases


def selected_updates(areas, desired_updates):
    # Preserve last duplicate ID/name and ID-first/no-name-fallback semantics.
    by_id = {item['area_id']: item for item in areas if 'area_id' in item}
    by_name = {item['name']: item for item in areas if 'name' in item}
    for desired in desired_updates:
        area_id = str(desired.get('area_id', '')).strip()
        name = str(desired.get('name', '')).strip()
        area = by_id.get(area_id) if area_id else by_name.get(name) if name else None
        if area is None:
            raise ValueError('unresolved area')
        update = {'type': 'config/area_registry/update', 'area_id': area['area_id']}
        if 'aliases' in desired:
            value = normalize_aliases(desired.get('aliases'))
            if value != normalize_aliases(area.get('aliases')):
                update['aliases'] = value
        for field in ('temperature_entity_id', 'humidity_entity_id'):
            if field in desired:
                value = str(desired.get(field, '') or '').strip() or None
                if value != (area.get(field) or None):
                    update[field] = value
        if len(update) > 2:
            yield update
        # Original does not rewrite this snapshot after each duplicate request.


def new_report():
    return dict(success=False, phase='input', pending=0, mutation_attempts=0,
                applied=0, changed=False, error='')


async def exchange(payload, report):
    if payload['action'] not in {'inspect', 'apply'}:
        raise ValueError('unsupported action')
    report['phase'] = 'connect'
    # As in the original, WebSocket TLS uses aiohttp defaults independently of
    # the HTTP readiness validate_certs flag. No URL/default-NETRC auth rewrite.
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(websocket_url(payload['url'])) as ws:
            async def receive():
                message = await ws.receive()
                if message.type != aiohttp.WSMsgType.TEXT:
                    raise RuntimeError('unexpected message')
                value = json.loads(message.data)
                if not isinstance(value, dict):
                    raise ValueError('invalid response')
                return value

            counter = 0

            async def command(body, *, mutation=False):
                nonlocal counter
                counter += 1
                body['id'] = counter
                if mutation:
                    # Even a send failure can follow partial transport delivery.
                    report['mutation_attempts'] += 1
                    report['changed'] = True
                await ws.send_json(body)
                while True:
                    response = await receive()
                    if response.get('id') == counter:
                        return response

            report['phase'] = 'authenticate'
            hello = await receive()
            if hello.get('type') == 'auth_required':
                await ws.send_json({'type': 'auth', 'access_token': payload['token']})
                hello = await receive()
            if hello.get('type') != 'auth_ok':
                raise RuntimeError('authentication failed')
            report['phase'] = 'list'
            response = await command({'type': 'config/area_registry/list'})
            if not response.get('success'):
                raise RuntimeError('list failed')
            report['phase'] = 'compare'
            for update in selected_updates(response.get('result', []), payload['updates']):
                report['pending'] += 1
                if payload['action'] == 'apply':
                    report['phase'] = 'update'
                    result = await command(update, mutation=True)
                    if not result.get('success'):
                        raise RuntimeError('update failed')
                    report['applied'] += 1
                    report['phase'] = 'compare'
            report['phase'] = 'complete'


async def run(payload, report):
    try:
        timeout = float(payload['timeout'])
        if not 0 < timeout < float('inf'):
            raise ValueError('invalid deadline')
        # A whole exchange deadline also bounds unmatched IDs and quiet peers.
        async with asyncio.timeout(timeout):
            await exchange(payload, report)
        report['success'] = True
    except Exception as error:
        report['success'] = False
        report['error'] = type(error).__name__
    return report


def main():
    report = new_report()
    try:
        asyncio.run(run(json.load(sys.stdin), report))
    except Exception as error:
        report['success'] = False
        report['error'] = type(error).__name__
    print(json.dumps(report, sort_keys=True))
    return 0 if report['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
