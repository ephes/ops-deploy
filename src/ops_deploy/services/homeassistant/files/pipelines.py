"""Prepared original list/preferred and standalone voice get/update protocols.

Desired definitions are resolved by the caller. Bodies/IDs remain in host RAM;
fixed counts retain partial effects. No result file or deployment API here.
"""
import asyncio
import json
import sys
from urllib.parse import urlparse, urlunparse

import aiohttp


def normalize_pipeline(pipeline):
    return {
        'id': pipeline.get('id', ''), 'name': pipeline['name'], 'language': pipeline['language'],
        'conversation_engine': pipeline['conversation_engine'],
        'conversation_language': pipeline['conversation_language'],
        'stt_engine': pipeline.get('stt_engine') or '', 'stt_language': pipeline.get('stt_language') or '',
        'tts_engine': pipeline.get('tts_engine') or '', 'tts_language': pipeline.get('tts_language') or '',
        'tts_voice': pipeline.get('tts_voice') or '', 'wake_word_entity': pipeline.get('wake_word_entity'),
        'wake_word_id': pipeline.get('wake_word_id'), 'prefer_local_intents': pipeline.get('prefer_local_intents', False),
    }


def websocket_url(api_url):
    parsed = urlparse(api_url)
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('unsupported scheme')
    path = (parsed.path.rstrip('/') if parsed.path else '') + '/api/websocket'
    return urlunparse(('wss' if parsed.scheme == 'https' else 'ws', parsed.netloc, path, '', '', ''))


def desired_fields(desired):
    return {
        'name': desired['name'], 'language': desired['language'],
        'conversation_engine': desired.get('conversation_engine', 'conversation.home_assistant'),
        'conversation_language': desired.get('conversation_language', desired['language']),
        'stt_engine': desired['stt_engine'], 'stt_language': desired['stt_language'],
        'tts_engine': desired['tts_engine'], 'tts_language': desired['tts_language'],
        'tts_voice': desired.get('tts_voice') or None,
        'wake_word_entity': desired.get('wake_word_entity'), 'wake_word_id': desired.get('wake_word_id'),
        'prefer_local_intents': desired.get('prefer_local_intents', False),
    }


def find_existing(existing, desired):
    if desired.get('id'):
        for item in existing:
            if item.get('id') == desired['id']:
                return item
    return next((item for item in existing if item.get('name') == desired['name']), None)


def update_for(existing, desired):
    body = desired_fields(desired)
    comparison = {**normalize_pipeline(existing), **{
        field: body[field] for field in (
            'name', 'language', 'conversation_engine', 'conversation_language',
            'stt_engine', 'stt_language', 'tts_engine', 'tts_language')},
        'tts_voice': desired.get('tts_voice') or ''}
    for field in ('wake_word_entity', 'wake_word_id', 'prefer_local_intents'):
        if field in desired:
            comparison[field] = desired[field]
    if comparison == normalize_pipeline(existing):
        return None
    for field in ('wake_word_entity', 'wake_word_id'):
        body[field] = desired.get(field, existing.get(field))
    body['prefer_local_intents'] = desired.get('prefer_local_intents', existing.get('prefer_local_intents', False))
    if 'acknowledge_media_id' in existing:
        body['acknowledge_media_id'] = existing['acknowledge_media_id']
    return {'type': 'assist_pipeline/pipeline/update', 'pipeline_id': existing['id'], **body}


async def reconcile(payload, command, report):
    report['phase'] = 'list'
    listed = await command({'type': 'assist_pipeline/pipeline/list'})
    if not listed.get('success'):
        raise RuntimeError('list failed')
    existing = listed['result']['pipelines']
    preferred = listed['result'].get('preferred_pipeline', '')
    resolved = {}
    for desired in payload['desired']:
        report['phase'] = 'compare'
        current = find_existing(existing, desired)
        body = ({'type': 'assist_pipeline/pipeline/create', **desired_fields(desired)}
                if current is None else update_for(current, desired))
        if body is None:
            resolved[desired['name']] = current['id']
            continue
        report['pending'] += 1
        if payload['action'] == 'inspect':
            # Do not simulate unknown remote create IDs or claim a full count.
            return
        report['phase'] = 'create' if current is None else 'update'
        result = await command(body, mutation=True)
        if not result.get('success'):
            raise RuntimeError('mutation failed')
        report['applied'] += 1
        if current is None:
            current = result['result']
            existing.append(current)
        # Original appends creates but does not replace updated snapshot entries.
        resolved[desired['name']] = current['id']
    selected = next((item for item in payload['desired'] if item.get('preferred')), None)
    if selected is not None and preferred != resolved[selected['name']]:
        report['pending'] += 1
        if payload['action'] == 'inspect':
            return
        report['phase'] = 'preferred'
        result = await command({'type': 'assist_pipeline/pipeline/set_preferred',
                                'pipeline_id': resolved[selected['name']]}, mutation=True)
        if not result.get('success'):
            raise RuntimeError('preferred failed')
        report['applied'] += 1



async def reconcile_voice(payload, command, report):
    """Original standalone enabled STT/TTS update; no create/preferred path."""
    report['phase'] = 'get'
    response = await command({'type': 'assist_pipeline/pipeline/get', 'pipeline_id': payload['pipeline_id']})
    if not response.get('success'):
        raise RuntimeError('pipeline get failed')
    current = response['result']
    desired = payload['voice']
    selected = {}
    changed = False
    for kind in ('stt', 'tts'):
        for field in (kind + '_engine', kind + '_language'):
            old = current.get(field) or ''
            selected[field] = desired[field] if payload['manage_' + kind] else old
            changed = changed or selected[field] != old
    selected['tts_voice'] = ((desired.get('tts_voice') or None) if payload['manage_tts']
                             else (current.get('tts_voice') or None))
    changed = changed or (selected['tts_voice'] or '') != (current.get('tts_voice') or '')
    report['phase'] = 'compare'
    if not changed:
        return
    report['pending'] += 1
    if payload['action'] == 'inspect':
        return
    body = {
        'type': 'assist_pipeline/pipeline/update', 'pipeline_id': current['id'],
        **{field: current[field] for field in ('conversation_engine', 'conversation_language', 'language', 'name')},
        **{field: val or None for field, val in selected.items()},
        'wake_word_entity': current.get('wake_word_entity'), 'wake_word_id': current.get('wake_word_id'),
        'prefer_local_intents': current.get('prefer_local_intents', False),
    }
    if 'acknowledge_media_id' in current:
        body['acknowledge_media_id'] = current['acknowledge_media_id']
    report['phase'] = 'update'
    response = await command(body, mutation=True)
    if not response.get('success'):
        raise RuntimeError('voice update failed')
    report['applied'] += 1

def new_report():
    return dict(success=False, phase='input', pending=0, mutation_attempts=0,
                applied=0, changed=False, error='')


async def exchange(payload, report):
    if payload['action'] not in {'inspect', 'apply'}:
        raise ValueError('unsupported action')
    report['phase'] = 'connect'
    async with aiohttp.ClientSession() as session:
        async with session.ws_connect(websocket_url(payload['url'])) as ws:
            async def receive():
                message = await ws.receive()
                if message.type != aiohttp.WSMsgType.TEXT:
                    raise RuntimeError('unexpected message')
                body = json.loads(message.data)
                if not isinstance(body, dict):
                    raise ValueError('invalid response')
                return body

            counter = 0

            async def command(body, *, mutation=False):
                nonlocal counter
                counter += 1
                body['id'] = counter
                if mutation:
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
            mode = payload.get('mode', 'list')
            if mode == 'voice':
                await reconcile_voice(payload, command, report)
            elif mode == 'list':
                await reconcile(payload, command, report)
            else:
                raise ValueError('unsupported mode')
            report['phase'] = 'complete'


async def run(payload, report):
    try:
        timeout = float(payload['timeout'])
        if not 0 < timeout < float('inf'):
            raise ValueError('invalid deadline')
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
