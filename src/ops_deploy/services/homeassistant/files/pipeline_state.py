"""Original host-local pipeline definition/target preparation.

The caller keeps selected operational values in protected process RAM, never
logs this result or the named registry bodies, and passes it to the service-user
protocol helper. No network, app import, registry write or recursive traversal.
"""
import json
import re
import sys
from pathlib import Path


def original_bool(value):
    # Original Ansible bool conversion, not Python's truthiness of "false".
    # Invalid values historically coerce false (with an Ansible warning).
    if isinstance(value, str):
        value = value.lower()
    return value in (True, 1, 'yes', 'on', '1', 'true')


def read_store(config_path, name):
    path = Path(config_path) / '.storage' / name
    return path.read_bytes() if path.exists() else None


def stored_items(raw, field):
    if raw is None:
        return []
    document = json.loads(raw)
    data = document.get('data') or {}
    return data.get(field) or []


def entry_id(options, raw):
    inherited = options.get('wyoming_entry_id') or ''
    if inherited:
        return inherited
    matches = [item for item in stored_items(raw, 'entries')
               if item.get('domain') == 'wyoming' and isinstance(item.get('data'), dict)
               and 'host' in item['data']
               and 'port' in item.get('data', {}) and item['data']['host'] == options['wyoming_host']
               and item['data']['port'] == int(options['wyoming_port'])]
    return (matches[0].get('entry_id') if matches else '') or ''


def engine(raw, selected, kind):
    matches = [item['entity_id'] for item in stored_items(raw, 'entities')
               if item.get('platform') == 'wyoming' and item.get('config_entry_id') == selected
               and 'entity_id' in item and re.match('^' + kind + r'\.', item['entity_id'])]
    return (matches[0] if matches else '') or ''


def prepare_list(options):
    desired = options['pipelines']
    # Original slurps the entity file whenever it exists, but parses only for
    # requested automatic discovery. Explicit-empty keys do NOT trigger it.
    entities = read_store(options['config_path'], 'core.entity_registry')
    auto_stt = any('stt_engine_id' not in item for item in desired)
    auto_tts = any('tts_engine_id' not in item for item in desired)
    selected = options.get('wyoming_entry_id') or ''
    if (auto_stt or auto_tts) and not selected:
        selected = entry_id(options, read_store(options['config_path'], 'core.config_entries'))
    stt = engine(entities, selected, 'stt') if auto_stt else ''
    tts = engine(entities, selected, 'tts') if auto_tts else ''
    custom = options.get('custom_conversation_entity_id') or ''
    llama = options.get('llama_cpp_entity_id') or ''
    if original_bool(options.get('llama_cpp_enabled')) and not options.get('check_mode', False) and any(item.get('conversation_engine') == 'auto:llama_cpp' for item in desired):
        if not llama:
            raise ValueError('unresolved active built-in conversation canary')
    result = []
    for item in desired:
        conversation = item.get('conversation_engine') or 'conversation.home_assistant'
        if conversation == 'auto:custom_conversation':
            conversation = custom or 'conversation.home_assistant'
        elif conversation == 'auto:llama_cpp':
            conversation = llama or 'conversation.home_assistant'
        prepared = {
            'id': item.get('id') or '', 'name': item['name'], 'language': item['language'],
            'conversation_engine': conversation,
            'conversation_language': item.get('conversation_language') or item['language'],
            'stt_engine': item.get('stt_engine_id') or stt,
            'stt_language': item.get('stt_language') or item['language'],
            'tts_engine': item.get('tts_engine_id') or tts,
            'tts_language': item.get('tts_language') or item['language'],
            'tts_voice': item.get('tts_voice') or '',
            'preferred': original_bool(item.get('preferred', False)),
        }
        for field in ('wake_word_entity', 'wake_word_id', 'prefer_local_intents'):
            if field in item:
                prepared[field] = original_bool(item[field]) if field == 'prefer_local_intents' else item[field]
        if any(prepared[field] == '' for field in ('name', 'language', 'stt_engine', 'tts_engine')):
            raise ValueError('unresolved desired pipeline definitions')
        result.append(prepared)
    return result


def prepare_voice(options):
    config = options['config_path']
    entities = read_store(config, 'core.entity_registry')
    storage = read_store(config, 'assist_pipeline.pipelines')
    manage_stt, manage_tts = original_bool(options['manage_stt']), original_bool(options['manage_tts'])
    stt = (options.get('stt_engine_id') if manage_stt else '') or ''
    tts = (options.get('tts_engine_id') if manage_tts else '') or ''
    selected = options.get('wyoming_entry_id') or ''
    if ((manage_stt and not stt) or (manage_tts and not tts)) and not selected:
        selected = entry_id(options, read_store(config, 'core.config_entries'))
    if manage_stt and not stt and entities is not None:
        stt = engine(entities, selected, 'stt')
    if manage_tts and not tts and entities is not None:
        tts = engine(entities, selected, 'tts')
    data = (json.loads(storage).get('data') or {}) if storage is not None else {}
    target_id = options.get('pipeline_id') or data.get('preferred_item') or ''
    target = next((item for item in data.get('items') or [] if item.get('id') == target_id), {})
    stt_language = options.get('stt_language') or target.get('stt_language') or target.get('language') or ''
    tts_language = options.get('tts_language') or target.get('tts_language') or target.get('language') or ''
    voice = options.get('tts_voice') or target.get('tts_voice') or ''
    if storage is None or not target_id:
        raise ValueError('unresolved pipeline target')
    if manage_stt and (entities is None or not stt or not stt_language):
        raise ValueError('unresolved STT selection')
    if manage_tts and (entities is None or not tts or not tts_language):
        raise ValueError('unresolved TTS selection')
    needed = ((manage_stt and ((target.get('stt_engine') or '') != stt or
                              (target.get('stt_language') or '') != stt_language)) or
              (manage_tts and ((target.get('tts_engine') or '') != tts or
                              (target.get('tts_language') or '') != tts_language or
                              (target.get('tts_voice') or '') != voice)))
    return {'pipeline_id': target_id, 'manage_stt': manage_stt, 'manage_tts': manage_tts,
            'voice': {'stt_engine': stt, 'stt_language': stt_language,
                      'tts_engine': tts, 'tts_language': tts_language, 'tts_voice': voice}, 'needed': needed}


def main():
    # stdout contains selected operational values: the controller must suppress
    # it and retain it only in protected process RAM. No registry body is returned.
    try:
        payload = json.load(sys.stdin)
        if payload['mode'] == 'list':
            result = prepare_list(payload['options'])
        elif payload['mode'] == 'voice':
            result = prepare_voice(payload['options'])
        else:
            raise ValueError('unsupported mode')
        print(json.dumps({'success': True, 'result': result}))
        return 0
    except Exception as error:
        print(json.dumps({'success': False, 'error': type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
