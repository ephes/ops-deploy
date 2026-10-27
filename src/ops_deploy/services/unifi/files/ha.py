# Appended to preflight.py's definitions: reuse the private, authenticated client.
import base64


def ha_pending(state, payload):
    if not payload['create_homeassistant_user']:
        return False
    ha = state['ha']
    return (
        not isinstance(ha, dict)
        or not matches_password(payload['homeassistant_password'], ha.get('x_shadow', ''))
        or state.get('ha_site_access') is not True
        or not state['privileges']
        or any(p.get('role') != 'readonly' or p.get('permissions') != [] for p in state['privileges'])
    )


def password_hash(password, existing):
    if matches_password(password, existing):
        return existing
    salt = base64.b64encode(os.urandom(12)).decode().replace('+', '.')
    library = ctypes.CDLL('libcrypt.so.1')
    library.crypt.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
    library.crypt.restype = ctypes.c_char_p
    answer = library.crypt(password.encode(), ('$6$' + salt + '$').encode())
    require(answer is not None, 'ha_hash_failed')
    hashed = answer.decode()
    require(matches_password(password, hashed), 'ha_hash_failed')
    return hashed


def ha_javascript(payload, hashed):
    # IDs are read and updated in place. Both native string IDs and the legacy
    # role's ObjectIds are reconciled, avoiding duplicate privilege records.
    return javascript(payload).split('print("OPS_UNIFI="')[0] + (
        'if (!site) quit(25);\n'
        f'const hash={json.dumps(hashed)};\n'
        f'const username={json.dumps(payload["homeassistant_username"])};\n'
        'if (!ha) u.admin.insertOne({name:username,email:username+"@local",last_site_name:"default",'
        'time_created:NumberLong(Date.now().toString()),x_shadow:hash});\n'
        'else if(ha.x_shadow!==hash) u.admin.updateOne({_id:ha._id},{$set:{x_shadow:hash,'
        'email:ha.email || username+"@local",last_site_name:ha.last_site_name || "default"}});\n'
        'const user=u.admin.findOne({name:username});\n'
        'const query={admin_id:{$in:[user._id,user._id.toString()]},'
        'site_id:{$in:[site._id,site._id.toString()]}};\n'
        'const canonical={admin_id:user._id.toString(),site_id:site._id.toString()};\n'
        'const existing=u.privilege.findOne(query);\n'
        'if(!existing) u.privilege.insertOne({...canonical,role:"readonly",permissions:[]});\n'
        'else {u.privilege.updateMany(query,{$set:{role:"readonly",permissions:[]}});\n'
        # A working native record wins: retain harmless legacy duplicates and
        # their IDs. Repair one legacy record in place only if no native one exists.
        'if(u.privilege.countDocuments(canonical)===0) '
        'u.privilege.updateOne({_id:existing._id},{$set:canonical});}\n'
        'print("OPS_UNIFI="+JSON.stringify({changed:true}));\n'
    )


def ha_main(mode, payload):
    global javascript
    if not payload['create_homeassistant_user']:
        print('current')
        return
    state = mongodb_state(payload)
    require(state['opts'].get('security', {}).get('authorization') == 'enabled', 'mongodb_auth_config_drift')
    if not state['site']:
        print('no-site')
        return
    dirty = ha_pending(state, payload)
    if mode == 'check':
        print('pending' if dirty else 'current')
    elif mode == 'apply':
        if dirty:
            hashed = password_hash(payload['homeassistant_password'], (state['ha'] or {}).get('x_shadow', ''))
            script = ha_javascript(payload, hashed)
            original = javascript
            try:
                javascript = lambda payload: script
                mongodb_state(payload)
            finally:
                javascript = original
        require(not ha_pending(mongodb_state(payload), payload), 'ha_reconciliation_failed')
    else:
        raise ValueError('invalid mode')


try:
    ha_main(sys.argv[1], json.load(sys.stdin))
except Exception:
    print('UniFi HA reconciliation refused', file=sys.stderr)
    sys.exit(1)
