"""Host-local original Matter/OTBR/Wyoming selection and protected config flows.

Only fixed progress/count/status fields leave this process. Configuration entry
bodies, API responses and credentials are never printed or written to a result
file. This component does not handle the separate active conversation canaries.
"""
import base64
import gzip
import http.cookiejar
import json
import netrc
import os
import socket
import signal
import ssl
import sys
import time
import urllib.error
import urllib.request
import urllib.parse


class DeadlineExceeded(Exception):
    pass


def deadline_expired(signum, frame):
    raise DeadlineExceeded()


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    """Original URI default safe redirects: GET/HEAD only, never a flow POST."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if req.get_method() not in ('GET', 'HEAD'):
            raise urllib.error.HTTPError(req.full_url, code, msg, headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def request_transport(url, headers, context):
    # Original URI auth precedence: URL credentials configure challenge handlers;
    # otherwise a matching default NETRC entry overrides the supplied header.
    # Only that original selected file is read; no credential value is exported.
    parsed = urllib.parse.urlparse(url)
    handlers = [SafeRedirect(), urllib.request.HTTPSHandler(context=context),
                urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar())]
    username = ''
    password = ''
    netloc = parsed.netloc
    if '@' in parsed.netloc:
        credentials, netloc = parsed.netloc.split('@', 1)
        username, _, password = credentials.partition(':')
        username, password = urllib.parse.unquote(username), urllib.parse.unquote(password)
        url = urllib.parse.urlunparse(parsed._replace(netloc=netloc))
    if username:
        manager = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        manager.add_password(None, netloc, username, password)
        handlers.extend([urllib.request.HTTPBasicAuthHandler(manager),
                         urllib.request.HTTPDigestAuthHandler(manager)])
    else:
        try:
            login = netrc.netrc(os.environ.get('NETRC')).authenticators(parsed.hostname)
        except OSError:
            login = None
        if login:
            username, _, password = login
            if username and password:
                headers['Authorization'] = 'Basic ' + base64.b64encode((username+':'+password).encode()).decode()
    return url, urllib.request.build_opener(*handlers)


def needs_config(payload):
    path = payload['config_path'].rstrip('/') + '/.storage/core.config_entries'
    try:
        os.lstat(path)
    except FileNotFoundError:
        entries = []
    else:
        with open(path, encoding='utf-8') as source:
            document = json.load(source)
        data = document.get('data') or {}
        entries = data.get('entries') or [] if isinstance(data, dict) else []
    domain = payload['domain']
    matches = [entry for entry in entries if isinstance(entry, dict) and entry.get('domain') == domain]
    if domain in ('matter', 'otbr'):
        values = [entry['data']['url'] for entry in matches
                  if isinstance(entry.get('data'), dict) and 'url' in entry['data']]
        current = (values[0] if values else '') or ''
        return current != payload['desired']['url']
    if domain != 'wyoming':
        raise ValueError('unsupported domain')
    matches = [entry for entry in matches if isinstance(entry.get('data'), dict)
               and 'host' in entry['data'] and 'port' in entry['data']
               and entry['data']['host'] == payload['desired']['host']
               and entry['data']['port'] == payload['desired']['port']]
    current = (matches[0].get('entry_id', '') if matches else '') or ''
    return len(current) == 0


def new_report():
    return dict(success=False, phase='input', needed=False, ready=False,
                http_requests=0, mutation_attempts=0, changed=False, error='')


def run(payload, report=None):
    # main owns this same progress object across every error/cleanup boundary.
    # A late timer must never replace completed attempts with a fresh zero report.
    if report is None:
        report = new_report()
    report.update(phase='inspect', ready=bool(payload.get('ready', False)))
    previous_handler = None
    previous_timer = None
    try:
        deadline = float(payload.get('deadline_seconds', 60))
        if not 0 < deadline < float('inf'):
            raise ValueError('invalid deadline')
        previous_handler = signal.signal(signal.SIGALRM, deadline_expired)
        previous_timer = signal.setitimer(signal.ITIMER_REAL, deadline)
        if payload['action'] not in ('inspect', 'apply', 'readiness'):
            raise ValueError('unsupported action')
        report['needed'] = False if payload['action'] == 'readiness' else needs_config(payload)
        if payload['action'] == 'inspect' or (payload['action'] == 'apply' and not report['needed']):
            report['phase'] = 'complete'
            report['success'] = True
            return report
        api = payload['api']
        report['ready'] = bool(payload.get('ready', False))
        context = ssl.create_default_context() if api['validate_certs'] else ssl._create_unverified_context()
        forwarded = api['forwarded_for'] or payload.get('default_ipv4', '127.0.0.1')
        headers = {'Authorization': 'Bearer ' + api['token'], 'X-Forwarded-For': forwarded,
                   'X-Forwarded-Proto': api['forwarded_proto']}

        def request(path, data=None):
            body = None if data is None else json.dumps(data).encode('utf-8')
            request_headers = dict(headers)
            if body is not None:
                request_headers['Content-Type'] = 'application/json'
            request_headers['User-Agent'] = 'ansible-httpget'
            url, opener = request_transport(api['url'] + path, request_headers, context)
            req = urllib.request.Request(url, data=body, headers=request_headers,
                                         method='GET' if body is None else 'POST')
            report['http_requests'] += 1
            if body is not None:
                # A failed response can follow a completed remote mutation.
                report['mutation_attempts'] += 1
                report['changed'] = True
            with opener.open(req, timeout=api['timeout']) as response:
                if response.status != 200:
                    raise RuntimeError('unexpected status')
                if body is None:
                    return None
                subtype = response.headers.get_content_subtype().rsplit('+', 1)[-1].lower()
                raw = response.read()
                if response.headers.get('content-encoding', '').lower() == 'gzip':
                    raw = gzip.decompress(raw)
                # URI only sets json for JSON/javascript types and a successful
                # parse. The caller requires a submission or the explicit
                # already_configured result; no arbitrary HTTP200 acceptance.
                if subtype not in ('json', 'javascript'):
                    return {}
                try:
                    value = json.loads(raw.decode(response.headers.get_content_charset() or 'utf-8', 'surrogateescape'))
                except (ValueError, UnicodeError):
                    return {}
                return value if isinstance(value, dict) else {}

        if not report['ready']:
            report['phase'] = 'readiness'
            # Original task executor includes the initial call plus retries.
            for attempt in range(max(0, api['retries']) + 1):
                try:
                    request('/api/')
                    report['ready'] = True
                    break
                except DeadlineExceeded:
                    raise
                except Exception:
                    # Original until/retries repeats every failed URI attempt,
                    # including malformed HTTP status and auth/transport errors.
                    if attempt >= max(0, api['retries']):
                        raise
                    time.sleep(api['retry_delay'])
        if payload['action'] == 'readiness':
            report['phase'] = 'complete'
            report['success'] = True
            return report
        if payload['domain'] == 'matter' and payload.get('manage_matter_server', False):
            report['phase'] = 'matter-port'
            deadline = time.monotonic() + api['timeout']
            while True:
                try:
                    with socket.create_connection(('127.0.0.1', payload['matter_port']),
                                                  timeout=max(0.001, min(5, deadline-time.monotonic()))):
                        break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(min(1, max(0, deadline-time.monotonic())))
        report['phase'] = 'start-flow'
        flow = request('/api/config/config_entries/flow', {'handler': payload['domain']})
        if flow.get('type') == 'abort' and flow.get('reason', '') != 'already_configured':
            raise RuntimeError('flow aborted')
        if 'flow_id' in flow:
            report['phase'] = 'submit-flow'
            result = request('/api/config/config_entries/flow/' + str(flow['flow_id']), payload['desired'])
            if result.get('type', '') != 'create_entry' and not (
                    result.get('type', '') == 'abort' and result.get('reason', '') == 'already_configured'):
                raise RuntimeError('flow incomplete')
        elif not (flow.get('type') == 'abort' and flow.get('reason') == 'already_configured'):
            raise RuntimeError('flow did not provide a submission')
        report['phase'] = 'complete'
        report['success'] = True
    except Exception as error:
        # Never serialize exception messages, URLs, flow IDs, response bodies or
        # registry values. The fixed phase and class preserve failure attribution.
        report['error'] = type(error).__name__
    finally:
        if previous_timer is not None:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.setitimer(signal.ITIMER_REAL, *previous_timer)
        if previous_handler is not None:
            signal.signal(signal.SIGALRM, previous_handler)
    return report


def main():
    result = new_report()
    try:
        payload = json.load(sys.stdin)
        try:
            run(payload, result)
        finally:
            # Also runs if run's cleanup itself is interrupted. The helper is
            # its own process; stop its deadline before constructing output.
            signal.setitimer(signal.ITIMER_REAL, 0)
    except Exception as error:
        result['success'] = False
        result['error'] = type(error).__name__
        # A one-shot alarm cannot erase the shared phase/attempt progress.
        signal.setitimer(signal.ITIMER_REAL, 0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result['success'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
