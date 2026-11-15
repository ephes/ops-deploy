# Gunicorn configuration for Paperless-ngx
import os

# Server socket
bind = "0.0.0.0:10030"
backlog = 2048

# Worker processes
workers = 2
worker_class = 'gthread'
threads = 2
worker_connections = 1000
max_requests = 1000
max_requests_jitter = 50
timeout = 120
graceful_timeout = 30
keepalive = 5

# Restart workers after this many seconds
max_worker_age = 3600

# Working directory
chdir = "/home/paperless/site/paperless-ngx/src"

# Process naming
proc_name = 'paperless-gunicorn'

# Server mechanics
daemon = False
pidfile = "/home/paperless/site/gunicorn.pid"
user = "paperless"
group = "paperless"
tmp_upload_dir = "/tmp"

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" %(D)s'

# StatsD (disabled by default)
statsd_host = None
statsd_prefix = 'paperless'

# Server hooks
def on_starting(server):
    server.log.info("Starting Paperless-ngx Gunicorn server")


def on_reload(server):
    server.log.info("Reloading Paperless-ngx Gunicorn server")


def when_ready(server):
    server.log.info("Paperless-ngx Gunicorn server is ready. Listening on: %s", server.address)


def worker_abort(worker):
    worker.log.info("Worker received SIGABRT signal")


def pre_request(worker, req):
    worker.log.debug("%s %s", req.method, req.path)
