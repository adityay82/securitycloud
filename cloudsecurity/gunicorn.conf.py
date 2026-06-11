"""Gunicorn production configuration for CloudSec."""

# Server socket
bind = "unix:/run/cloudsec/cloudsec.sock"
backlog = 2048

# Worker processes
workers = 3                    # 2 * CPU cores + 1 is rule of thumb
worker_class = "sync"
worker_connections = 1000
timeout = 30
keepalive = 2

# Process naming
proc_name = "cloudsec"

# Logging
accesslog = "-"
errorlog = "-"
loglevel = "info"
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# Security
limit_request_line = 4094
limit_request_fields = 100
limit_request_field_size = 8190
