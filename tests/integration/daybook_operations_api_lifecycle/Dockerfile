# Synthetic macmini-like host for tests/test_daybook_operations_api_lifecycle_docker.py:
# Debian 12 with systemd as PID 1 and python3. The test installs the service
# account, the two units, the route and a synthetic stand-in for Daybook's
# private services/operations_api/lifecycle.py itself.
FROM debian:bookworm-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends systemd systemd-sysv dbus python3 \
 && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/bin/sh", "-c", "mount -o remount,rw /sys/fs/cgroup && exec /sbin/init"]
