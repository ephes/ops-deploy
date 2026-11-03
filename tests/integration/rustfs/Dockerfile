FROM ghcr.io/astral-sh/uv:0.13.5 AS uv
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus python3 curl ca-certificates iproute2 util-linux sudo && apt-get clean
COPY --from=uv /uv /usr/local/bin/uv
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
