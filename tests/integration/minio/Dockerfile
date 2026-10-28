FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends systemd systemd-sysv dbus python3 curl git ca-certificates fish apache2-utils sudo util-linux iproute2 && apt-get clean
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
