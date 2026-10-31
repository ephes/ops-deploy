FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv udev dbus python3 python3-apt curl git ca-certificates fish \
    sudo util-linux iproute2 openssh-server openssh-client sshpass acl file libnl-route-3-200 \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && truncate -s 0 /etc/machine-id && rm -f /var/lib/dbus/machine-id
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
