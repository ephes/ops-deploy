# Synthetic macmini-like host for tests/test_vibe_coding_docker.py: Ubuntu
# 24.04 with systemd as PID 1, a running sshd, Ansible (for the role-first
# parity run) and shell_basics' packages preinstalled. No vibe user, no
# toolchain: the deploys install those.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      systemd systemd-sysv dbus openssh-server openssh-client sudo acl python3 git curl ca-certificates gnupg \
      ansible-core ansible \
      fish bat fzf ripgrep fd-find eza tmux tree tig lsof file strace psmisc vim btop bmon sysstat iotop \
      tealdeer just gh zoxide xz-utils update-notifier-common \
 && systemctl enable ssh.service \
 && mkdir -p /root/.ssh /mnt/cryptdata && chmod 0700 /root/.ssh \
 && rm -f /etc/apt/apt.conf.d/docker-clean
STOPSIGNAL SIGRTMIN+3
CMD ["/bin/sh", "-c", "mount -o remount,rw /sys/fs/cgroup && exec /sbin/init"]
