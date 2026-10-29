FROM ubuntu:24.04 AS guest
ARG OWNED_ID
LABEL io.ops.minio.fixture=$OWNED_ID
ENV DEBIAN_FRONTEND=noninteractive
# Docker's per-build resolver file is an ephemeral container mount.
# Use only public DNS for anonymous bootstrap; never modify host resolver settings.
RUN printf 'nameserver 1.1.1.1\noptions timeout:2 attempts:2\n' > /etc/resolv.conf && \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d && chmod 0755 /usr/sbin/policy-rc.d && \
    apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends \
    systemd systemd-sysv dbus linux-image-virtual initramfs-tools python3 python3-venv python3-apt \
    curl git ca-certificates fish apache2-utils sudo util-linux iproute2 && \
    rm /usr/sbin/policy-rc.d && apt-get clean
ARG IMPLEMENTATION_SHA
ARG MINIO_COMPONENT=normal
RUN printf 'nameserver 1.1.1.1\noptions timeout:2 attempts:2\n' > /etc/resolv.conf && \
    test "${#IMPLEMENTATION_SHA}" = 40 && ! printf '%s' "$IMPLEMENTATION_SHA" | grep -q '[^0-9a-f]' && \
    git -c credential.helper= clone https://github.com/ephes/ops-deploy.git /opt/controller && \
    git -C /opt/controller checkout --detach "$IMPLEMENTATION_SHA" && \
    bash /opt/controller/tests/integration/minio/kvm/prepare-rootfs.sh "$IMPLEMENTATION_SHA" "$OWNED_ID" "$MINIO_COMPONENT"

FROM ubuntu:24.04 AS tooling
ARG OWNED_ID
LABEL io.ops.minio.fixture=$OWNED_ID
ENV DEBIAN_FRONTEND=noninteractive
RUN printf 'nameserver 1.1.1.1\noptions timeout:2 attempts:2\n' > /etc/resolv.conf && \
    apt-get -o APT::Update::Error-Mode=any update && apt-get install -y --no-install-recommends \
    qemu-system-x86 e2fsprogs genisoimage coreutils python3 ca-certificates && apt-get clean
COPY --from=guest / /guest-root/
RUN mkdir -p /work /evidence && \
    printf 'ops-owned-minio\n' > /guest-root/etc/hostname && \
    rm -f /guest-root/.dockerenv /guest-root/run/.containerenv && \
    cp -L /guest-root/boot/vmlinuz-* /work/vmlinuz && \
    cp -L /guest-root/boot/initrd.img-* /work/initrd && \
    truncate -s 8G /work/rootfs.raw && \
    mkfs.ext4 -q -F -d /guest-root /work/rootfs.raw && \
    cp /guest-root/opt/controller/tests/integration/minio/kvm/run-tooling.sh /run-tooling.sh && \
    cp /guest-root/opt/controller/tests/integration/minio/kvm/tooling.py /tooling.py && \
    rm -rf /guest-root
CMD ["bash", "/run-tooling.sh"]
