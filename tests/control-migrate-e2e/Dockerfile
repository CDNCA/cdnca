# Two of these run as the old and the new control host. Real systemd,
# PostgreSQL, NATS JetStream and OpenSSH; the native control services are
# stand-ins (see fixture.sh) because the signed native package is amd64-only
# and licence-activated.
FROM nats:2.10-alpine AS nats
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends systemd systemd-sysv openssh-server openssh-client \
      postgresql postgresql-client jq python3 curl ca-certificates iproute2 procps tar >/dev/null && \
    rm -rf /var/lib/apt/lists/* && \
    systemctl disable postgresql >/dev/null 2>&1 || true; \
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config && \
    echo 'root:migrate-e2e-root' | chpasswd && systemctl enable ssh >/dev/null 2>&1 || true
# Kept outside the archived runtime paths; fixture.sh installs it on the old host only.
COPY --from=nats /usr/local/bin/nats-server /opt/fixture/nats-server
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
