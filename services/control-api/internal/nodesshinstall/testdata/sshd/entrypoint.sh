#!/bin/bash
set -e
echo "root:${ROOT_PASSWORD}" | chpasswd
echo "deploy:${DEPLOY_PASSWORD}" | chpasswd
if [ -n "${AUTHORIZED_KEY:-}" ]; then
  mkdir -p /root/.ssh && echo "$AUTHORIZED_KEY" > /root/.ssh/authorized_keys && chmod 700 /root/.ssh && chmod 600 /root/.ssh/authorized_keys
fi
exec /usr/sbin/sshd -D -e
