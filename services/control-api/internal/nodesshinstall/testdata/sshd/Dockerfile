# Test-only SSH target for nodesshinstall (never a real server): sshd with a
# root password login and a sudo user, and a stand-in curl that serves a
# fake install-node.sh which records its arguments instead of installing.
FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends openssh-server sudo && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd && ssh-keygen -A \
 && useradd -m -s /bin/bash deploy && echo 'deploy ALL=(ALL) ALL' > /etc/sudoers.d/deploy \
 && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/; s/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY curl /usr/local/bin/curl
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /usr/local/bin/curl /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
