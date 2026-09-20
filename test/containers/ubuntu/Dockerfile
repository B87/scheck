# Ubuntu 24.04 audit target: sshd, sudo (no NOPASSWD until a test installs the
# scheck fragment), one unprivileged user `ops`.
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server sudo iproute2 ufw cron \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
ARG PUBKEY
RUN useradd -m -s /bin/bash ops \
 && install -d -m 700 -o ops -g ops /home/ops/.ssh \
 && printf '%s\n' "$PUBKEY" > /home/ops/.ssh/authorized_keys \
 && chown ops:ops /home/ops/.ssh/authorized_keys && chmod 600 /home/ops/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
