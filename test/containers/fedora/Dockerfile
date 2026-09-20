# Fedora audit target: sshd, sudo, dnf, one unprivileged user `ops`.
FROM fedora:40
RUN dnf -y install openssh-server sudo iproute passwd shadow-utils util-linux \
 && dnf clean all \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
ARG PUBKEY
RUN useradd -m -s /bin/bash ops \
 && install -d -m 700 -o ops -g ops /home/ops/.ssh \
 && printf '%s\n' "$PUBKEY" > /home/ops/.ssh/authorized_keys \
 && chown ops:ops /home/ops/.ssh/authorized_keys && chmod 600 /home/ops/.ssh/authorized_keys
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
