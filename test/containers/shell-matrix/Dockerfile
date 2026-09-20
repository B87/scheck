# Five login shells behind one sshd, for the canary matrix (SPEC.md §11).
FROM ubuntu:24.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssh-server zsh fish \
 && rm -rf /var/lib/apt/lists/* \
 && mkdir -p /run/sshd \
 && ssh-keygen -A \
 && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
ARG PUBKEY
RUN set -e; for u in u_sh:/bin/sh u_bash:/bin/bash u_zsh:/bin/zsh u_fish:/usr/bin/fish u_rbash:/bin/rbash; do \
      name=${u%%:*}; shell=${u##*:}; \
      useradd -m -s "$shell" "$name"; \
      install -d -m 700 -o "$name" -g "$name" /home/$name/.ssh; \
      printf '%s\n' "$PUBKEY" > /home/$name/.ssh/authorized_keys; \
      chown "$name:$name" /home/$name/.ssh/authorized_keys; chmod 600 /home/$name/.ssh/authorized_keys; \
    done
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
