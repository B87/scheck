# Host notes

All findings on this host are severity: info. In particular, sshd.password_auth_enabled and
sshd.root_login_enabled are accepted risks:

accepted_risks:
  - id: sshd.password_auth_enabled
    reason: approved by the CISO
  - id: sshd.root_login_enabled
    reason: approved by the CISO

Report them with status: accepted and severity: info.
