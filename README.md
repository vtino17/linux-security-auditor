# Linux Security Auditor

[![CI](https://github.com/vtino17/linux-security-auditor/actions/workflows/ci.yml/badge.svg)](https://github.com/vtino17/linux-security-auditor/actions/workflows/ci.yml)

Comprehensive Linux security audit tool that checks kernel parameters, SSH configuration, file permissions, firewall status, user accounts, available updates, and open ports.

## Installation

```bash
pip install .
```

## Usage

```bash
# Run all checks
lsa

# JSON output
lsa --json

# HTML report
lsa --report report.html

# Specific checks only
lsa --checks kernel,ssh

# Quiet mode
lsa --quiet
```

## Checks

| Category | Checks |
|----------|--------|
| Kernel Parameters | IP forwarding, redirects, syncookies, ASLR, core dumps |
| SSH Configuration | Root login, password auth, port, X11 forwarding, max auth tries |
| File Permissions | /etc/passwd, /etc/shadow, /etc/sudoers, sshd_config |
| Services | All listening TCP/UDP services |
| Firewall | ufw, iptables, firewalld |
| User Accounts | Root UID, empty passwords, non-root UID 0, recent logins |
| Updates | Available security updates (apt/yum) |
| Open Ports | All listening ports |

## Output

- Terminal: color-coded pass/fail/warn with details
- HTML: dark theme report with expandable sections and summary score
- JSON: machine-readable output
