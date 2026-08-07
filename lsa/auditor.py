import subprocess
import os

try:
    import pwd
    import grp
    _POSIX = True
except ImportError:
    pwd = grp = None
    _POSIX = False

try:
    import spwd
except ImportError:
    # Removed in Python 3.13 by PEP 594. Its absence says nothing about
    # whether we are on a POSIX host, so it must not gate _POSIX -- the
    # shadow file is read directly instead.
    spwd = None

# Shadow password fields that mean "this account cannot authenticate with a
# password", as opposed to an empty field, which means anyone can log in
# without one.
_LOCKED_HASHES = ('!', '*', '!!', '!*', 'x')
_EMPTY_HASHES = ('', 'NP')


def _run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except FileNotFoundError:
        return '', 'command not found', -1
    except subprocess.TimeoutExpired:
        return '', 'timeout', -1


def _read_file(path):
    try:
        with open(path, 'r') as f:
            return f.read().strip()
    except (FileNotFoundError, PermissionError, OSError):
        return None


def _fmt(s):
    return ' '.join(s.split()) if s else ''


def shadow_entries(path='/etc/shadow'):
    """Yield (username, password_field) pairs from the shadow database.

    Uses :mod:`spwd` where it still exists and falls back to parsing
    ``/etc/shadow`` on Python 3.13+, where the module was removed. Raises
    ``PermissionError`` when the database cannot be read, so callers can tell
    "nothing to report" apart from "could not look".
    """
    if spwd is not None:
        return [(e.sp_namp, e.sp_pwd) for e in spwd.getspall()]

    entries = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(':')
            if len(parts) >= 2:
                entries.append((parts[0], parts[1]))
    return entries


def check_kernel_params():
    checks = [
        ('net.ipv4.ip_forward', '0'),
        ('net.ipv4.conf.all.accept_redirects', '0'),
        ('net.ipv4.conf.all.send_redirects', '0'),
        ('net.ipv4.tcp_syncookies', '1'),
        ('net.ipv4.conf.all.rp_filter', '1'),
        ('net.ipv4.icmp_echo_ignore_broadcasts', '1'),
        ('net.ipv4.conf.all.accept_source_route', '0'),
        ('net.ipv6.conf.all.accept_redirects', '0'),
        ('fs.suid_dumpable', '0'),
        ('kernel.randomize_va_space', '2'),
    ]
    results = []
    for param, expected in checks:
        val = _run(['sysctl', '-n', param])[0]
        if val == expected:
            results.append(dict(name=f'sysctl {param}', status='pass', details=f'={val}', remediation=''))
        elif val == '':
            results.append(dict(name=f'sysctl {param}', status='warn', details='unreadable', remediation=''))
        else:
            results.append(dict(name=f'sysctl {param}', status='fail', details=f'={val} (expected {expected})', remediation=f'sysctl -w {param}={expected}'))
    return results


def check_ssh_config():
    results = []
    sshd_config = _read_file('/etc/ssh/sshd_config')
    if sshd_config is None:
        return [dict(name='SSH config', status='warn', details='cannot read /etc/ssh/sshd_config', remediation='')]

    lines = sshd_config.splitlines()
    config = {}
    for line in lines:
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            # sshd uses the first obtained value for each keyword. Keeping the
            # last value can make a later, ineffective hardening line hide an
            # insecure directive that actually controls the daemon.
            config.setdefault(parts[0].lower(), parts[1])

    checks = [
        ('PermitRootLogin', lambda v: v and v.lower() in ('no', 'prohibit-password', 'without-password'), 'set PermitRootLogin no'),
        ('PasswordAuthentication', lambda v: v and v.lower() == 'no', 'set PasswordAuthentication no'),
        ('Port', lambda v: v and v.strip() != '22', 'change Port from default 22'),
        ('Protocol', lambda v: True, ''),
        ('X11Forwarding', lambda v: v and v.lower() == 'no', 'set X11Forwarding no'),
        ('MaxAuthTries', lambda v: v and v.strip().isdigit() and int(v.strip()) <= 4, 'set MaxAuthTries 4'),
        ('ClientAliveInterval', lambda v: v and v.strip().isdigit() and int(v.strip()) <= 300, 'set ClientAliveInterval 300'),
        ('PermitEmptyPasswords', lambda v: v and v.lower() == 'no', 'set PermitEmptyPasswords no'),
    ]

    for key, check_fn, remediation in checks:
        val = config.get(key.lower())
        if key == 'Protocol':
            results.append(dict(name=f'SSH {key}', status='pass', details='SSH2 only (deprecated key)', remediation=''))
            continue
        if val and check_fn(val):
            results.append(dict(name=f'SSH {key}', status='pass', details=f'={val}', remediation=''))
        elif val:
            results.append(dict(name=f'SSH {key}', status='fail', details=f'={val}', remediation=remediation))
        else:
            results.append(dict(name=f'SSH {key}', status='warn', details='not set', remediation=remediation))

    return results


def check_file_permissions():
    targets = [
        ('/etc/passwd', '644', 'root'),
        ('/etc/shadow', '640', 'root'),
        ('/etc/sudoers', '440', 'root'),
        ('/etc/ssh/sshd_config', '600', 'root'),
    ]
    results = []
    for path, expected_perm, expected_owner in targets:
        try:
            st = os.stat(path)
            actual_perm = oct(st.st_mode & 0o777)[2:]
            owner = pwd.getpwuid(st.st_uid).pw_name if _POSIX else None
            perm_ok = actual_perm == expected_perm
            # An unresolvable owner is a gap in the audit, not a finding
            # against the host -- claiming otherwise produced a chown
            # remediation for files that were already correct.
            owner_ok = owner == expected_owner if owner is not None else None
            details = f'{actual_perm} {owner if owner is not None else "owner unknown"}'
            if perm_ok and owner_ok is not False:
                status = 'pass' if owner_ok else 'warn'
                results.append(dict(name=f'perms {path}', status=status, details=details, remediation=''))
            else:
                fail = []
                if not perm_ok:
                    fail.append(f'chmod {expected_perm} {path}')
                if owner_ok is False:
                    fail.append(f'chown {expected_owner}:{expected_owner} {path}')
                results.append(dict(name=f'perms {path}', status='fail', details=details, remediation='; '.join(fail)))
        except FileNotFoundError:
            results.append(dict(name=f'perms {path}', status='warn', details='not found', remediation=''))
    return results


def check_services():
    out, _, _ = _run(['ss', '-tlnp4'])
    tcp4 = _fmt(out)
    out, _, _ = _run(['ss', '-tlnp6'])
    tcp6 = _fmt(out)
    out, _, _ = _run(['ss', '-ulnp4'])
    udp4 = _fmt(out)
    out, _, _ = _run(['ss', '-ulnp6'])
    udp6 = _fmt(out)
    details = f'TCP4: {tcp4[:200]}' if tcp4 else 'none'
    details += f' | UDP4: {udp4[:200]}' if udp4 else ''
    details += f' | TCP6: {tcp6[:200]}' if tcp6 else ''
    details += f' | UDP6: {udp6[:200]}' if udp6 else ''
    return [dict(name='listening services', status='info', details=details, remediation='review unexpected services')]


def check_firewall():
    results = []
    ufw_out, ufw_err, ufw_rc = _run(['ufw', 'status'])
    if ufw_rc == 0:
        active = 'active' in ufw_out.lower() or 'Status: active' in ufw_out
        results.append(dict(name='ufw', status='pass' if active else 'fail', details='active' if active else 'inactive', remediation='' if active else 'ufw enable'))
    else:
        results.append(dict(name='ufw', status='warn', details='not installed', remediation=''))

    ipt_out, _, ipt_rc = _run(['iptables', '-L', 'INPUT', '-n', '--line-numbers'])
    if ipt_rc == 0:
        rules = len([l for l in ipt_out.splitlines() if l.strip() and not l.startswith('Chain') and not l.startswith('num') and not l.startswith('target')])
        results.append(dict(name='iptables INPUT', status='pass' if rules > 0 else 'warn', details=f'{rules} rules', remediation=''))
    else:
        results.append(dict(name='iptables', status='warn', details='not available', remediation=''))

    fd_out, _, fd_rc = _run(['firewall-cmd', '--state'])
    if fd_rc == 0:
        results.append(dict(name='firewalld', status='pass', details='running', remediation=''))
    else:
        results.append(dict(name='firewalld', status='warn', details='not running or not installed', remediation=''))

    return results


def check_users():
    results = []
    if not _POSIX:
        results.append(dict(name='User Accounts', status='warn', details='POSIX modules unavailable (Windows)', remediation=''))
        return results

    root = pwd.getpwnam('root')
    if root.pw_uid == 0:
        results.append(dict(name='root UID', status='pass', details='uid=0', remediation=''))
    else:
        results.append(dict(name='root UID', status='fail', details=f'uid={root.pw_uid}', remediation=''))

    empty = []
    readable = True
    try:
        entries = shadow_entries()
    except (PermissionError, FileNotFoundError, OSError):
        entries = []
        readable = False
        results.append(dict(name='shadow passwords', status='warn', details='permission denied', remediation=''))

    for name, pw_hash in entries:
        if pw_hash in _EMPTY_HASHES:
            # No password at all -- collected below rather than skipped.
            empty.append(name)
        elif pw_hash in _LOCKED_HASHES or pw_hash.startswith('!'):
            continue
        elif pw_hash.startswith('$'):
            results.append(dict(name=f'pwd {name}', status='pass', details='hashed', remediation=''))
        else:
            results.append(dict(name=f'pwd {name}', status='fail', details='cleartext or weak', remediation=f'passwd {name}'))

    if empty:
        results.append(dict(name='empty passwords', status='fail', details=', '.join(empty), remediation=f'passwd -l {" ".join(empty)}'))
    elif readable:
        results.append(dict(name='empty passwords', status='pass', details='none', remediation=''))
    else:
        results.append(dict(name='empty passwords', status='warn', details='shadow database unreadable', remediation='re-run as root'))

    last_out, _, _ = _run(['last', '-5'])
    details = _fmt(last_out[:300]) if last_out else 'none'
    results.append(dict(name='recent logins', status='info', details=details, remediation=''))

    # getpwall() is optional -- some libc implementations (bionic, musl in
    # certain builds) ship pwd without it, and calling it aborted the whole
    # user audit rather than skipping one check.
    getpwall = getattr(pwd, 'getpwall', None)
    if getpwall is None:
        results.append(dict(name='non-root UID 0', status='warn', details='cannot enumerate passwd database', remediation=''))
        return results

    for user in getpwall():
        if user.pw_uid == 0 and user.pw_name not in ('root', 'sync', 'shutdown', 'halt', 'toor'):
            results.append(dict(name=f'non-root UID 0: {user.pw_name}', status='fail', details=f'uid={user.pw_uid} shell={user.pw_shell}', remediation=f'userdel {user.pw_name}'))
            break
    else:
        results.append(dict(name='non-root UID 0', status='pass', details='no extra uid=0 users', remediation=''))

    return results


def check_updates():
    out, err, rc = _run(['apt-get', '--just-print', 'dist-upgrade'])
    if rc == 0:
        sec_count = 0
        total = 0
        for line in out.splitlines():
            if 'Inst' in line:
                total += 1
                if 'security' in line.lower() or '-security' in line.lower():
                    sec_count += 1
        status = 'warn' if sec_count > 0 else 'pass'
        results = [dict(name='apt updates', status=status, details=f'{total} total, {sec_count} security' if sec_count > 0 else 'up to date', remediation='apt-get dist-upgrade' if sec_count > 0 else '')]
        return results

    out, _, _ = _run(['yum', 'check-update'])
    if _run(['which', 'yum'])[2] == 0:
        lines = [l for l in out.splitlines() if l.strip() and not l.startswith('Loaded') and not l.startswith('Last')]
        sec = [l for l in lines if 'security' in l.lower()]
        status = 'warn' if sec else 'pass'
        return [dict(name='yum updates', status=status, details=f'{len(lines)} available' if lines else 'up to date', remediation='yum update')]

    return [dict(name='updates', status='warn', details='package manager not detected', remediation='')]


def check_open_ports():
    results = []
    out, _, rc = _run(['ss', '-tulpn'])
    if rc == 0:
        listening = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 5 and 'LISTEN' in line.upper():
                proto = parts[0]
                addr = parts[4] if len(parts) > 4 else ''
                proc = parts[5] if len(parts) > 5 else ''
                listening.append(f'{proto}:{addr} {proc}')
        results = [dict(name='open ports', status='info', details='; '.join(listening[:50]), remediation='review and close unused ports')]
    else:
        results = [dict(name='open ports', status='warn', details='cannot enumerate', remediation='install netstat or ss')]
    return results


ALL_CHECKS = [
    ('Kernel Parameters', check_kernel_params),
    ('SSH Configuration', check_ssh_config),
    ('File Permissions', check_file_permissions),
    ('Services', check_services),
    ('Firewall', check_firewall),
    ('User Accounts', check_users),
    ('Updates', check_updates),
    ('Open Ports', check_open_ports),
]


def run_all():
    output = {}
    for name, fn in ALL_CHECKS:
        try:
            output[name] = fn()
        except Exception as e:
            output[name] = [dict(name=name, status='error', details=str(e), remediation='')]
    return output


def summarize(results):
    total = 0
    passed = 0
    failed = 0
    warned = 0
    infos = 0
    for _, checks in results.items():
        for c in checks:
            total += 1
            if c['status'] == 'pass':
                passed += 1
            elif c['status'] == 'fail':
                failed += 1
            elif c['status'] == 'warn':
                warned += 1
            elif c['status'] == 'info':
                infos += 1
    score = round((passed / max(total - infos, 1)) * 100)
    return dict(total=total, passed=passed, failed=failed, warned=warned, info=infos, score=score)
