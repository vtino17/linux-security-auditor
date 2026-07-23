import os
import unittest
from unittest.mock import patch, mock_open, MagicMock, PropertyMock
from lsa.auditor import (
    check_kernel_params, check_ssh_config, check_file_permissions,
    check_services, check_firewall, check_users, check_updates,
    check_open_ports, run_all, summarize, ALL_CHECKS,
    _run, _read_file, _POSIX,
)


class TestUtils(unittest.TestCase):
    @patch('lsa.auditor.subprocess.run')
    def test_run_success(self, mock_run):
        mock_run.return_value = MagicMock(stdout='hello\n', stderr='', returncode=0)
        out, err, rc = _run(['echo', 'hello'])
        self.assertEqual(out, 'hello')
        self.assertEqual(rc, 0)

    @patch('lsa.auditor.subprocess.run')
    def test_run_not_found(self, mock_run):
        mock_run.side_effect = FileNotFoundError()
        out, err, rc = _run(['nonexistent'])
        self.assertEqual(out, '')
        self.assertEqual(err, 'command not found')
        self.assertEqual(rc, -1)

    @patch('lsa.auditor.subprocess.run')
    def test_run_timeout(self, mock_run):
        mock_run.side_effect = __import__('subprocess').TimeoutExpired(cmd='test', timeout=1)
        out, err, rc = _run(['sleep', '10'], timeout=1)
        self.assertEqual(out, '')
        self.assertEqual(err, 'timeout')
        self.assertEqual(rc, -1)

    @patch('builtins.open', side_effect=FileNotFoundError)
    def test_read_file_not_found(self, mock_file):
        self.assertIsNone(_read_file('/nonexistent'))


class TestKernelChecks(unittest.TestCase):
    @patch('lsa.auditor._run')
    def test_kernel_params_pass(self, mock_run):
        mock_run.return_value = ('1', '', 0)
        results = check_kernel_params()
        self.assertTrue(len(results) > 5)
        for r in results:
            self.assertIn(r['status'], ('pass', 'fail', 'warn'))

    @patch('lsa.auditor._run')
    def test_kernel_params_fail_ip_forward(self, mock_run):
        def side_effect(cmd, timeout=10):
            if cmd[-1] == 'net.ipv4.ip_forward':
                return ('1', '', 0)
            return ('', '', -1)
        mock_run.side_effect = side_effect
        results = check_kernel_params()
        ipf = [r for r in results if 'ip_forward' in r['name']]
        self.assertTrue(ipf)
        self.assertEqual(ipf[0]['status'], 'fail')


class TestSSHChecks(unittest.TestCase):
    @patch('lsa.auditor._read_file')
    def test_ssh_root_login_fail(self, mock_read):
        mock_read.return_value = 'PermitRootLogin yes\nPasswordAuthentication no\nPort 22\n'
        results = check_ssh_config()
        root = [r for r in results if 'PermitRootLogin' in r['name']]
        self.assertTrue(root)
        self.assertEqual(root[0]['status'], 'fail')

    @patch('lsa.auditor._read_file')
    def test_ssh_root_login_pass(self, mock_read):
        mock_read.return_value = 'PermitRootLogin prohibit-password\nPasswordAuthentication no\nPort 2222\n'
        results = check_ssh_config()
        root = [r for r in results if 'PermitRootLogin' in r['name']]
        self.assertTrue(root)
        self.assertEqual(root[0]['status'], 'pass')

    @patch('lsa.auditor._read_file')
    def test_ssh_unreadable(self, mock_read):
        mock_read.return_value = None
        results = check_ssh_config()
        self.assertTrue(len(results) == 1)
        self.assertEqual(results[0]['status'], 'warn')


class TestFilePerms(unittest.TestCase):
    @patch('lsa.auditor.os.stat')
    def test_perms_pass(self, mock_stat):
        mock_pwd = MagicMock()
        mock_pwd.getpwuid.return_value = MagicMock(pw_name='root')
        mock_stat.return_value = MagicMock(st_mode=0o100644, st_uid=0)

        with patch('lsa.auditor.pwd', mock_pwd), patch('lsa.auditor._POSIX', True):
            results = check_file_permissions()
        passwd = [r for r in results if 'passwd' in r['name']]
        self.assertTrue(passwd)
        self.assertEqual(passwd[0]['status'], 'pass')

    @patch('lsa.auditor.os.stat')
    def test_perms_fail(self, mock_stat):
        mock_stat.side_effect = FileNotFoundError
        results = check_file_permissions()
        for r in results:
            self.assertEqual(r['status'], 'warn')


class TestFirewall(unittest.TestCase):
    @patch('lsa.auditor._run')
    def test_firewall_ufw_active(self, mock_run):
        def side_effect(cmd, timeout=10):
            if cmd[0] == 'ufw':
                return ('Status: active', '', 0)
            elif cmd[0] == 'iptables':
                return ('Chain INPUT\n1 ACCEPT', '', 0)
            elif cmd[0] == 'firewall-cmd':
                return ('running', '', 0)
            return ('', '', 0)
        mock_run.side_effect = side_effect
        results = check_firewall()
        ufw = [r for r in results if 'ufw' in r['name'] and r['name'] == 'ufw']
        self.assertTrue(ufw)
        self.assertEqual(ufw[0]['status'], 'pass')


class TestUpdates(unittest.TestCase):
    @patch('lsa.auditor._run')
    def test_updates_empty(self, mock_run):
        def side_effect(cmd, timeout=10):
            if 'which' in cmd:
                return ('', '', -1)
            if 'apt-get' in cmd:
                return ('', '', 0)
            return ('', '', -1)
        mock_run.side_effect = side_effect
        results = check_updates()
        self.assertTrue(results)
        self.assertIn(results[0]['status'], ('pass', 'warn'))


class TestSummarize(unittest.TestCase):
    def test_summarize_all_pass(self):
        results = {
            'Test': [
                dict(name='a', status='pass', details='', remediation=''),
                dict(name='b', status='pass', details='', remediation=''),
            ]
        }
        s = summarize(results)
        self.assertEqual(s['passed'], 2)
        self.assertEqual(s['failed'], 0)
        self.assertEqual(s['score'], 100)

    def test_summarize_mixed(self):
        results = {
            'Test': [
                dict(name='a', status='pass', details='', remediation=''),
                dict(name='b', status='fail', details='', remediation=''),
                dict(name='c', status='warn', details='', remediation=''),
                dict(name='d', status='info', details='', remediation=''),
            ]
        }
        s = summarize(results)
        self.assertEqual(s['passed'], 1)
        self.assertEqual(s['failed'], 1)
        self.assertEqual(s['warned'], 1)
        self.assertEqual(s['info'], 1)
        self.assertEqual(s['score'], 33)


class TestRunAll(unittest.TestCase):
    @patch('lsa.auditor.ALL_CHECKS', new=[
        ('Kernel', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('SSH', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Files', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Services', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Firewall', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Users', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Updates', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
        ('Ports', lambda: [dict(name='mock', status='pass', details='', remediation='')]),
    ])
    def test_run_all_calls_all_no_mocks(self):
        results = run_all()
        self.assertEqual(len(results), 8)
        for _, v in results.items():
            self.assertEqual(v[0]['status'], 'pass')


if __name__ == '__main__':
    unittest.main()
