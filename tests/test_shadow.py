import unittest
from unittest.mock import patch

from lsa import auditor
from lsa.auditor import check_file_permissions, check_users, shadow_entries, _POSIX


SHADOW_SAMPLE = """\
root:$6$rounds=656000$abcdefgh$hash:19000:0:99999:7:::
daemon:*:19000:0:99999:7:::
locked:!:19000:0:99999:7:::
alsolocked:!!:19000:0:99999:7:::
nopassword::19000:0:99999:7:::
legacynp:NP:19000:0:99999:7:::
weak:plaintextpw:19000:0:99999:7:::
# a comment line

"""


def _findings(results, prefix):
    return [r for r in results if r['name'].startswith(prefix)]


class TestPosixDetection(unittest.TestCase):
    """spwd was removed in Python 3.13; that must not disable POSIX support."""

    def test_posix_is_detected_regardless_of_spwd(self):
        # pwd and grp still exist on every supported Python, so a host that
        # can import them is POSIX whether or not spwd survived PEP 594.
        self.assertTrue(_POSIX)

    def test_pwd_module_is_available(self):
        self.assertIsNotNone(auditor.pwd)
        self.assertIsNotNone(auditor.grp)


class TestShadowEntries(unittest.TestCase):

    def test_parses_shadow_file_when_spwd_is_absent(self):
        with patch.object(auditor, 'spwd', None):
            with patch('builtins.open', unittest.mock.mock_open(read_data=SHADOW_SAMPLE)):
                entries = shadow_entries('/etc/shadow')

        self.assertIn(('root', '$6$rounds=656000$abcdefgh$hash'), entries)
        self.assertIn(('nopassword', ''), entries)
        self.assertIn(('legacynp', 'NP'), entries)

    def test_comments_and_blank_lines_are_skipped(self):
        with patch.object(auditor, 'spwd', None):
            with patch('builtins.open', unittest.mock.mock_open(read_data=SHADOW_SAMPLE)):
                names = [name for name, _ in shadow_entries('/etc/shadow')]

        self.assertNotIn('# a comment line', names)
        self.assertNotIn('', names)

    def test_permission_error_propagates(self):
        with patch.object(auditor, 'spwd', None):
            with patch('builtins.open', side_effect=PermissionError):
                with self.assertRaises(PermissionError):
                    shadow_entries('/etc/shadow')


@unittest.skipUnless(_POSIX, 'requires POSIX')
class TestEmptyPasswordDetection(unittest.TestCase):
    """The empty-password branch used to be unreachable for every value."""

    def _run_with(self, entries):
        with patch('lsa.auditor.shadow_entries', return_value=entries):
            with patch('lsa.auditor._run', return_value=('', '', 0)):
                return check_users()

    def test_empty_password_is_reported_as_a_failure(self):
        results = self._run_with([('nopassword', '')])
        empty = _findings(results, 'empty passwords')[0]

        self.assertEqual(empty['status'], 'fail')
        self.assertIn('nopassword', empty['details'])

    def test_np_placeholder_counts_as_empty(self):
        results = self._run_with([('legacynp', 'NP')])
        empty = _findings(results, 'empty passwords')[0]

        self.assertEqual(empty['status'], 'fail')
        self.assertIn('legacynp', empty['details'])

    def test_multiple_empty_accounts_are_all_listed(self):
        results = self._run_with([('a', ''), ('b', 'NP'), ('c', '$6$x$y')])
        empty = _findings(results, 'empty passwords')[0]

        self.assertEqual(empty['status'], 'fail')
        self.assertIn('a', empty['details'])
        self.assertIn('b', empty['details'])

    def test_locked_accounts_are_not_flagged(self):
        results = self._run_with([
            ('daemon', '*'), ('locked', '!'), ('alsolocked', '!!'),
        ])
        empty = _findings(results, 'empty passwords')[0]

        self.assertEqual(empty['status'], 'pass')
        self.assertEqual(_findings(results, 'pwd '), [])

    def test_hashed_password_passes(self):
        results = self._run_with([('root', '$6$rounds=656000$abc$hash')])
        entry = _findings(results, 'pwd root')[0]

        self.assertEqual(entry['status'], 'pass')
        self.assertEqual(entry['details'], 'hashed')

    def test_cleartext_password_fails(self):
        results = self._run_with([('weak', 'plaintextpw')])
        entry = _findings(results, 'pwd weak')[0]

        self.assertEqual(entry['status'], 'fail')
        self.assertIn('passwd weak', entry['remediation'])

    def test_unreadable_shadow_warns_instead_of_passing(self):
        with patch('lsa.auditor.shadow_entries', side_effect=PermissionError):
            with patch('lsa.auditor._run', return_value=('', '', 0)):
                results = check_users()

        empty = _findings(results, 'empty passwords')[0]
        self.assertEqual(empty['status'], 'warn')
        self.assertEqual(_findings(results, 'shadow passwords')[0]['status'], 'warn')


class TestFilePermissionOwnerUnknown(unittest.TestCase):

    def test_unknown_owner_does_not_produce_a_bogus_chown(self):
        import os as _os
        stat_result = _os.stat_result((0o100644, 0, 0, 1, 0, 0, 0, 0, 0, 0))

        with patch('lsa.auditor._POSIX', False):
            with patch('lsa.auditor.os.stat', return_value=stat_result):
                results = check_file_permissions()

        passwd = _findings(results, 'perms /etc/passwd')[0]
        self.assertEqual(passwd['status'], 'warn')
        self.assertEqual(passwd['remediation'], '')

    def test_wrong_mode_still_fails_when_owner_is_unknown(self):
        import os as _os
        stat_result = _os.stat_result((0o100777, 0, 0, 1, 0, 0, 0, 0, 0, 0))

        with patch('lsa.auditor._POSIX', False):
            with patch('lsa.auditor.os.stat', return_value=stat_result):
                results = check_file_permissions()

        passwd = _findings(results, 'perms /etc/passwd')[0]
        self.assertEqual(passwd['status'], 'fail')
        self.assertIn('chmod 644 /etc/passwd', passwd['remediation'])
        self.assertNotIn('chown', passwd['remediation'])


if __name__ == '__main__':
    unittest.main()
