# Changelog

## [Unreleased]
### Fixed
- `build-backend` pointed at `setuptools.backends._legacy:_Backend`, a path
  that does not exist, so `pip install -e .` failed and CI had not passed on
  `main` since 2026-07-24. Now `setuptools.build_meta`, matching the other
  projects in this set.
- Empty-password detection never fired. A `continue` guard discarded the very
  values (`''` and `NP`) the check below it was meant to collect, so the audit
  always reported "empty passwords: none" no matter what was in the shadow
  database.
- `spwd` was imported alongside `pwd` and `grp` in one `try` block. Python 3.13
  removed `spwd` (PEP 594), which flipped `_POSIX` to `False` on ordinary Linux
  hosts: user checks reported "POSIX modules unavailable (Windows)" and every
  readable file failed its permission check with a bogus `chown` remediation.
  Shadow entries are now read via `/etc/shadow` when `spwd` is gone.
- An unresolvable file owner is reported as `warn` rather than a `fail` against
  the host.
- `check_users` no longer aborts on libc builds whose `pwd` module has no
  `getpwall()`; only that one check is skipped.

### Added
- Tests for shadow parsing, empty/locked/cleartext password classification and
  the unknown-owner path (16 tests -> 30).

## [1.0.0] - 2026-07-26
### Added
- linux-security-auditor release
