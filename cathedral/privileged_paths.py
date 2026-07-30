"""Trusted-path checks for anything a privileged process reads or executes.

A root process that sources an environment file, imports an interpreter, or
runs a script from a directory an unprivileged user can write is not running
the operator's code. It is running whatever that user last put there, as
root, at the next timer firing. The file's own mode is not the whole answer:
a file at 0600 owned by ``polaris`` is writable by ``polaris``, and a
root-owned file inside a ``polaris``-writable directory can be replaced
wholesale by renaming it.

So the unit of trust is the **whole chain**: the target and every ancestor
directory up to ``/`` must be owned by a trusted uid and must not be writable
by group or other. Symlinks anywhere in the chain are refused rather than
followed, because a symlink is one more thing whose meaning can change
between the check and the use.

Usage from a privileged wrapper, before sourcing anything::

    python3 -m cathedral.privileged_paths /etc/cathedral/epoch.env.sh || exit 1
    set -a; . /etc/cathedral/epoch.env.sh; set +a

The check is advisory in the sense that it cannot close a TOCTOU window that
spans a separate process. It is decisive about the thing that actually
matters here: a path that is *structurally* writable by an unprivileged user
is refused every time, not just when someone happens to have modified it.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass
from pathlib import Path, PurePath

# Root only. An operator who deliberately runs a service under a dedicated
# system account passes that account's uid explicitly.
DEFAULT_TRUSTED_UIDS = frozenset({0})


class UntrustedPath(Exception):
    """A path a privileged process was about to trust is writable by others."""

    def __init__(self, target: str, violations: list[str]) -> None:
        detail = "; ".join(violations)
        super().__init__(f"{target} is not safe for privileged use: {detail}")
        self.target = target
        self.violations = list(violations)


@dataclass(frozen=True)
class PathVerdict:
    """The full picture, so one run tells an operator everything to fix."""

    target: str
    violations: tuple[str, ...]

    @property
    def trusted(self) -> bool:
        return not self.violations


def _describe_owner(uid: int) -> str:
    try:
        import pwd

        return f"uid {uid} ({pwd.getpwuid(uid).pw_name})"
    except (ImportError, KeyError):
        return f"uid {uid}"


def _chain(target: Path) -> list[Path]:
    """The target followed by every ancestor, nearest first."""
    absolute = Path(os.path.abspath(target))
    return [absolute, *absolute.parents]


def inspect_path(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    require_file: bool = True,
    allow_group_write: bool = False,
) -> PathVerdict:
    """Report every reason *target* is unsafe for a privileged process.

    Never raises for an untrusted path; it returns the reasons. Callers that
    must fail closed use :func:`require_trusted_path`.
    """
    if not isinstance(target, (str, PurePath, os.PathLike)):
        raise TypeError("target must be a path")
    trusted = frozenset(trusted_uids)
    if not trusted:
        raise ValueError("at least one trusted uid is required")

    absolute = Path(os.path.abspath(target))
    violations: list[str] = []

    writable_bits = stat.S_IWOTH if allow_group_write else (stat.S_IWGRP | stat.S_IWOTH)

    for index, component in enumerate(_chain(absolute)):
        try:
            info = component.lstat()
        except FileNotFoundError:
            violations.append(f"{component} does not exist")
            continue
        except OSError as exc:
            violations.append(f"{component} cannot be inspected ({exc.strerror})")
            continue

        if stat.S_ISLNK(info.st_mode):
            # Refused rather than resolved: a symlink is one more thing whose
            # target can change between this check and the use.
            violations.append(f"{component} is a symlink")
            continue

        if info.st_uid not in trusted:
            violations.append(f"{component} is owned by {_describe_owner(info.st_uid)}")

        if info.st_mode & writable_bits:
            which = "group- or world-writable" if not allow_group_write else "world-writable"
            violations.append(f"{component} is {which} (mode {info.st_mode & 0o7777:04o})")

        if index == 0:
            if require_file and not stat.S_ISREG(info.st_mode):
                violations.append(f"{component} is not a regular file")
        elif not stat.S_ISDIR(info.st_mode):
            violations.append(f"{component} is not a directory")

    return PathVerdict(target=str(absolute), violations=tuple(violations))


def require_trusted_path(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    require_file: bool = True,
    allow_group_write: bool = False,
) -> str:
    """Return the absolute path, or raise :class:`UntrustedPath`."""
    verdict = inspect_path(
        target,
        trusted_uids=trusted_uids,
        require_file=require_file,
        allow_group_write=allow_group_write,
    )
    if not verdict.trusted:
        raise UntrustedPath(verdict.target, list(verdict.violations))
    return verdict.target


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m cathedral.privileged_paths",
        description=(
            "Refuse a path that a privileged process must not read or execute. "
            "Exits 0 when the target and every ancestor directory are owned by "
            "a trusted uid and are not writable by group or other."
        ),
    )
    parser.add_argument("path", nargs="+", help="paths to check")
    parser.add_argument(
        "--trusted-uid",
        type=int,
        action="append",
        metavar="UID",
        help="uid permitted to own the chain (repeatable; default: 0)",
    )
    parser.add_argument(
        "--directory",
        action="store_true",
        help="the target is a directory rather than a regular file",
    )
    parser.add_argument(
        "--allow-group-write",
        action="store_true",
        help=(
            "permit group-writable components. Only correct when the group is "
            "as trusted as the owner; it is not the default for that reason"
        ),
    )
    args = parser.parse_args(argv)

    trusted = frozenset(args.trusted_uid) if args.trusted_uid else DEFAULT_TRUSTED_UIDS
    failed = False
    for candidate in args.path:
        verdict = inspect_path(
            candidate,
            trusted_uids=trusted,
            require_file=not args.directory,
            allow_group_write=args.allow_group_write,
        )
        if verdict.trusted:
            print(f"ok {verdict.target}")
            continue
        failed = True
        print(f"REFUSED {verdict.target}", file=sys.stderr)
        for violation in verdict.violations:
            print(f"  - {violation}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
