"""Trusted-path checks for anything a privileged process reads or executes.

A root process that sources an environment file, imports an interpreter, or
runs a script from a directory an unprivileged user can write is not running
the operator's code. It is running whatever that user last put there, as
root, at the next timer firing. The file's own mode is not the whole answer:
a file at 0600 owned by ``polaris`` is writable by ``polaris``, and a
root-owned file inside a ``polaris``-writable directory can be replaced
wholesale by renaming it.

So the unit of trust is the **whole chain**: the target and every ancestor
directory up to ``/`` must be owned by a trusted uid, must not be writable by
group or other, and must have no extended ACL. Regular-file and tree checks
refuse symlinks. Executables use a separate resolved mode that checks every
link object, each ancestor, and the eventual regular file.

Usage from a privileged wrapper, before sourcing anything, uses the
root-installed standalone copy of this file rather than importing the package
tree it is meant to inspect::

    /usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py \
        /etc/cathedral/epoch.env.sh || exit 1
    set -a; . /etc/cathedral/epoch.env.sh; set +a

The check is advisory in the sense that it cannot close a TOCTOU window that
spans a separate process. It is decisive about the thing that actually
matters here: a path that is *structurally* writable by an unprivileged user
is refused every time, not just when someone happens to have modified it.
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePath

# Root only. An operator who deliberately runs a service under a dedicated
# system account passes that account's uid explicitly.
DEFAULT_TRUSTED_UIDS = frozenset({0})
MAX_SYMLINKS = 40
MAX_TREE_DEPTH = 64
MAX_TREE_ENTRIES = 100_000


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


def _acl_violations(target: Path) -> list[str]:
    """Fail closed unless the path has no extended access-control list.

    The privileged-path contract is deliberately narrower than attempting to
    interpret every possible ACL: owner plus mode bits are the complete policy,
    so any extended ACL is refused. Linux exposes POSIX access/default ACLs as
    system xattrs. Darwin's ACLs are queried through the OS ``ls`` tool. An
    unsupported platform or an inspection error is not treated as "no ACL".
    """
    if sys.platform.startswith("linux"):
        try:
            names = {
                os.fsdecode(name)
                for name in os.listxattr(target, follow_symlinks=False)
            }
        except (AttributeError, OSError) as exc:
            detail = getattr(exc, "strerror", None) or str(exc)
            return [f"{target} ACL safety cannot be established ({detail})"]
        acl_names = sorted(
            name
            for name in names
            if name in {"system.posix_acl_access", "system.posix_acl_default"}
        )
        if acl_names:
            return [
                f"{target} has an extended POSIX ACL ({', '.join(acl_names)})"
            ]
        return []

    if sys.platform == "darwin":
        try:
            result = subprocess.run(
                ["/bin/ls", "-lde", os.fspath(target)],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
                env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return [f"{target} ACL safety cannot be established ({exc})"]
        if result.returncode != 0:
            detail = result.stderr.strip() or f"ls exited {result.returncode}"
            return [f"{target} ACL safety cannot be established ({detail})"]
        if any(re.match(r"^\s*\d+:\s", line) for line in result.stdout.splitlines()[1:]):
            return [f"{target} has an extended Darwin ACL"]
        return []

    return [f"{target} ACL safety cannot be established on {sys.platform}"]


def _mode_violations(
    component: Path,
    info: os.stat_result,
    *,
    trusted: frozenset[int],
    allow_group_write: bool,
    check_writable_bits: bool = True,
    check_acl: bool = True,
) -> list[str]:
    violations: list[str] = []
    if info.st_uid not in trusted:
        violations.append(f"{component} is owned by {_describe_owner(info.st_uid)}")
    writable_bits = stat.S_IWOTH if allow_group_write else (stat.S_IWGRP | stat.S_IWOTH)
    if check_writable_bits and info.st_mode & writable_bits:
        which = "group- or world-writable" if not allow_group_write else "world-writable"
        violations.append(f"{component} is {which} (mode {info.st_mode & 0o7777:04o})")
    if check_acl:
        violations.extend(_acl_violations(component))
    return violations


def inspect_path(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    require_file: bool = True,
    allow_group_write: bool = False,
    _allow_leaf_symlink: bool = False,
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
            if index != 0 or not _allow_leaf_symlink:
                violations.append(f"{component} is a symlink")
            violations.extend(
                _mode_violations(
                    component,
                    info,
                    trusted=trusted,
                    allow_group_write=allow_group_write,
                    # Symlink mode bits are not access control. The parent
                    # directory controls replacement of the link. Linux also
                    # does not attach access ACLs to symlink objects.
                    check_writable_bits=False,
                    check_acl=False,
                )
            )
            continue

        violations.extend(
            _mode_violations(
                component,
                info,
                trusted=trusted,
                allow_group_write=allow_group_write,
            )
        )

        if index == 0:
            if require_file and not stat.S_ISREG(info.st_mode):
                violations.append(f"{component} is not a regular file")
            elif not require_file and not stat.S_ISDIR(info.st_mode):
                violations.append(f"{component} is not a directory")
        elif not stat.S_ISDIR(info.st_mode):
            violations.append(f"{component} is not a directory")

    return PathVerdict(target=str(absolute), violations=tuple(violations))


def inspect_creatable_file(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    allow_group_write: bool = False,
) -> PathVerdict:
    """Inspect an existing file, or its directory when first-run creation is safe.

    A missing leaf is safe to create only when its complete parent chain is
    trusted. If the leaf already exists, it must pass the ordinary regular-file
    check, including ownership, mode, symlink, and ACL rules. The parent check
    also makes a create-after-check race unavailable to an untrusted user.
    """
    if not isinstance(target, (str, PurePath, os.PathLike)):
        raise TypeError("target must be a path")
    absolute = Path(os.path.abspath(target))
    try:
        absolute.lstat()
    except FileNotFoundError:
        parent = inspect_path(
            absolute.parent,
            trusted_uids=trusted_uids,
            require_file=False,
            allow_group_write=allow_group_write,
        )
        return PathVerdict(target=str(absolute), violations=parent.violations)
    except OSError:
        # Let inspect_path preserve its detailed fail-closed diagnostic.
        pass
    return inspect_path(
        absolute,
        trusted_uids=trusted_uids,
        allow_group_write=allow_group_write,
    )


def _first_symlink(target: Path) -> tuple[Path, tuple[str, ...]] | None:
    """Return the first symlink and the unresolved tail beneath it."""
    absolute = Path(os.path.abspath(target))
    parts = absolute.parts
    current = Path(parts[0])
    for index, part in enumerate(parts[1:], 1):
        current = current / part
        try:
            info = current.lstat()
        except OSError:
            return None
        if stat.S_ISLNK(info.st_mode):
            return current, tuple(parts[index + 1 :])
    return None


def inspect_resolved_path(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    allow_group_write: bool = False,
) -> PathVerdict:
    """Inspect a standard executable symlink chain and its final file.

    Every link object, each link's ancestor chain, and the eventual regular
    file are checked. This supports the symlinks created by a normal POSIX
    virtualenv without treating an unchecked redirect as trusted.
    """
    if not isinstance(target, (str, PurePath, os.PathLike)):
        raise TypeError("target must be a path")
    trusted = frozenset(trusted_uids)
    if not trusted:
        raise ValueError("at least one trusted uid is required")

    original = Path(os.path.abspath(target))
    current = original
    seen: set[str] = set()
    violations: list[str] = []
    for _ in range(MAX_SYMLINKS + 1):
        found = _first_symlink(current)
        if found is None:
            final = inspect_path(
                current,
                trusted_uids=trusted,
                allow_group_write=allow_group_write,
            )
            violations.extend(final.violations)
            return PathVerdict(target=str(original), violations=tuple(dict.fromkeys(violations)))

        link, tail = found
        key = str(link)
        if key in seen:
            violations.append(f"{link} forms a symlink cycle")
            return PathVerdict(target=str(original), violations=tuple(dict.fromkeys(violations)))
        seen.add(key)

        link_verdict = inspect_path(
            link,
            trusted_uids=trusted,
            require_file=False,
            allow_group_write=allow_group_write,
            _allow_leaf_symlink=True,
        )
        violations.extend(link_verdict.violations)
        try:
            destination = Path(os.readlink(link))
        except OSError as exc:
            violations.append(f"{link} cannot be read ({exc.strerror})")
            return PathVerdict(target=str(original), violations=tuple(dict.fromkeys(violations)))
        if not destination.is_absolute():
            destination = link.parent / destination
        current = Path(os.path.abspath(destination.joinpath(*tail)))

    violations.append(f"{original} exceeds the {MAX_SYMLINKS}-link safety limit")
    return PathVerdict(target=str(original), violations=tuple(dict.fromkeys(violations)))


def inspect_tree(
    target: str | os.PathLike[str],
    *,
    trusted_uids: frozenset[int] | set[int] = DEFAULT_TRUSTED_UIDS,
    allow_group_write: bool = False,
    max_entries: int = MAX_TREE_ENTRIES,
    max_depth: int = MAX_TREE_DEPTH,
) -> PathVerdict:
    """Inspect a complete import/source tree with bounded descriptor walking.

    The tree root first has to pass the normal ancestor check. The walk then
    uses ``os.fwalk`` and descriptor-relative ``stat`` calls, never follows a
    symlink, refuses special files, and stops rather than descending into an
    already-untrusted directory. Entry and depth limits make a hostile or
    accidental giant tree a refusal instead of unbounded preflight work.
    This inspects one named tree; it deliberately does not execute or infer
    external redirects from ``.pth`` contents. Privileged Python startup must
    disable site initialization or name and check those roots separately.
    """
    if not isinstance(target, (str, PurePath, os.PathLike)):
        raise TypeError("target must be a path")
    trusted = frozenset(trusted_uids)
    if not trusted:
        raise ValueError("at least one trusted uid is required")
    if max_entries < 1 or max_depth < 0:
        raise ValueError("tree limits must be positive")

    root = Path(os.path.abspath(target))
    root_verdict = inspect_path(
        root,
        trusted_uids=trusted,
        require_file=False,
        allow_group_write=allow_group_write,
    )
    violations = list(root_verdict.violations)
    if violations:
        return PathVerdict(target=str(root), violations=tuple(dict.fromkeys(violations)))

    entries = 0
    try:
        walker = os.fwalk(root, topdown=True, follow_symlinks=False)
        for directory, dirnames, filenames, descriptor in walker:
            relative = Path(directory).relative_to(root)
            depth = 0 if relative == Path(".") else len(relative.parts)
            if depth > max_depth:
                violations.append(f"{directory} exceeds the tree depth limit {max_depth}")
                dirnames[:] = []
                continue

            for name, expected_directory in [
                *((name, True) for name in sorted(dirnames)),
                *((name, False) for name in sorted(filenames)),
            ]:
                entries += 1
                path = Path(directory) / name
                if entries > max_entries:
                    violations.append(f"{root} exceeds the tree entry limit {max_entries}")
                    dirnames[:] = []
                    return PathVerdict(
                        target=str(root), violations=tuple(dict.fromkeys(violations))
                    )
                try:
                    info = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                except OSError as exc:
                    violations.append(f"{path} cannot be inspected ({exc.strerror})")
                    if expected_directory and name in dirnames:
                        dirnames.remove(name)
                    continue

                if stat.S_ISLNK(info.st_mode):
                    violations.append(f"{path} is a symlink")
                    if expected_directory and name in dirnames:
                        dirnames.remove(name)
                    continue

                item_violations = _mode_violations(
                    path,
                    info,
                    trusted=trusted,
                    allow_group_write=allow_group_write,
                )
                if expected_directory:
                    if not stat.S_ISDIR(info.st_mode):
                        item_violations.append(f"{path} is not a directory")
                    if item_violations and name in dirnames:
                        # One untrusted directory is enough to refuse the tree;
                        # do not continue walking content its owner controls.
                        dirnames.remove(name)
                elif not stat.S_ISREG(info.st_mode):
                    item_violations.append(f"{path} is not a regular file")
                violations.extend(item_violations)
    except OSError as exc:
        violations.append(f"{root} cannot be walked safely ({exc.strerror})")

    return PathVerdict(target=str(root), violations=tuple(dict.fromkeys(violations)))


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
        prog="cathedral-privileged-paths",
        description=(
            "Refuse a path that a privileged process must not read or execute. "
            "Exits 0 when the target and every ancestor directory are owned by "
            "a trusted uid, are not writable by group or other, and have no "
            "extended ACL."
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
        "--resolve-symlinks",
        action="store_true",
        help="verify every link and the final regular file in an executable symlink chain",
    )
    parser.add_argument(
        "--tree",
        action="store_true",
        help="verify every descendant under one bounded, named import tree",
    )
    parser.add_argument(
        "--creatable-file",
        action="store_true",
        help=(
            "verify an existing regular file, or its complete parent chain when "
            "the leaf does not exist yet"
        ),
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

    selected_modes = sum(
        bool(value)
        for value in (
            args.directory,
            args.resolve_symlinks,
            args.tree,
            args.creatable_file,
        )
    )
    if selected_modes > 1:
        parser.error(
            "--directory, --resolve-symlinks, --tree, and --creatable-file "
            "are mutually exclusive"
        )

    trusted = frozenset(args.trusted_uid) if args.trusted_uid else DEFAULT_TRUSTED_UIDS
    failed = False
    for candidate in args.path:
        if args.creatable_file:
            verdict = inspect_creatable_file(
                candidate,
                trusted_uids=trusted,
                allow_group_write=args.allow_group_write,
            )
        elif args.resolve_symlinks:
            verdict = inspect_resolved_path(
                candidate,
                trusted_uids=trusted,
                allow_group_write=args.allow_group_write,
            )
        elif args.tree:
            verdict = inspect_tree(
                candidate,
                trusted_uids=trusted,
                allow_group_write=args.allow_group_write,
            )
        else:
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
