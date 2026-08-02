"""Trusted-path checks for anything a privileged process reads or executes.

The finding these regress: a root epoch wrapper sourced an environment file
owned by, and writable by, an unprivileged user. Mode 0600 was not a
mitigation, because the danger was the owner, not the group or other bits.
The shipped policy-republisher unit had the same shape: `User=root` running
an interpreter out of a home directory.

Covers:
  1. A root-owned file under root-owned directories is accepted.
  2. A file owned by another user is refused even at mode 0600.
  3. A trusted file inside an untrusted or writable directory is refused,
     anywhere up the chain.
  4. Ordinary symlinks are refused; a standard venv executable chain is
     accepted only after every link and final file pass.
  5. Group- and world-writable components are refused; --allow-group-write
     narrows to world-writable only.
  6. Extended ACLs and ACL-inspection failures are refused.
  7. Every descendant under a named import root is checked without following
     links; privileged startup disables unchecked .pth redirects.
  8. Missing, non-regular, and non-directory components are refused, while a
     securely creatable first-run leaf checks its complete parent chain.
  9. Every violation is reported at once, and the CLI exits non-zero.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

import pytest

from cathedral.privileged_paths import (
    UntrustedPath,
    inspect_creatable_file,
    inspect_path,
    inspect_resolved_path,
    inspect_tree,
    main,
    require_trusted_path,
)

ME = os.getuid()
OTHER = ME + 1  # a uid this process certainly is not
# A realistic accepting set: the service account plus root, which owns the
# system directories every temporary path is nested under.
ACCEPT = {ME, 0}


@pytest.fixture
def tmp_path(tmp_path_factory):
    """Provide a writable test root whose complete ancestor chain is trusted.

    Pytest commonly roots ``tmp_path`` below world-writable ``/tmp`` on Linux.
    That is correctly refused by the production checker, but it is the wrong
    fixture for positive-path assertions. Prefer pytest's root when safe and
    otherwise create a private directory below a trusted writable base.
    """
    candidate = tmp_path_factory.mktemp("privileged-paths")
    candidate_verdict = inspect_path(
        candidate,
        trusted_uids=ACCEPT,
        require_file=False,
    )
    if candidate_verdict.trusted:
        yield candidate
        return

    fallback: Path | None = None
    seen: set[Path] = set()
    fallback_bases = [
        Path(os.environ[name])
        for name in ("CATHEDRAL_TEST_TMPDIR", "TMPDIR", "TEMP", "TMP")
        if os.environ.get(name)
    ]
    fallback_bases.extend(
        [
            Path(tempfile.gettempdir()),
            Path(__file__).resolve().parents[1],
            Path.home(),
        ]
    )
    for base in fallback_bases:
        # Resolve platform aliases such as macOS /var -> /private/var, then
        # inspect and use the exact resolved chain.
        base = Path(os.path.realpath(base))
        if base in seen or not base.is_dir() or not os.access(base, os.W_OK):
            continue
        seen.add(base)
        base_verdict = inspect_path(
            base,
            trusted_uids=ACCEPT,
            require_file=False,
        )
        if not base_verdict.trusted:
            continue
        trial = Path(tempfile.mkdtemp(prefix=".cathedral-path-test-", dir=base))
        trial_verdict = inspect_path(
            trial,
            trusted_uids=ACCEPT,
            require_file=False,
        )
        if trial_verdict.trusted:
            fallback = trial
            break
        shutil.rmtree(trial)

    if fallback is None:
        pytest.fail(
            "no writable trusted temporary root is available; pytest root: "
            + "; ".join(candidate_verdict.violations)
        )

    try:
        # This assertion is the regression boundary for every positive fixture.
        assert inspect_path(
            fallback,
            trusted_uids=ACCEPT,
            require_file=False,
        ).trusted
        yield fallback
    finally:
        shutil.rmtree(fallback)


def _chain(tmp_path: Path, *, mode: int = 0o755) -> tuple[Path, Path]:
    """A directory holding one file, both owned by the invoking user."""
    directory = tmp_path / "etc"
    directory.mkdir(mode=mode)
    target = directory / "epoch.env.sh"
    target.write_text("export CATHEDRAL_X=1\n")
    target.chmod(0o600)
    return directory, target


# ---------------------------------------------------------------------------
# 1. Accepted
# ---------------------------------------------------------------------------

def test_a_trusted_chain_is_accepted(tmp_path: Path):
    _, target = _chain(tmp_path)
    verdict = inspect_path(target, trusted_uids=ACCEPT)
    assert verdict.trusted
    assert verdict.violations == ()
    assert require_trusted_path(target, trusted_uids=ACCEPT) == os.path.abspath(target)


def test_a_directory_target_is_accepted_when_asked_for(tmp_path: Path):
    directory, _ = _chain(tmp_path)
    assert inspect_path(directory, trusted_uids=ACCEPT, require_file=False).trusted


# ---------------------------------------------------------------------------
# 2. Ownership — the finding itself
# ---------------------------------------------------------------------------

def test_a_file_owned_by_another_user_is_refused_even_at_0600(tmp_path: Path):
    """Mode 0600 is not a mitigation when the owner is the untrusted party."""
    _, target = _chain(tmp_path)
    assert oct(target.stat().st_mode & 0o777) == "0o600"

    # Trust only root; this file is owned by the invoking user, standing in
    # for the polaris-owned .env.sh a root wrapper would have sourced.
    verdict = inspect_path(target, trusted_uids={0})
    assert not verdict.trusted
    assert any("is owned by" in violation for violation in verdict.violations)

    with pytest.raises(UntrustedPath, match="not safe for privileged use"):
        require_trusted_path(target, trusted_uids={0})


def test_the_exception_carries_every_reason(tmp_path: Path):
    _, target = _chain(tmp_path)
    with pytest.raises(UntrustedPath) as caught:
        require_trusted_path(target, trusted_uids={OTHER})
    assert caught.value.target == str(target.resolve())
    assert caught.value.violations
    assert all(isinstance(item, str) for item in caught.value.violations)


# ---------------------------------------------------------------------------
# 3. The chain, not just the file
# ---------------------------------------------------------------------------

def test_a_trusted_file_in_a_writable_directory_is_refused(tmp_path: Path):
    """A root-owned file can be replaced wholesale by renaming its parent."""
    directory, target = _chain(tmp_path)
    directory.chmod(0o777)

    verdict = inspect_path(target, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any(str(directory) in violation and "writable" in violation
               for violation in verdict.violations)


def test_an_untrusted_ancestor_further_up_is_refused(tmp_path: Path):
    nested = tmp_path / "home" / "polaris" / "cathedral"
    nested.mkdir(parents=True)
    target = nested / "epoch.env.sh"
    target.write_text("export X=1\n")
    target.chmod(0o600)

    # The whole chain belongs to this user, so trusting only root refuses it
    # at every level rather than only at the leaf.
    verdict = inspect_path(target, trusted_uids={0})
    assert not verdict.trusted
    owner_violations = [v for v in verdict.violations if "is owned by" in v]
    assert len(owner_violations) >= 3  # file, cathedral, polaris, home, ...


# ---------------------------------------------------------------------------
# 4. Symlinks
# ---------------------------------------------------------------------------

def test_a_symlinked_target_is_refused_not_followed(tmp_path: Path):
    _, real = _chain(tmp_path)
    link = tmp_path / "etc" / "link.env.sh"
    link.symlink_to(real)

    verdict = inspect_path(link, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("is a symlink" in violation for violation in verdict.violations)


def test_a_symlinked_ancestor_is_refused(tmp_path: Path):
    directory, _ = _chain(tmp_path)
    linked_dir = tmp_path / "etc-link"
    linked_dir.symlink_to(directory)

    verdict = inspect_path(linked_dir / "epoch.env.sh", trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("is a symlink" in violation for violation in verdict.violations)


def test_a_standard_venv_interpreter_symlink_chain_is_verified(tmp_path: Path, capsys):
    """The example unit must not reject the layout Python creates by default."""
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    interpreter = environment / "bin" / "python"
    if not interpreter.is_symlink():
        pytest.skip("this platform's standard venv copies the interpreter")

    # Venv link layouts vary: hosted Linux points bin/python directly into a
    # platform-managed writable tool cache, while local installs often use a
    # versioned sibling link. Preserve bin/python as the symlink under test but
    # give it a trusted local target so host-installation policy is out of scope.
    base = interpreter.resolve(strict=True)
    local_target = interpreter.with_name("python-local-target")
    shutil.copyfile(base, local_target)
    local_target.chmod(0o755)
    interpreter.unlink()
    interpreter.symlink_to(local_target.name)
    assert interpreter.is_symlink()
    assert interpreter.resolve(strict=True) == local_target

    verdict = inspect_resolved_path(interpreter, trusted_uids=ACCEPT)
    assert verdict.trusted, verdict.violations
    assert main([
        "--resolve-symlinks",
        "--trusted-uid", str(ME),
        "--trusted-uid", "0",
        str(interpreter),
    ]) == 0
    assert "ok " in capsys.readouterr().out


def test_no_site_blocks_a_trusted_pth_redirect_to_user_writable_sitecustomize(
    tmp_path: Path,
):
    """-I alone still executes site hooks reached through a trusted .pth file."""
    environment = tmp_path / "venv"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(environment)
    interpreter = environment / "bin" / "python"
    site_packages = (
        environment
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    assert site_packages.is_dir()

    attacker_tree = tmp_path / "attacker-code"
    attacker_tree.mkdir()
    marker = tmp_path / "sitecustomize-ran"
    (attacker_tree / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('executed as service user\\n')\n"
    )
    attacker_tree.chmod(0o777)
    redirect = site_packages / "trusted-editable-redirect.pth"
    redirect.write_text(
        f"{attacker_tree}\n"
        f"import runpy; runpy.run_path({str(attacker_tree / 'sitecustomize.py')!r})\n"
    )
    redirect.chmod(0o644)

    # The .pth file itself is inside the trusted, recursively checked tree.
    # Its path target is not. This is the exact gap -S closes for the service.
    assert inspect_tree(site_packages, trusted_uids=ACCEPT).trusted
    with_site = subprocess.run(
        [interpreter, "-I", "-c", "pass"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert with_site.returncode == 0, with_site.stderr
    assert marker.exists(), with_site.stdout + with_site.stderr

    marker.unlink()
    without_site = subprocess.run(
        [interpreter, "-I", "-S", "-c", "pass"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert without_site.returncode == 0, without_site.stderr
    assert not marker.exists()


# ---------------------------------------------------------------------------
# 5. Writability
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", [0o660, 0o606, 0o666, 0o777])
def test_group_or_world_writable_targets_are_refused(tmp_path: Path, mode: int):
    _, target = _chain(tmp_path)
    target.chmod(mode)
    verdict = inspect_path(target, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("writable" in violation for violation in verdict.violations)


def test_allow_group_write_narrows_to_world_writable_only(tmp_path: Path):
    _, target = _chain(tmp_path)
    target.chmod(0o660)
    assert inspect_path(target, trusted_uids=ACCEPT, allow_group_write=True).trusted

    target.chmod(0o662)
    assert not inspect_path(target, trusted_uids=ACCEPT, allow_group_write=True).trusted


def test_the_default_refuses_group_write(tmp_path: Path):
    _, target = _chain(tmp_path)
    target.chmod(0o640)
    assert inspect_path(target, trusted_uids=ACCEPT).trusted
    target.chmod(0o660)
    assert not inspect_path(target, trusted_uids=ACCEPT).trusted


def test_an_extended_acl_is_refused_without_mode_bit_help(tmp_path: Path):
    _, target = _chain(tmp_path)
    before = target.stat().st_mode & 0o777

    if sys.platform == "darwin":
        command = ["/bin/chmod", "+a", "everyone allow write", str(target)]
    elif sys.platform.startswith("linux") and shutil.which("setfacl"):
        command = [shutil.which("setfacl") or "setfacl", "-m", "u:nobody:rw", str(target)]
    else:
        pytest.skip("no supported ACL grant tool on this host")

    result = subprocess.run(command, check=False, capture_output=True, text=True)
    if result.returncode != 0:
        pytest.skip(f"host refused the ACL test fixture: {result.stderr.strip()}")
    # Linux setfacl commonly widens the group mode bits through the ACL mask.
    # Restore the original mode while retaining the named extended ACL, so the
    # refusal below proves ACL inspection rather than ordinary mode checking.
    target.chmod(before)
    assert target.stat().st_mode & 0o777 == before
    if sys.platform.startswith("linux"):
        names = {os.fsdecode(name) for name in os.listxattr(target, follow_symlinks=False)}
        assert "system.posix_acl_access" in names

    verdict = inspect_path(target, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("ACL" in violation for violation in verdict.violations)
    assert not any("writable" in violation for violation in verdict.violations)


def test_acl_inspection_failure_is_not_treated_as_no_acl(tmp_path: Path, monkeypatch):
    _, target = _chain(tmp_path)

    def unavailable(*_args, **_kwargs):
        raise OSError("ACL backend unavailable")

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(os, "listxattr", unavailable, raising=False)
    verdict = inspect_path(target, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("ACL safety cannot be established" in item for item in verdict.violations)


# ---------------------------------------------------------------------------
# 6. Complete import trees
# ---------------------------------------------------------------------------

def test_tree_refuses_a_writable_imported_package_file(tmp_path: Path):
    site_packages = tmp_path / "site-packages"
    package = site_packages / "cathedral"
    package.mkdir(parents=True)
    module = package / "policy_registry.py"
    module.write_text("ATTACKER_CONTROLLED = True\n")
    module.chmod(0o666)

    verdict = inspect_tree(site_packages, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any(
        str(module) in violation and "writable" in violation
        for violation in verdict.violations
    )


def test_tree_refuses_descendant_symlinks_without_following_them(tmp_path: Path):
    source = tmp_path / "cathedral"
    source.mkdir()
    real = source / "common.py"
    real.write_text("VALUE = 1\n")
    link = source / "policy.py"
    link.symlink_to(real)

    verdict = inspect_tree(source, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any(
        str(link) in violation and "symlink" in violation
        for violation in verdict.violations
    )


# ---------------------------------------------------------------------------
# 7. Shape
# ---------------------------------------------------------------------------

def test_a_missing_target_is_refused(tmp_path: Path):
    verdict = inspect_path(tmp_path / "absent.sh", trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("does not exist" in violation for violation in verdict.violations)


def test_a_directory_where_a_file_was_expected_is_refused(tmp_path: Path):
    directory, _ = _chain(tmp_path)
    verdict = inspect_path(directory, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("not a regular file" in violation for violation in verdict.violations)


def test_a_file_where_a_directory_was_expected_is_refused(tmp_path: Path):
    _, target = _chain(tmp_path)
    verdict = inspect_path(target, trusted_uids=ACCEPT, require_file=False)
    assert not verdict.trusted
    assert any("not a directory" in violation for violation in verdict.violations)


def test_a_fifo_is_refused(tmp_path: Path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo)
    verdict = inspect_path(fifo, trusted_uids=ACCEPT)
    assert not verdict.trusted
    assert any("not a regular file" in violation for violation in verdict.violations)
    assert stat.S_ISFIFO(fifo.lstat().st_mode)


def test_a_creatable_file_checks_existing_leaf_or_missing_leaf_parent(tmp_path: Path):
    directory = tmp_path / "state"
    directory.mkdir()
    candidate = directory / "approval.jsonl"

    assert inspect_creatable_file(candidate, trusted_uids=ACCEPT).trusted
    assert main([
        "--creatable-file",
        "--trusted-uid", str(ME),
        "--trusted-uid", "0",
        str(candidate),
    ]) == 0

    candidate.write_text("")
    candidate.chmod(0o666)
    assert not inspect_creatable_file(candidate, trusted_uids=ACCEPT).trusted

    candidate.unlink()
    directory.chmod(0o777)
    assert not inspect_creatable_file(candidate, trusted_uids=ACCEPT).trusted


def test_invalid_arguments_are_rejected(tmp_path: Path):
    with pytest.raises(ValueError, match="at least one trusted uid"):
        inspect_path(tmp_path, trusted_uids=set())
    with pytest.raises(TypeError, match="must be a path"):
        inspect_path(1234)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 8. CLI and service integration
# ---------------------------------------------------------------------------

def test_cli_accepts_a_trusted_chain(tmp_path: Path, capsys):
    _, target = _chain(tmp_path)
    assert main([str(target), "--trusted-uid", str(ME), "--trusted-uid", "0"]) == 0
    assert "ok " in capsys.readouterr().out


def test_cli_exits_non_zero_and_names_every_reason(tmp_path: Path, capsys):
    _, target = _chain(tmp_path)
    target.chmod(0o666)
    assert main([str(target), "--trusted-uid", str(OTHER)]) == 1

    err = capsys.readouterr().err
    assert "REFUSED" in err
    assert "is owned by" in err
    assert "writable" in err


def test_cli_checks_every_path_before_failing(tmp_path: Path, capsys):
    _, good = _chain(tmp_path)
    bad = tmp_path / "missing.sh"
    assert main([str(good), str(bad), "--trusted-uid", str(ME), "--trusted-uid", "0"]) == 1

    captured = capsys.readouterr()
    assert "ok " in captured.out  # the good path was still reported
    assert "does not exist" in captured.err


def test_cli_defaults_to_root_only(tmp_path: Path, capsys):
    _, target = _chain(tmp_path)
    # No --trusted-uid: the default trusts root alone, so a user-owned file
    # is refused. This is the shape the deployed wrapper needed.
    assert main([str(target)]) == 1
    assert "is owned by" in capsys.readouterr().err


def test_example_unit_uses_a_standalone_checker_and_complete_import_trees():
    unit = (
        Path(__file__).resolve().parents[1]
        / "examples/systemd/cathedral-sn39-policy-republisher.service"
    ).read_text()

    assert "/usr/bin/python3 -I -S /usr/local/libexec/cathedral-privileged-paths.py" in unit
    assert "-m cathedral.privileged_paths" not in unit
    assert "--resolve-symlinks" in unit
    assert "/opt/cathedral-sn39/.venv/pyvenv.cfg" in unit
    assert "/opt/cathedral-sn39/scripts/cathedral_isolated_republisher.py" in unit
    assert "--tree" in unit
    assert "/opt/cathedral-sn39/cathedral" in unit
    assert "/opt/cathedral-sn39/.venv/lib/python3.11/site-packages" in unit
    assert "/var/lib/cathedral-confidential-sn39/policy-state.sqlite" in unit
    assert "/var/lib/cathedral-confidential-sn39/policy-republication.jsonl" in unit
    assert "/var/lib/cathedral-confidential-sn39/policy-writer.lock" in unit
    assert "--creatable-file" in unit
    assert "--directory" in unit
    assert "/var/lib/cathedral-confidential-sn39/policy-history" in unit
    assert "ExecStart=/opt/cathedral-sn39/.venv/bin/python -I -S " in unit


def test_isolated_bootstrap_imports_checked_packages_without_running_pth(tmp_path: Path):
    deployment = tmp_path / "deployment"
    scripts = deployment / "scripts"
    site_packages = (
        deployment
        / ".venv"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    scripts.mkdir(parents=True)
    site_packages.mkdir(parents=True)
    source_package = deployment / "cathedral"
    source_package.mkdir()
    (source_package / "__init__.py").write_text("VALUE = 'checked source ok'\n")
    bootstrap_source = (
        Path(__file__).resolve().parents[1]
        / "scripts/cathedral_isolated_republisher.py"
    )
    bootstrap = scripts / bootstrap_source.name
    shutil.copy2(bootstrap_source, bootstrap)
    (site_packages / "required_dependency.py").write_text("VALUE = 'required import ok'\n")

    attacker_tree = tmp_path / "attacker-bootstrap-code"
    attacker_tree.mkdir()
    marker = tmp_path / "bootstrap-sitecustomize-ran"
    (attacker_tree / "sitecustomize.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(marker)!r}).write_text('unexpected execution\\n')\n"
    )
    attacker_tree.chmod(0o777)
    (site_packages / "editable-redirect.pth").write_text(
        f"{attacker_tree}\nimport sitecustomize\n"
    )
    target = scripts / "cathedral_measurement_approval.py"
    target.write_text(
        "from cathedral import VALUE as SOURCE_VALUE\n"
        "from required_dependency import VALUE\n"
        "print(VALUE + '; ' + SOURCE_VALUE)\n"
    )

    result = subprocess.run(
        [sys.executable, "-I", "-S", bootstrap],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "required import ok; checked source ok"
    assert not marker.exists()
