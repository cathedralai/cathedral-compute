#!/usr/bin/env python3
"""Run the privileged policy republisher without Python site initialization.

The systemd unit executes this bootstrap with ``-I -S``. It adds the checked
venv package root without processing site hooks, loads the checked Cathedral
package by exact filename, then transfers control to the measurement-approval
program.
"""

from __future__ import annotations

import importlib.util
import runpy
import sys
from pathlib import Path


def main() -> int:
    if not sys.flags.isolated or not sys.flags.no_site:
        raise SystemExit("isolated republisher bootstrap requires Python -I -S")

    deployment_root = Path(__file__).resolve().parents[1]
    site_packages = (
        deployment_root
        / ".venv"
        / "lib"
        / f"python{sys.version_info.major}.{sys.version_info.minor}"
        / "site-packages"
    )
    source_package = deployment_root / "cathedral"
    target = deployment_root / "scripts" / "cathedral_measurement_approval.py"
    if not site_packages.is_dir():
        raise SystemExit(
            f"isolated republisher requires checked site-packages at {site_packages}"
        )
    if not target.is_file() or target.is_symlink():
        raise SystemExit(
            f"isolated republisher target must be a regular non-symlink file: {target}"
        )
    package_init = source_package / "__init__.py"
    if not package_init.is_file() or package_init.is_symlink():
        raise SystemExit(
            f"isolated republisher package must have a regular __init__.py: {package_init}"
        )

    # Do not use site.addsitedir. It executes .pth files and follows their
    # external path redirects. The site tree is checked by ExecStartPre.
    sys.path.insert(0, str(site_packages))
    specification = importlib.util.spec_from_file_location(
        "cathedral",
        package_init,
        submodule_search_locations=[str(source_package)],
    )
    if specification is None or specification.loader is None:
        raise SystemExit("isolated republisher could not load the checked Cathedral package")
    package = importlib.util.module_from_spec(specification)
    sys.modules["cathedral"] = package
    specification.loader.exec_module(package)
    sys.argv = [str(target), *sys.argv[1:]]
    runpy.run_path(str(target), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
