from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
from typing_extensions import Self


@pytest.mark.usefixtures("_mock_registry")
def test_pep514_discovers_interpreters() -> None:
    from python_discovery._windows._pep514 import discover_pythons

    interpreters = list(discover_pythons())
    assert len(interpreters) == 12
    companies = {i[0] for i in interpreters}
    assert "ContinuumAnalytics" in companies
    assert "PythonCore" in companies
    assert "CompanyA" in companies


@pytest.mark.usefixtures("_mock_registry")
def test_pep514_parse_functions() -> None:
    from python_discovery._windows._pep514 import parse_arch, parse_version

    assert parse_arch("64bit") == 64
    assert parse_arch("32bit") == 32
    with pytest.raises(ValueError, match="invalid format"):
        parse_arch("magic")
    with pytest.raises(ValueError, match="arch is not string"):
        parse_arch(100)

    assert parse_version("3.12") == (3, 12, None)
    assert parse_version("3.12.1") == (3, 12, 1)
    assert parse_version("3") == (3, None, None)
    with pytest.raises(ValueError, match="invalid format"):
        parse_version("3.X")
    with pytest.raises(ValueError, match="version is not string"):
        parse_version(2778)


@pytest.mark.skipif(sys.platform != "win32", reason="path joining differs on POSIX")
@pytest.mark.usefixtures("_mock_registry")
def test_pep514() -> None:
    from python_discovery._windows._pep514 import discover_pythons

    interpreters = list(discover_pythons())
    assert interpreters == [
        ("ContinuumAnalytics", 3, 10, 32, False, "C:\\Users\\user\\Miniconda3\\python.exe", None),
        ("ContinuumAnalytics", 3, 10, 64, False, "C:\\Users\\user\\Miniconda3-64\\python.exe", None),
        (
            "PythonCore",
            3,
            9,
            64,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python39\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            9,
            64,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python39\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            8,
            64,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python38\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            9,
            64,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python39\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            10,
            32,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python310-32\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            12,
            64,
            False,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python312\\python.exe",
            None,
        ),
        (
            "PythonCore",
            3,
            13,
            64,
            True,
            "C:\\Users\\user\\AppData\\Local\\Programs\\Python\\Python313\\python3.13t.exe",
            None,
        ),
        ("CompanyA", 3, 6, 64, False, "Z:\\CompanyA\\Python\\3.6\\python.exe", None),
        ("PythonCore", 2, 7, 64, False, "C:\\Python27\\python.exe", None),
        ("PythonCore", 3, 7, 64, False, "C:\\Python37\\python.exe", None),
    ]


@pytest.mark.skipif(sys.platform != "win32", reason="path joining differs on POSIX")
@pytest.mark.usefixtures("_mock_registry")
def test_pep514_run(capsys: pytest.CaptureFixture[str], caplog: pytest.LogCaptureFixture) -> None:
    from python_discovery._windows import _pep514 as pep514

    pep514._run()
    out, err = capsys.readouterr()
    py = r"C:\Users\user\AppData\Local\Programs\Python"
    expected = textwrap.dedent(
        rf"""
    ('CompanyA', 3, 6, 64, False, 'Z:\\CompanyA\\Python\\3.6\\python.exe', None)
    ('ContinuumAnalytics', 3, 10, 32, False, 'C:\\Users\\user\\Miniconda3\\python.exe', None)
    ('ContinuumAnalytics', 3, 10, 64, False, 'C:\\Users\\user\\Miniconda3-64\\python.exe', None)
    ('PythonCore', 2, 7, 64, False, 'C:\\Python27\\python.exe', None)
    ('PythonCore', 3, 10, 32, False, '{py}\\Python310-32\\python.exe', None)
    ('PythonCore', 3, 12, 64, False, '{py}\\Python312\\python.exe', None)
    ('PythonCore', 3, 13, 64, True, '{py}\\Python313\\python3.13t.exe', None)
    ('PythonCore', 3, 7, 64, False, 'C:\\Python37\\python.exe', None)
    ('PythonCore', 3, 8, 64, False, '{py}\\Python38\\python.exe', None)
    ('PythonCore', 3, 9, 64, False, '{py}\\Python39\\python.exe', None)
    ('PythonCore', 3, 9, 64, False, '{py}\\Python39\\python.exe', None)
    ('PythonCore', 3, 9, 64, False, '{py}\\Python39\\python.exe', None)
    """,
    ).strip()
    assert out.strip() == expected
    assert not err
    prefix = "PEP-514 violation in Windows Registry at "
    expected_logs = [
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.1/SysArchitecture error: invalid format magic",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.2/SysArchitecture error: arch is not string: 100",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.3 error: no ExecutablePath or default for it",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.3 error: could not load exe with value None",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.11/InstallPath error: missing",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.12/SysVersion error: invalid format magic",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.X/SysVersion error: version is not string: 2778",
        f"{prefix}HKEY_CURRENT_USER/PythonCore/3.X error: invalid format 3.X",
    ]
    assert caplog.messages == expected_logs


@pytest.mark.usefixtures("_mock_registry")
@pytest.mark.parametrize(
    ("registered_args", "expected_args"),
    [
        ('-3.11 --config "settings folder\\python.json"', '-3.11 --config "settings folder\\python.json"'),
        ("", None),
        ("   ", None),
        (42, False),
    ],
)
def test_pep514_loads_executable_arguments(
    monkeypatch: pytest.MonkeyPatch, registered_args: object, expected_args: str | bool | None
) -> None:
    from python_discovery._windows import _pep514 as pep514

    class Key:
        def __enter__(self) -> Self:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    monkeypatch.setattr(pep514.winreg, "OpenKeyEx", lambda *_args: Key())
    monkeypatch.setattr(pep514, "_resolve_exe", lambda *_args: r"C:\PythonLauncher\py.exe")
    monkeypatch.setattr(pep514.os.path, "exists", lambda _path: True)
    monkeypatch.setattr(
        pep514,
        "get_value",
        lambda _key, name: registered_args if name == "ExecutableArguments" else None,
    )

    result = pep514.load_exe("HKCU", "PythonCore", object(), "3.11")

    if expected_args is False:
        assert result is None
    else:
        assert result == (r"C:\PythonLauncher\py.exe", expected_args)


@pytest.mark.skipif(sys.platform != "win32", reason="requires the Windows Python launcher")
def test_launcher_registry_arguments_return_an_executable_for_selected_python(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from python_discovery import DiskCache, PythonSpec
    from python_discovery._windows import _propose

    launcher = shutil.which("py")
    if launcher is None:
        # pytest accepts a reason, but ty's bundled Python 3.9 pytest signature is stale.
        pytest.skip("the Windows Python launcher is unavailable")  # ty: ignore[too-many-positional-arguments]
    selector = "-3.11"
    script = (
        "import json, struct, sys; print(json.dumps((sys.executable, *sys.version_info[:2], struct.calcsize('P') * 8)))"
    )
    try:
        selected = subprocess.run(
            [launcher, selector, "-c", script],
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
    except subprocess.CalledProcessError:
        # pytest accepts a reason, but ty's bundled Python 3.9 pytest signature is stale.
        pytest.skip(f"the Windows launcher cannot select {selector}")  # ty: ignore[too-many-positional-arguments]
    selected_exe, major, minor, arch = json.loads(selected)
    registry_row = ("PythonCore", major, minor, arch, False, launcher, selector)
    monkeypatch.setattr(_propose, "discover_pythons", lambda: iter([registry_row]))

    spec = PythonSpec.from_string_spec(f"python{major}.{minor}")
    info = next(_propose.propose_interpreters(spec, DiskCache(tmp_path), dict(os.environ)))
    assert info.version_info[:2] == (major, minor)
    assert Path(info.executable).samefile(selected_exe)

    actual = subprocess.run(
        [info.executable, "-c", "import sys; print(*sys.version_info[:2])"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    assert actual == f"{major} {minor}"
