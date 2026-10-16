from __future__ import annotations

import os
import sys
from pathlib import Path
from subprocess import list2cmdline
from typing import TYPE_CHECKING, Final
from unittest.mock import MagicMock

import pytest

from python_discovery import DiskCache, PythonInfo
from python_discovery._cached_py_info import _get_from_cache, _get_via_file_cache, _run_subprocess

if TYPE_CHECKING:
    from pytest_mock import MockerFixture

LAUNCHER: Final[str] = r"C:\Program Files\Python Launcher\py.exe"
ARGS: Final[str] = '-3.11 --config "settings folder\\python.json"'
SELECTED: Final[str] = r"C:\Python311\python.exe"


@pytest.fixture
def popen(mocker: MockerFixture) -> MagicMock:
    start, end = "a" * 32, "b" * 32
    mocker.patch("python_discovery._cached_py_info.gen_cookie", side_effect=[start, end])
    info = PythonInfo()
    info.executable = SELECTED
    out = f"{start[::-1]}{info.to_json()}{end[::-1]}"
    process = MagicMock(**{"communicate.return_value": (out, ""), "returncode": 0})
    return mocker.patch("python_discovery._cached_py_info.Popen", return_value=process)


def test_executable_args_precede_query_script(popen: MagicMock) -> None:
    _run_subprocess(PythonInfo, LAUNCHER, dict(os.environ), ARGS)

    cmd = popen.call_args.args[0]
    assert cmd.startswith(f"{list2cmdline([LAUNCHER])} {ARGS} ")
    assert cmd.endswith(f" {'a' * 32} {'b' * 32}")


@pytest.mark.usefixtures("popen")
def test_executable_args_report_the_selected_interpreter() -> None:
    failure, result = _run_subprocess(PythonInfo, LAUNCHER, dict(os.environ), ARGS)

    assert failure is None
    assert result is not None
    assert result.executable == SELECTED


def test_executable_args_disk_entry_not_reused_without_args(tmp_path: Path, mocker: MockerFixture) -> None:
    with_args, without_args = PythonInfo(), PythonInfo()
    with_args.executable = "selected"
    query = mocker.patch(
        "python_discovery._cached_py_info._run_subprocess",
        side_effect=[(None, with_args), (None, without_args)],
    )
    cache, path, env = DiskCache(tmp_path), Path(sys.executable), dict(os.environ)
    _get_via_file_cache(PythonInfo, cache, path, sys.executable, env, executable_args=ARGS)

    result = _get_via_file_cache(PythonInfo, cache, path, sys.executable, env)

    assert result is without_args
    assert query.call_count == 2


def test_executable_args_memory_cache_keyed_by_args(tmp_path: Path, mocker: MockerFixture) -> None:
    mocker.patch.dict("python_discovery._cached_py_info._CACHE", clear=True)
    first, second = PythonInfo(), PythonInfo()
    query = mocker.patch("python_discovery._cached_py_info._get_via_file_cache", side_effect=[first, second])
    cache, env = DiskCache(tmp_path), dict(os.environ)

    results = [
        _get_from_cache(PythonInfo, cache, LAUNCHER, env, ignore_cache=False, executable_args=args)
        for args in ("-3.11", "-3.12", "-3.11")
    ]

    assert results == [first, second, first]
    assert query.call_count == 2
