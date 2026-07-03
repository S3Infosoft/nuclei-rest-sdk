"""Tests for binary discovery."""

import os
from unittest.mock import patch

import pytest

from nuclei_rest_sdk._binary import find_binary
from nuclei_rest_sdk.exceptions import NucleiNotFoundError


def test_find_binary_with_explicit_path(tmp_path) -> None:
    binary = tmp_path / "nuclei"
    binary.write_text("")
    binary.chmod(0o755)
    assert find_binary(str(binary)) == str(binary)


@patch.dict(os.environ, {"NUCLEI_BINARY": "/custom/nuclei"})
@patch("nuclei_rest_sdk._binary._resolve_candidate", return_value="/custom/nuclei")
def test_find_binary_from_env(_mock_resolve) -> None:
    assert find_binary() == "/custom/nuclei"


@patch("nuclei_rest_sdk._binary.shutil.which", return_value=None)
@patch("nuclei_rest_sdk._binary._resolve_candidate", return_value=None)
def test_find_binary_raises_when_missing(_mock_resolve, _mock_which) -> None:
    with pytest.raises(NucleiNotFoundError):
        find_binary()
