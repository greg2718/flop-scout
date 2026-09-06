"""Tests may use fixtures, never live network or the production state directory."""
import socket
import os
import tempfile

# Set before importing Scout, whose default paths are bound at module import.
_TEST_STATE = tempfile.TemporaryDirectory(prefix="scout-suite-")
os.environ["FLOP_SCOUT_STATE_DIR"] = _TEST_STATE.name
import pytest


@pytest.fixture(autouse=True)
def no_live_network(monkeypatch):
    def blocked(*args, **kwargs):
        raise AssertionError('Live network access is forbidden in tests; supply a captured fixture')
    monkeypatch.setattr(socket.socket,'connect',blocked)
    monkeypatch.setattr(socket.socket,'connect_ex',blocked)
