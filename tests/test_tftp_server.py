"""Tests for the `TftpServer` wrapper's PR 3 additions: __enter__ + stop(now=...)."""

from unittest.mock import MagicMock

import pytest

from extremeflash.tftp_server import TftpServer


@pytest.fixture
def fake_initramfs(tmp_path):
    p = tmp_path / "initramfs.bin"
    p.write_bytes(b"fake firmware")
    return p


def test_stop_plumbs_now_true(fake_initramfs, monkeypatch):
    """stop(now=True) must reach the underlying tftpy.TftpServer.stop(now=True)."""
    server = TftpServer(str(fake_initramfs))
    underlying_stop = MagicMock()
    monkeypatch.setattr(server.tftp_server, "stop", underlying_stop)
    monkeypatch.setattr(server, "is_alive", lambda: True)
    server.stop(now=True)
    underlying_stop.assert_called_once_with(now=True)


def test_stop_default_is_now_false(fake_initramfs, monkeypatch):
    """Calling stop() with no args must default to now=False (graceful shutdown)."""
    server = TftpServer(str(fake_initramfs))
    underlying_stop = MagicMock()
    monkeypatch.setattr(server.tftp_server, "stop", underlying_stop)
    monkeypatch.setattr(server, "is_alive", lambda: True)
    server.stop()
    underlying_stop.assert_called_once_with(now=False)


def test_context_manager_entry_returns_self(fake_initramfs, monkeypatch):
    """`with TftpServer(...) as t:` must yield the TftpServer instance."""
    monkeypatch.setattr(TftpServer, "start", lambda self: None)
    monkeypatch.setattr(TftpServer, "stop", lambda self, now=False: None)
    server = TftpServer(str(fake_initramfs))
    monkeypatch.setattr(server.tmpdir, "cleanup", lambda: None)
    with server as entered:
        assert entered is server


def test_context_manager_exit_force_stops_and_cleans_tmpdir(fake_initramfs, monkeypatch):
    """__exit__ must call stop(now=True) and tmpdir.cleanup() — the latter is
    the path that ensures TemporaryDirectory.cleanup() actually runs (pre-PR-3
    it never did because nothing used `with`)."""
    monkeypatch.setattr(TftpServer, "start", lambda self: None)
    server = TftpServer(str(fake_initramfs))

    stop_call = MagicMock()
    cleanup_call = MagicMock()
    monkeypatch.setattr(server, "stop", stop_call)
    monkeypatch.setattr(server.tmpdir, "cleanup", cleanup_call)

    with server:
        pass

    stop_call.assert_called_once_with(now=True)
    cleanup_call.assert_called_once_with()
