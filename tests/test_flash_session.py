"""Unit tests for `FlashSession` lifecycle and failure-propagation rules.

Focus areas:
  - cancel_ssh ordering (set ssh_abort *before* ssh_ready)
  - first-failure-wins via _failure_lock
  - swallow rule: OperationCancelled during cancel-driven shutdown does not poison
    serial_failure
  - narrow swallow rule: a non-OperationCancelled exception (e.g. RuntimeError)
    raised during a cancelled run still poisons serial_failure
  - os._exit replacement: wait_for_ramboot raising FlashError propagates cleanly
"""

from unittest.mock import MagicMock

import pytest

from extremeflash import flash_session as fs_module
from extremeflash.exceptions import FlashError, OperationCancelled
from extremeflash.flash_session import FlashSession


@pytest.fixture
def session(monkeypatch):
    """A FlashSession with `setting_up_ips` short-circuited so we can construct without args."""
    monkeypatch.setattr(
        "extremeflash.flash_session.setting_up_ips",
        lambda local, ap=None: (
            __import__("ipaddress").ip_interface("192.168.1.254/24"),
            __import__("ipaddress").ip_interface("192.168.1.70/24"),
        ),
    )
    return FlashSession(
        serial_port="/dev/null",
        initramfs_path_str="/tmp/initramfs",
        sysupgrade_path_str="/tmp/sysupgrade",
        local_ip="192.168.1.70/24",
    )


def test_cancel_ssh_sets_abort_before_ready(session):
    """Producer order is load-bearing: consumer waits on ssh_ready then checks
    ssh_abort. If `ready.set()` ran first, a context switch could let the
    consumer wake and miss `abort`."""
    seen = []

    def record_set(name):
        original = getattr(session, name)

        def wrapped():
            seen.append(name)
            original.set.__wrapped__ = None  # marker for the closure
            original.set()

        return wrapped

    abort_set = MagicMock(side_effect=lambda: seen.append("ssh_abort"))
    ready_set = MagicMock(side_effect=lambda: seen.append("ssh_ready"))
    session.ssh_abort.set = abort_set
    session.ssh_ready.set = ready_set

    session.cancel_ssh()

    assert seen == ["ssh_abort", "ssh_ready"], "ssh_abort must be set before ssh_ready"


def test_cancel_run_signals_cancel_and_ssh_but_not_tftp_stop(session):
    """cancel_run must set cancel + ssh_abort + ssh_ready. tftp_server.stop is
    deferred to run()'s `with` exit so the still-running serial thread retains
    its TFTP server through the unwind."""
    session.cancel_run()
    assert session.cancel.is_set()
    assert session.ssh_abort.is_set()
    assert session.ssh_ready.is_set()


def test_first_failure_wins_serial_then_ssh(session):
    """Once serial_failure is set, ssh_failure stays None (first to acquire the lock wins)."""
    serial_exc = RuntimeError("serial died first")
    session._record_failure("serial_failure", serial_exc)
    session._record_failure("ssh_failure", RuntimeError("ssh died second"))
    assert session.serial_failure is serial_exc
    assert session.ssh_failure is None


def test_first_failure_wins_ssh_then_serial(session):
    """Symmetric: SSH-first ordering also holds."""
    ssh_exc = RuntimeError("ssh died first")
    session._record_failure("ssh_failure", ssh_exc)
    session._record_failure("serial_failure", RuntimeError("serial died second"))
    assert session.ssh_failure is ssh_exc
    assert session.serial_failure is None


def test_serial_thread_swallows_cancel_driven_operation_cancelled(session):
    """OperationCancelled raised while cancel.is_set() is the *cancel-driven* path:
    the SSH thread (or external caller) caused the cancel, and that side's failure
    is the one we want to surface. The serial wrapper must not poison serial_failure."""
    session.cancel.set()  # simulate: another thread already triggered cancellation

    def raising_run_serial():
        raise OperationCancelled("read aborted by cancel")

    session._run_serial = raising_run_serial
    session._serial_thread_target()  # must not raise out

    assert session.serial_failure is None, (
        "OperationCancelled during a cancel-driven shutdown must not be recorded as the failure cause"
    )


def test_serial_thread_records_runtime_error_during_cancel(session):
    """Narrow swallow rule: only OperationCancelled is swallowed. A RuntimeError
    (e.g., 'Maximum TFTP retries reached' from wait_for_ramboot at ws.py:151)
    raised during a cancelled run must still poison serial_failure."""
    session.cancel.set()

    def raising_run_serial():
        raise RuntimeError("Maximum TFTP retries reached. Aborting")

    session._run_serial = raising_run_serial

    with pytest.raises(RuntimeError, match="Maximum TFTP retries"):
        session._serial_thread_target()

    assert isinstance(session.serial_failure, RuntimeError)
    assert "Maximum TFTP retries" in str(session.serial_failure)


def test_serial_thread_records_flash_error_and_cancels_ssh(session):
    """The os._exit(1) replacement: wait_for_ramboot raises FlashError on bad
    initramfs. The wrapper must store it on serial_failure AND signal SSH to
    abort (otherwise SSH could hang waiting for ssh_ready that never sets)."""

    def raising_run_serial():
        raise FlashError("Unable to boot initramfs file. Check you provided the correct file. Aborting.")

    session._run_serial = raising_run_serial

    with pytest.raises(FlashError):
        session._serial_thread_target()

    assert isinstance(session.serial_failure, FlashError)
    assert session.ssh_abort.is_set(), "Serial-side fatal error must wake the SSH thread to abort"
    assert session.ssh_ready.is_set()


def test_ssh_thread_records_failure_and_cancels_run(session):
    """Symmetrical: an SSH-side failure (e.g., paramiko connect failure) records
    ssh_failure and calls cancel_run() to bring the serial thread down."""
    ssh_exc = RuntimeError("paramiko refused")

    def raising_run_ssh():
        raise ssh_exc

    # Simulate run_ssh_flash raising
    original = fs_module.run_ssh_flash
    fs_module.run_ssh_flash = lambda *_args, **_kwargs: raising_run_ssh()
    try:
        with pytest.raises(RuntimeError, match="paramiko refused"):
            session._ssh_thread_target()
    finally:
        fs_module.run_ssh_flash = original

    assert session.ssh_failure is ssh_exc
    assert session.cancel.is_set(), "ssh failure must trigger session-wide cancel"
    assert session.ssh_abort.is_set()
    assert session.ssh_ready.is_set()
