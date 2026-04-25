"""FlashSession — owns one flash run's lifecycle, threading, and cancellation.

Replaces the three module-level threading.Events plus the procedural `main()` body
in `ws.py` with a single object whose `run()` orchestrates the TFTP server, the
serial conversation thread, and the SSH/sysupgrade thread, and tears them down
cleanly via a `with`-managed `TftpServer` context.

Cancellation model:
  - `cancel`: set when serial-side work should stop (TFTP-watch loops, login waits,
    kernel-boot polling). Replaces the previous `event_keep_serial_active` global,
    inverted: `cancel.is_set() == True` means stop.
  - `ssh_ready`: set by the serial thread when the AP is up and reachable; the SSH
    thread blocks on this until it fires.
  - `ssh_abort`: paired with `ssh_ready` for the cancel hand-off. Producer order
    matters: set `ssh_abort` *before* `ssh_ready` so a consumer woken by `ready`
    sees `abort.is_set() == True` on its check.

Failure-propagation model:
  - Each thread wrapper records its non-cancel exception via `_record_failure`,
    which uses a lock to enforce first-failure-wins. Cancel-driven OperationCancelled
    in the serial thread is *swallowed* so the *original* failure (typically on the
    SSH side) propagates as the CLI's exit cause.
  - `run()` re-raises whichever failure was recorded so the CLI exits non-zero.
"""

import logging
import pathlib
import threading
from typing import Optional

import serial

from .exceptions import FlashError, OperationCancelled
from .ip_planning import setting_up_ips
from .serial_console import (
    boot_set_ips,
    boot_wait_for_brlan,
    bootup_interrupt,
    bootup_login,
    bootup_login_verification,
    keep_logging_until_reboot,
)
from .ssh_flasher import run_ssh_flash
from .tftp_server import TftpServer
from .ws import boot_via_tftp, bootup_set_boot_openwrt, wait_for_ramboot


class FlashSession:
    """One flash run. All cancel state, failure state, and lifecycle live here."""

    # Provisional defaults; tune in PR 3's hardware verification if AP boot-to-SSH
    # exceeds the 25 s threshold the plan calls out.
    DEFAULT_SSH_CONNECT_TIMEOUT = 30.0
    DEFAULT_SSH_BANNER_TIMEOUT = 15.0

    def __init__(
        self,
        serial_port: str,
        initramfs_path_str: str,
        sysupgrade_path_str: str,
        local_ip: str,
        ap_ip: Optional[str] = None,
        dryrun: bool = False,
        ssh_connect_timeout: float = DEFAULT_SSH_CONNECT_TIMEOUT,
        ssh_banner_timeout: float = DEFAULT_SSH_BANNER_TIMEOUT,
    ):
        self.serial_port = serial_port
        self.initramfs_path = pathlib.Path(initramfs_path_str)
        self.sysupgrade_path = pathlib.Path(sysupgrade_path_str)
        self.dryrun = dryrun
        self.ssh_connect_timeout = ssh_connect_timeout
        self.ssh_banner_timeout = ssh_banner_timeout

        # IP plan computed eagerly so misconfigurations surface before any thread starts.
        self.ap_ip_interface, self.local_ip_interface = setting_up_ips(local_ip, ap_ip)

        self.cancel = threading.Event()
        self.ssh_ready = threading.Event()
        self.ssh_abort = threading.Event()

        self.serial_failure: Optional[BaseException] = None
        self.ssh_failure: Optional[BaseException] = None
        self._failure_lock = threading.Lock()

    def cancel_ssh(self) -> None:
        """Wake the SSH thread and tell it to abort.

        Producer order: set ssh_abort *before* ssh_ready. The consumer in
        `run_ssh_flash` does `ssh_ready.wait(); if ssh_abort.is_set(): return`,
        so abort must be true at the moment ready releases the wait.
        """
        self.ssh_abort.set()
        self.ssh_ready.set()

    def cancel_run(self) -> None:
        """Signal the entire session to wind down. Sets `cancel` (serial loops fall
        out at their next check) and signals the SSH side to abort. TFTP cleanup
        runs from `run()`'s `with TftpServer` block on exit, *not* here — the
        serial thread may still be using the TFTP server for a few moments after
        cancel.set() while it unwinds its current `read*` call."""
        self.cancel.set()
        self.cancel_ssh()

    def _record_failure(self, attr_name: str, exc: BaseException) -> None:
        """First-failure-wins: only stores `exc` if neither serial_failure nor
        ssh_failure is already populated. Lock makes the check-and-set atomic."""
        with self._failure_lock:
            if self.serial_failure is None and self.ssh_failure is None:
                setattr(self, attr_name, exc)

    def _serial_thread_target(self) -> None:
        try:
            self._run_serial()
        except OperationCancelled:
            # Cancel-driven; some other thread is the real failure source. Swallow.
            if self.cancel.is_set():
                return
            # OperationCancelled raised without the cancel event being set is a real bug.
            raise
        except BaseException as exc:  # noqa: BLE001 — we're a thread wrapper
            self._record_failure("serial_failure", exc)
            self.cancel_ssh()
            raise

    def _ssh_thread_target(self) -> None:
        try:
            run_ssh_flash(self, str(self.sysupgrade_path), str(self.ap_ip_interface.ip))
        except BaseException as exc:  # noqa: BLE001 — we're a thread wrapper
            self._record_failure("ssh_failure", exc)
            self.cancel_run()
            raise

    def _run_serial(self) -> None:
        # Note: the serial port is opened inside the worker thread so its lifetime
        # matches the thread's. Pre-PR-3 this lived in start_tftp_boot_via_serial.
        # PR 4a lowered timeout from 30 s to 1 s so read_until's cancel-check
        # between readline() cycles fires within ≤ 1 s on a silent wire.
        with serial.Serial(port=self.serial_port, baudrate=115200, timeout=1) as ser:
            logging.info(f"Starting to connect to serial port {ser.name}")

            bootup_interrupt(ser, self.cancel)
            bootup_login(ser, self.cancel)
            bootup_login_verification(ser, self.cancel)
            model = bootup_set_boot_openwrt(ser, self.cancel, self.dryrun)
            boot_via_tftp(
                ser, self.local_ip_interface, self.initramfs_path.name, self.ap_ip_interface, model, self.cancel
            )
            wait_for_ramboot(ser, self.cancel)
            boot_wait_for_brlan(ser, self.cancel)
            boot_set_ips(ser, self.ap_ip_interface)
            self.ssh_ready.set()
            keep_logging_until_reboot(ser, self.cancel)

    def run(self) -> None:
        """Execute the flash. Blocks until both threads complete or fail.

        Raises whichever of (serial_failure, ssh_failure) was recorded first;
        cancel-driven OperationCancelled is swallowed so the *original* cause
        (typically SSH-side) is what surfaces.
        """
        with TftpServer(str(self.initramfs_path), listenip=str(self.local_ip_interface.ip)):
            # Both threads daemon=True so an unrecoverable hang in either doesn't
            # wedge interpreter shutdown.
            serial_thread = threading.Thread(target=self._serial_thread_target, daemon=True)
            ssh_thread = threading.Thread(target=self._ssh_thread_target, daemon=True)

            logging.debug("Starting serial thread")
            serial_thread.start()
            logging.debug("Starting ssh thread")
            ssh_thread.start()

            try:
                logging.debug("Waiting for ssh thread")
                # Polling join() so KeyboardInterrupt can interrupt the wait.
                while ssh_thread.is_alive():
                    ssh_thread.join(5)

                logging.debug("Waiting for serial thread")
                while serial_thread.is_alive():
                    serial_thread.join(5)

                logging.info(
                    "All steps finished. Give the AP some time to reboot and then access it on http://192.168.1.1"
                )
            except (KeyboardInterrupt, SystemExit, SystemError):
                logging.warning("Aborting main process")
                self.cancel_run()
                # Wait briefly for threads to acknowledge cancel, then exit.
                serial_thread.join(2)
                ssh_thread.join(2)

        # First-failure-wins: report whichever was recorded first.
        if self.serial_failure is not None:
            raise self.serial_failure
        if self.ssh_failure is not None:
            raise self.ssh_failure


def main(
    serial_port: str,
    initramfs_path_str: str,
    sysupgrade_path_str: str,
    local_ip: str,
    ap_ip: Optional[str] = None,
    dryrun: bool = False,
) -> None:
    """Backwards-compatible entry-point preserved for `__main__.py`."""
    session = FlashSession(serial_port, initramfs_path_str, sysupgrade_path_str, local_ip, ap_ip, dryrun)
    try:
        session.run()
    except FlashError as exc:
        # Surface as a CLI error without a stack trace for the expected "wrong file" case.
        logging.error(str(exc))
        raise SystemExit(1) from exc
