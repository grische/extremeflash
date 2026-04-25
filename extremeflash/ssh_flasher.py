"""SSH-based sysupgrade upload + remote-exec.

Free-function `run_ssh_flash(session, sysupgrade_firmware_path, ap_ip)` does the
work; the SSH thread's state (ssh_ready / ssh_abort / dryrun / connect-timeout
attributes) lives on the FlashSession passed in. Not a class — adding a wrapper
class here would carry no state and no behavior beyond what FlashSession already
provides.

Cancel coverage (documented limitation): only the TCP-connect phase is
cancellable via `socket.create_connection`'s timeout. Once the socket is handed
to paramiko, `transport.connect()` (banner exchange), `transport.auth_none()`,
and `scp_client.put()` are blocking calls without paramiko-side cancel hooks.
The daemon-flag normalization on FlashSession's threads ensures interpreter
exit doesn't wedge on these.
"""

import logging
import socket
from typing import TYPE_CHECKING

import paramiko
import scp

if TYPE_CHECKING:
    from .flash_session import FlashSession


def run_ssh_flash(session: "FlashSession", sysupgrade_firmware_path: str, ap_ip: str) -> None:
    """Wait for the serial thread's ready signal, then upload sysupgrade.bin via SCP and run it."""
    logging.info("SSH waiting for ready signal.")
    session.ssh_ready.wait()
    if session.ssh_abort.is_set():
        return
    logging.info("SSH Starting")

    sock = socket.create_connection((ap_ip, 22), timeout=session.ssh_connect_timeout)
    with paramiko.Transport(sock) as transport:
        transport.banner_timeout = session.ssh_banner_timeout
        transport.connect()  # ignoring all security
        transport.auth_none("root")  # password-less login

        if session.ssh_abort.is_set():
            return

        firmware_target_path = "/tmp/firmware.bin"

        # Basic OpenWRT only supports SCP, not SFTP
        with scp.SCPClient(transport) as scp_client:
            scp_client.put(sysupgrade_firmware_path, firmware_target_path)

        if session.ssh_abort.is_set():
            return

        with transport.open_session() as chan:
            sysupgrade_command = "sysupgrade -n " + firmware_target_path
            if session.dryrun:
                logging.info("dryrun: running sysupgrade with test and rebooting")
                sysupgrade_command = sysupgrade_command.replace("sysupgrade", "sysupgrade --test")
                sysupgrade_command = sysupgrade_command + " && reboot"
            logging.debug(f"Running remote: {sysupgrade_command}")
            stdout = chan.makefile("r")
            stderr = chan.makefile_stderr("r")

            chan.exec_command(sysupgrade_command)
            sysupgrade_stdout = stdout.read().decode()
            sysupgrade_stderr = stderr.read().decode()
            logging.debug("sysupgrade stdout: %s", sysupgrade_stdout)
            logging.debug("sysupgrade stderr: %s", sysupgrade_stderr)

            # sysupgrade prints to stderr by default
            if "Commencing upgrade" in sysupgrade_stderr:
                logging.info("Flashing in progress...")
        logging.debug("Closing SSH session.")
