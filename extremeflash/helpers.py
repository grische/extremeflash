#
#     Copyright (C) 2023 Grische
#
#     This program is free software: you can redistribute it and/or modify
#     it under the terms of the GNU General Public License as published by
#     the Free Software Foundation, version 3.
#
#     This program is distributed in the hope that it will be useful,
#     but WITHOUT ANY WARRANTY; without even the implied warranty of
#     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#     GNU General Public License for more details.
#
#     You should have received a copy of the GNU General Public License
#     along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only
"""This tool allows flashing Enterasys WS-AP3710i access points fully automatically, using OpenWRT's initramfs image."""
import ipaddress
import logging
import time
from threading import Event
from typing import Optional, Union

import paramiko
import serial
import scp

DRYRUN = False
#
#  What this tool actually does
#
# 1. It will start a "TFTP server thread" on the `local_ip` on port `69`.
# 2. Starting a "serial thread" to watch and interact with the serial console.
#    First, it will interrupt the U-Boot boot process, set boot parameters for TFTP and execute the TFTP boot using
#    the initramfs-kernel.bin file.
# 3. Once the serial thread identified that the TFTP boot succeeded, an "SSH Thread" will establish an SSH connection
#    and upload the sysupgrade.bin file, run sysupgrade to install it and then terminate
# 4. In the meanwhile, the "serial thread" will watch for a message that flashing was successful and that the reboot was
#    initiated and then terminate.
# 5. In the meanwhile the main programm will wait for SSH and Serial threads to terminate and then stop the TFTP server
#
# Main Thread: .....................................................................................................
# |  |  |                                                                                           (join) /     |  \
# \  \  \_ SSH Thread: halt ....................................... resume: upload file + flash it + terminate   |   \
#  \  \                                                        (event) /                                 (join) /     \
#   \  \_ Serial Thread: Interrupt U-Boot .. Boot TFTP .. Wait for br-lan .. Wait for flash + reboot .. terminate      |
#    \                                                                                                          (stop) |
#     \_ TFTP Server Thread: ................................................................................. terminate


# TODO: these global events might need a better location
event_keep_serial_active = Event()
event_abort_ssh = Event()
event_ssh_ready = Event()


def debug_serial(string: str):
    logging.debug(string.rstrip())


def bootup_interrupt(ser: serial.Serial):
    bootlog_buffer = ""

    while event_keep_serial_active.is_set():
        time.sleep(0.01)
        if ser.in_waiting == 0:
            continue

        try:
            new_data = ser.read(ser.in_waiting).decode("ascii")
        except UnicodeDecodeError as e:
            logging.warning(f"Failed to decode serial data: {e}")
            new_data = str(ser.read(ser.in_waiting))
        bootlog_buffer += new_data

        # Only print full lines to debug output
        while "\n" in bootlog_buffer:
            line_end = bootlog_buffer.find("\n") + 1
            debug_serial(bootlog_buffer[:line_end])
            bootlog_buffer = bootlog_buffer[line_end:]

        if "Hit 'd' for diagnostics" in bootlog_buffer:
            text = b"x"  # send interrupt key
            debug_serial(bootlog_buffer)  # print remaining debug buffer
            logging.info(f"Sending interrupt key {text.decode()} to enter Boot prompt.")
            time.sleep(0.5)  # sleep 500ms
            ser.write(text)
            break


def bootup_login(ser: serial.Serial):
    while event_keep_serial_active.is_set():
        line = readline_from_serial(ser)

        if "[30s timeout]" in line:
            time.sleep(0.1)
            logging.info("Attempting to log in.")
            ser.write(b"admin\n")
            time.sleep(0.1)
            ser.write(b"new2day\n")
        elif "password: new2day" in line:
            time.sleep(0.1)  # sleep 500ms
            logging.info("Checking if login was successful.")
            break

        time.sleep(0.01)


def bootup_login_verification(ser: serial.Serial):
    prompt_string = "Boot (PRI)->"
    prompt_string_backup = "Boot (BAK)->"
    # The assertion ensures that both prompt strings have the same length, which is crucial
    # for the buffer reading logic in the loop below. If the strings had different lengths,
    # the code might not read enough bytes from the buffer to recognize either prompt or
    # might not receive enough bytes to ever continue.
    assert len(prompt_string_backup) == len(prompt_string)
    # Reading byte by byte because there is no linebreak after the prompt
    while event_keep_serial_active.is_set():
        # only read chars if there are enough bytes in wait from the buffer
        if ser.in_waiting > len(prompt_string):
            chars = ser.read(ser.in_waiting).decode("ascii")
            debug_serial(chars)

            if prompt_string in chars or prompt_string_backup in chars:
                logging.info("U-Boot login successful!")
                break

            raise RuntimeError("U-Boot login failed :((")

        time.sleep(0.01)


def is_kernel_booting(line):
    if "## Booting kernel from FIT Image at" in line:  # with U-Boot v2009.x
        # https://github.com/u-boot/u-boot/blob/f20393c5e787b3776c179d20f82a86bda124d651/common/cmd_bootm.c#L897
        return True

    # TODO: check if this works! the original check above might be called different with newer version of U-Boot:
    if "## Loading kernel from FIT Image at" in line:  # with U-Boot v2013.07 and newer
        # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/image-fit.c#L2079
        return True

    # TODO: improve this section. Mixing usages here.
    if "[    0.000000] Linux version " in line:
        # kernel is booting
        return True

    return False


def boot_wait_for_brlan(ser: serial.Serial):
    # The "eth0: Link is Up" comes up, then goes down again and then comes up again
    # It seems that the second "up" happens after eth0 has entered promiscuous mode
    # and after the bridge has been created

    while event_keep_serial_active.is_set():
        line = readline_from_serial(ser)

        if "br-lan: link becomes ready" in line or (  # OpenWRT 22.10 and earlier
            "br-lan: port" in line and "entered forwarding state" in line  # OpenWRT 24.10 and later
        ):
            logging.info("br-lan is ready.")
            time.sleep(2)  # sometimes br-lan is ready but the default IP is still not reachable
            break

        time.sleep(0.1)


def boot_set_ips(ser, new_ap_ip):
    logging.info(f"Setting new AP ip to {new_ap_ip}")
    ip_str = new_ap_ip.with_prefixlen.encode("ascii")

    write_to_serial(ser, b"\n")  # login
    write_to_serial(ser, b"ip address del 192.168.1.1 dev br-lan\n")  # remove default IP to avoid collisions
    write_to_serial(ser, b"ip address add " + ip_str + b" dev br-lan\n")
    write_to_serial(ser, b"ip -4 address show\n")
    time.sleep(0.5)


def keep_logging_until_reboot(ser: serial.Serial):
    while event_keep_serial_active.is_set():
        if ser.in_waiting > 5:
            line = readline_from_serial(ser)
            if "Upgrade completed" in line:
                logging.info("Flashing successful.")
            elif "reboot: Restarting system" in line:
                logging.info("Reboot detected. Stopping serial connection.")
                break

        time.sleep(0.05)


def write_to_serial(ser: serial.Serial, text: bytes, sleep: float = 0) -> str:
    ser.write(text)
    if sleep > 0:
        time.sleep(sleep)

    return_string = ser.readline().decode("ascii")
    debug_serial(return_string)
    return return_string


def readline_from_serial(ser: serial.Serial) -> str:
    bytestring = ser.readline()
    try:
        line = bytestring.decode("ascii")
    except UnicodeDecodeError:
        # We receive non-ascii/non-utf8 chars from the Linux kernel like 0xea or 0x90
        # after "Serial: 8250/16550 driver, 16 ports, IRQ sharing enabled"
        line = str(bytestring)
        line.replace(r"\n", "\n")

    debug_serial(line)
    return line


def start_ssh(sysupgrade_firmware_path: str, ap_ip: str = "192.168.1.1", dryrun: bool = False):
    logging.info("SSH waiting for ready signal.")
    event_ssh_ready.wait()
    if event_abort_ssh.is_set():
        return
    logging.info("SSH Starting")
    paramiko.util.log_to_file("paramiko.log")
    with paramiko.Transport(ap_ip) as transport:
        transport.connect()  # ignoring all security
        transport.auth_none("root")  # password-less login

        firmware_target_path = "/tmp/firmware.bin"

        # Basic OpenWRT only supports SCP, not SFTP
        with scp.SCPClient(transport) as scp_client:
            scp_client.put(sysupgrade_firmware_path, firmware_target_path)

        with transport.open_session() as chan:
            sysupgrade_command = "sysupgrade -n " + firmware_target_path
            if dryrun:
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


def post_cleanup(tftp_server, ssh_thread, serial_thread):
    if ssh_thread and ssh_thread.is_alive():
        logging.info("Stopping SSH thread")
        event_abort_ssh.set()
        event_ssh_ready.set()
    if serial_thread and serial_thread.is_alive():
        logging.info("Stopping Serial thread")
        event_keep_serial_active.clear()

    if tftp_server and tftp_server.is_alive():
        logging.debug("Stopping TFTP server.")
        tftp_server.stop()  # set now=True to force shutdown


def setting_up_ips(local_ip: str, ap_ip_str: Optional[str] = None):
    # IP management
    local_ip_interface = ipaddress.ip_interface(local_ip)
    local_ip_interface = ip_address_fix_prefix(local_ip_interface)
    # the ap shall have one less than the broadcast address re-using the same prefix
    ap_ip_interface = ipaddress.ip_interface(
        f"{local_ip_interface.network.broadcast_address - 1}/{local_ip_interface.network.prefixlen}"
    )

    if ap_ip_str:
        ap_ip_interface = ipaddress.ip_interface(ap_ip_str)
        ap_ip_interface = ip_address_fix_prefix(ap_ip_interface)

    if local_ip_interface.ip == ap_ip_interface.ip:
        raise ValueError(
            f"Local IP {local_ip_interface.with_prefixlen} and AP IP {ap_ip_interface.with_prefixlen} are identical."
        )

    # TODO: Check that AP and Local ip can reach each other: ap_ip_str.network.overlaps(...) maybe?
    return ap_ip_interface, local_ip_interface


def ip_address_fix_prefix(
    ip_interface: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface],
) -> Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface]:
    if ip_interface.network.prefixlen == ip_interface.network.max_prefixlen:  # probably forgot to specify network
        if isinstance(ip_interface, ipaddress.IPv4Interface):
            new_prefix = 24
        elif isinstance(ip_interface, ipaddress.IPv6Interface):
            new_prefix = 64
        else:
            raise ValueError(f"Invalid IP interface received {type(ip_interface)}")

        logging.warning(
            "Received too small network prefix %s for %s. Assuming %s/%s.",
            ip_interface.network.prefixlen,
            ip_interface,
            ip_interface.ip,
            new_prefix,
        )
        ip_interface = ipaddress.ip_interface(f"{ip_interface.ip}/{new_prefix}")
    elif ip_interface.network.prefixlen == ip_interface.network.max_prefixlen - 1:  # we need at least two IPs+broadcast
        raise ValueError(f"Too small IP prefix for {ip_interface}. Requires space for at least two IPs + broadcast.")

    return ip_interface
