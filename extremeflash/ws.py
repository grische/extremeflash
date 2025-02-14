#!/usr/bin/env python3
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
"""This tool allows flashing Enterasys WS-AP3825i access points fully automatically, using OpenWRT's initramfs image."""
import ipaddress
import logging
import pathlib
import re
import time
from threading import Thread
from typing import Optional

import serial # pyserial

from .tftp_server import TftpServer

from .helpers import (
    boot_set_ips,
    boot_wait_for_brlan,
    bootup_interrupt,
    bootup_login,
    bootup_login_verification,
    debug_serial,
    is_kernel_booting,
    keep_logging_until_reboot,
    post_cleanup,
    readline_from_serial,
    setting_up_ips,
    start_ssh,
    write_to_serial,
    event_keep_serial_active,
    event_ssh_ready,
)
from extremeflash import helpers

SUPPORTED_DEVICES = [
    "AP3705i",
    "AP3710i",
    "AP3715i",
    "AP3825i",
    "AP3915i",
]

#  See .helpers file for implementation details


def bootup_set_boot_openwrt(
        ser: serial.Serial,
        dryrun: bool = False,
    ) -> str:
    #    if not event_keep_serial_active.is_set():
    #        return ""
    ser.write(b"printenv\n")
    time.sleep(1)
    printenv_return = ser.read(ser.in_waiting).decode("ascii")
    debug_serial(printenv_return)
    model = re.search(r"MODEL=(.*)\r\n", printenv_return)

    if model not in SUPPORTED_DEVICES:
        model = re.search(r"MODEL=(.*)\r\n", printenv_return)
        raise RuntimeWarning(
            f"Unexpected Model {None if model is None else model.group(1)} found. Aborting to not harm device."
        )

    if model == "AP3825i":
        # From https://forum.darmstadt.freifunk.net/t/flashing-of-the-extreme-networks-ws-ap3825i/923
        boot_openwrt_params = (
            b"cp.b 0xEC000000 0x2000000 0x2000000;"
            b"interrupts off;"
            b"bootm start 0x2000000;"
            b"bootm loados;"
            b"fdt resize;"
            b"fdt boardsetup;"
            b"fdt resize;"
            b"fdt boardsetup;"
            b"fdt chosen;"
            b"fdt resize;"
            b"fdt chosen;"
            b"bootm prep;"
            b"bootm go;"
        )
    elif model == "AP3715i":
        boot_openwrt_params = b"sf probe 0;" b"sf read 0x2000000 0x140000 0x1000000;" b"bootm 0x2000000;"
    elif model == "AP3705i":
        # https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=ebddc5f984a240980303aed68524eb615484eef8
        boot_openwrt_params = b"setenv boot_openwrt 'setenv bootargs; bootm 0xbf230000'"
        # tftpboot 0x85000000; bootm'
    elif model == "AP3710i":
        boot_openwrt_params = b"setenv bootargs; cp.b 0xee000000 0x1000000 0x1000000; bootm 0x1000000"
    elif model == "AP3915i":
        # https://github.com/openwrt/openwrt/commit/e16a0e7e8876df0a92ec4779fe766de1a943307a
        boot_openwrt_params = b"setenv boot_openwrt 'sf probe; sf read 0x88000000 0x280000 0xc00000; bootm 0x88000000'"
        #boot_openwrt_params = b"setenv bootargs; cp.b 0xee000000 0x1000000 0x1000000; bootm 0x1000000"
    elif model == "AP3805i":
        boot_openwrt_params = "setenv boot_openwrt 'setenv bootargs; bootm 0xa1280000'"
    else:
        boot_openwrt_params = ""


    if "boot_openwrt" in printenv_return:
        logging.debug("Found existing U-Boot boot_openwrt parameter. Verifying.")
        existing_boot_openwrt_params = re.search(r"boot_openwrt=(.*)\r\n", printenv_return)
        if not existing_boot_openwrt_params:
            raise RuntimeError("Unable to parse detected boot_openwrt paramter")

        if boot_openwrt_params.decode("ascii") != existing_boot_openwrt_params.group(1):
            # Some AP3825i had wrong and/or outdated boot_openwrt parameters in the past.
            logging.warning(f"Overwriting unexpected param for 'boot_openwrt': {existing_boot_openwrt_params}")
        else:
            # do not set anything if we found boot_openwrt
            # TODO: should we check if bootcmd is also set correctly?
            logging.debug("Existing U-Boot boot_openwrt parameter looks good.")
            return ""
    else:
        logging.info("Did not find boot_openwrt in U-Boot parameters. Setting it.")

    write_to_serial(ser, b'setenv boot_openwrt "' + boot_openwrt_params + b'"\n')
    time.sleep(0.5)

    write_to_serial(ser, b'setenv bootcmd "run boot_openwrt"\n')
    time.sleep(0.5)

    if dryrun:
        logging.info("dryrun: Skipping saveenv")
        return ""

    ser.write(b"saveenv\n")
    if model == "AP3715i":
        # 3715i takes longer
        time.sleep(6)
    else:
        time.sleep(2)
    saveenv_return = ser.read(ser.in_waiting).decode("ascii")
    debug_serial(saveenv_return)

    if "Writing to Flash" not in saveenv_return:
        raise RuntimeError("saveenv did not successfully write to flash")

    return model


def boot_via_tftp(
    ser: serial.Serial,
    tftp_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
    tftp_file: str,
    new_ap_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
    model: str
):
    new_ap_ip_str = str(new_ap_ip.ip).encode("ascii")
    new_ap_netmask_str = str(new_ap_ip.netmask).encode("ascii")
    tftp_ip_str = str(tftp_ip.ip).encode("ascii")

    write_to_serial(ser, b"setenv ipaddr " + new_ap_ip_str + b"\n")
    write_to_serial(ser, b"setenv netmask " + new_ap_netmask_str + b"\n")
    write_to_serial(ser, b"setenv serverip " + tftp_ip_str + b"\n")
    write_to_serial(ser, b"setenv gatewayip " + tftp_ip_str + b"\n")
    print("Starting TFTP Boot.")
    if model == "AP3710i":
        write_to_serial(ser, b"tftpboot 0x1000000 " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n")
    elif model == "AP3915i":
        write_to_serial(ser, b"tftpboot 0x86000000 " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n")
    elif model == "AP3915i":
        write_to_serial(ser, b"tftpboot 0x86000000 " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n")
    elif model == "AP3805i":
        write_to_serial(ser, b"tftpboot 0x89000000 " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n")
    else:
        # AP3815i, AP3805i
        write_to_serial(ser, b"tftpboot 0x2000000 " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n")
    # wait until TFTP transfer is complete
    while event_keep_serial_active.is_set():
        line = readline_from_serial(ser)

        if "Bytes transferred" in line:
            time.sleep(1)
            break
    if model == "AP3825i":
        # Note: We must step through the `bootm` process manually to avoid fdt relocation.
        # https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=7e614820a89208c4e91a3a5f9de07a5402accdaa
        write_to_serial(ser, b"interrupts off\n")
        write_to_serial(ser, b"bootm start 0x2000000\n", sleep=0.2)
        # time.sleep(0.2) # wait for "Booting using the fdt blob at" ...
        write_to_serial(ser, b"bootm loados\n", sleep=2)
        # time.sleep(2) # wait for "Uncompressing Kernel Image ... OK"
        write_to_serial(ser, b"fdt resize\n", sleep=0.1)
        # time.sleep(0.12)
        write_to_serial(ser, b"fdt boardsetup\n", sleep=0.1)
        write_to_serial(ser, b"fdt chosen\n", sleep=0.1)
        write_to_serial(ser, b"bootm prep\n", sleep=0.1)
        print("Starting TFTP Boot.")
        write_to_serial(ser, b"bootm go\n", sleep=0.1)
    elif model in ["AP3715i", "AP3710i"]:
        # See https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=765f66810a3324cc35fa6471ee8eeee335ba8c2b
        write_to_serial(ser, b"bootm\n", sleep=0.1)

        
    max_retries = 2
    cur_retries = 0
    while event_keep_serial_active.is_set():
        line = readline_from_serial(ser)

        if "Retry count exceeded" in line:  # TFTP boot failed
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/net/tftp.c#L704
            logging.warning(f"Failed booting from TFTP (attempt #{cur_retries}): {line}")
            cur_retries = cur_retries + 1
            if cur_retries > max_retries:
                write_to_serial(ser, b"\x03")
                raise RuntimeError(f"Maximum TFTP retries {max_retries} reached. Aborting")

        elif "Wrong Image Format for bootm command" in line:
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/bootm.c#L974
            # do not trigger any other condition, simply retyry when wrong image format was found
            logging.error("TFTP boot found wrong image format")

        elif "ERROR: can't get kernel image!" in line:
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/bootm.c#L123
            logging.error("Unable to boot initramfs file. Check you provided the correct file. Aborting.")
            import os

            # pylint: disable=protected-access
            os._exit(1)

        elif is_kernel_booting(line):
            break

        time.sleep(0.01)



def start_tftp_boot_via_serial(
    name: str,
    tftp_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
    tftp_file: str,
    new_ap_ip: ipaddress.IPv4Interface | ipaddress.IPv6Interface,
    dryrun: bool = False,
):
    with serial.Serial(port=name, baudrate=115200, timeout=30) as ser:
        logging.info(f"Starting to connect to serial port {ser.name}")
        event_keep_serial_active.set()

        bootup_interrupt(ser)
        bootup_login(ser)
        bootup_login_verification(ser)
        model = bootup_set_boot_openwrt(ser, dryrun)
        boot_via_tftp(ser, tftp_ip, tftp_file, new_ap_ip, model)
        boot_wait_for_brlan(ser)
        boot_set_ips(ser, new_ap_ip)
        event_ssh_ready.set()
        keep_logging_until_reboot(ser)


def main(
    serial_port: str,
    initramfs_path_str: str,
    sysupgrade_path_str: str,
    local_ip: str,
    ap_ip: Optional[str] = None,
    dryrun: bool = False,
):

    ap_ip_interface, local_ip_interface = setting_up_ips(local_ip, ap_ip)

    initramfs_path = pathlib.Path(initramfs_path_str)
    sysupgrade_path = pathlib.Path(sysupgrade_path_str)

    tftp_server = TftpServer(initramfs_path_str, listenip=str(local_ip_interface.ip))
    tftp_server.start()
    serial_thread = None
    ssh_thread = None
    try:
        serial_thread = Thread(
            target=start_tftp_boot_via_serial,
            args=[serial_port, local_ip_interface, initramfs_path.name, ap_ip_interface, dryrun],
            daemon=True,
        )
        ssh_thread = Thread(target=start_ssh, args=[sysupgrade_path, str(ap_ip_interface.ip), dryrun])
        logging.debug("Starting serial thread")
        serial_thread.start()
        logging.debug("Starting ssh thread")
        ssh_thread.start()

        logging.debug("Waiting for ssh thread")
        # Strange workaround to allow ctrl+c or system stop events during a join()
        while ssh_thread.is_alive():
            ssh_thread.join(5)  # wait for SSH to conclude its actions

        logging.debug("Waiting for serial thread")
        # Strange workaround to allow ctrl+c or system stop events during a join()
        while serial_thread.is_alive():
            serial_thread.join(5)

        logging.info("All steps finished. Give the AP some time to reboot and then access it on http://192.168.1.1")
    except (KeyboardInterrupt, SystemExit, SystemError):
        logging.warning("Aborting main process")
    finally:
        post_cleanup(tftp_server, ssh_thread, serial_thread)
