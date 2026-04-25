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
import re
import time
from threading import Event
from typing import Union

import serial

from .exceptions import FlashError
from .helpers import (
    debug_serial,
    is_kernel_booting,
    readline_from_serial,
    write_to_serial,
)
from .models import ApModel, get_model_from_printenv


def bootup_set_boot_openwrt(ser: serial.Serial, dryrun: bool = False) -> ApModel:
    ser.write(b"printenv\n")
    time.sleep(1)
    printenv_return = ser.read(ser.in_waiting).decode("ascii")
    debug_serial(printenv_return)
    model = get_model_from_printenv(printenv_return)

    if "boot_openwrt" in printenv_return:
        logging.debug("Found existing U-Boot boot_openwrt parameter. Verifying.")
        existing_boot_openwrt_params = re.search(r"boot_openwrt=(.*)\r\n", printenv_return)
        if not existing_boot_openwrt_params:
            raise RuntimeError("Unable to parse detected boot_openwrt paramter")

        if model.boot_openwrt_params.decode("ascii") != existing_boot_openwrt_params.group(1):
            # Some AP3825i had wrong and/or outdated boot_openwrt parameters in the past.
            logging.warning(f"Overwriting unexpected param for 'boot_openwrt': {existing_boot_openwrt_params.group(0)}")
        else:
            # do not set anything if we found boot_openwrt
            # TODO: should we check if bootcmd is also set correctly?
            logging.debug("Existing U-Boot boot_openwrt parameter looks good.")
            return model
    else:
        logging.info("Did not find boot_openwrt in U-Boot parameters. Setting it.")

    write_to_serial(ser, b'setenv boot_openwrt "' + model.boot_openwrt_params + b'"\n')
    time.sleep(0.5)

    write_to_serial(ser, b'setenv bootcmd "run boot_openwrt"\n')
    time.sleep(0.5)

    if dryrun:
        logging.info("dryrun: Skipping saveenv")
        return model

    ser.write(b"saveenv\n")
    time.sleep(model.saveenv_wait_seconds)

    saveenv_return = ser.read(ser.in_waiting).decode("ascii")
    debug_serial(saveenv_return)

    save_env_success = False

    for msg in ["Writing to Flash", "Writing to NAND", "Writing to redundant NAND"]:
        if msg in saveenv_return:
            save_env_success = True
            break
    if not save_env_success:
        raise RuntimeError("saveenv did not successfully write to flash")

    return model


def boot_via_tftp(
    ser: serial.Serial,
    tftp_ip: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface],
    tftp_file: str,
    new_ap_ip: Union[ipaddress.IPv4Interface, ipaddress.IPv6Interface],
    model: ApModel,
    cancel: Event,
):
    new_ap_ip_str = str(new_ap_ip.ip).encode("ascii")
    new_ap_netmask_str = str(new_ap_ip.netmask).encode("ascii")
    tftp_ip_str = str(tftp_ip.ip).encode("ascii")

    write_to_serial(ser, b"setenv ipaddr " + new_ap_ip_str + b"\n")
    write_to_serial(ser, b"setenv netmask " + new_ap_netmask_str + b"\n")
    write_to_serial(ser, b"setenv serverip " + tftp_ip_str + b"\n")
    write_to_serial(ser, b"setenv gatewayip " + tftp_ip_str + b"\n")
    logging.info("Did setup TFTP Boot.")
    write_to_serial(
        ser,
        b"tftpboot " + model.tftp_load_address + b" " + tftp_ip_str + b":" + tftp_file.encode("ascii") + b"\n",
    )

    # wait until TFTP transfer is complete
    while not cancel.is_set():
        line = readline_from_serial(ser)

        if "Bytes transferred" in line:
            time.sleep(1)
            break

    for cmd, sleep in model.bootm_sequence:
        write_to_serial(ser, cmd, sleep=sleep)

    logging.info("Starting TFTP Boot.")


def wait_for_ramboot(ser: serial.Serial, cancel: Event):
    max_retries = 2
    cur_retries = 0
    while not cancel.is_set():
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
            # Raise instead of os._exit so FlashSession's run() finally block runs cleanly:
            # cleanup tears down the TFTP server, closes the paramiko log, and joins ssh_thread.
            raise FlashError("Unable to boot initramfs file. Check you provided the correct file. Aborting.")

        elif is_kernel_booting(line):
            logging.info("Booting Linux kernel in RAM")
            break

        time.sleep(0.01)
