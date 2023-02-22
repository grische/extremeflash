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
import re
import time

import serial

# TODO: replace these with arguments (using argparse)
local_ip = "192.168.0.25"

tftp_file = b'01C8A8C0.img'  # Only change this if you know what you are doing
DEBUG = True


def debug_serial(string: str):
    if DEBUG:
        print("DEBUG: " + string.rstrip())


def bootup_interrupt(ser: serial.Serial):
    while True:
        line = readline_from_serial(ser)

        # These lines probably only works with custom Enterasys U-Boot v2009.11.10
        # TODO: add support for other / newer versions of U-Boot
        if (
                "### JFFS2 load complete" in line  # stock firmware message
                or "### JFFS2 LOAD ERROR" in line  # OpenWRT message :-|
        ):
            text = b"x"  # send interrupt key
            print(f"JFFS2 load done. Sending interrupt key {text}.")
            time.sleep(0.5)  # sleep 500ms
            ser.write(text)
            break

        time.sleep(0.01)


def bootup_login(ser: serial.Serial):
    while True:
        line = readline_from_serial(ser)

        if "[30s timeout]" in line:
            time.sleep(0.1)
            print(f"Attempting to log in.")
            ser.write(b"admin\n")
            time.sleep(0.1)
            ser.write(b"new2day\n")
        elif "password: new2day" in line:
            time.sleep(0.1)  # sleep 500ms
            print(f"Checking if login was successful.")
            break

        time.sleep(0.01)


def bootup_login_verification(ser: serial.Serial):
    prompt_string = "Boot (PRI)->"
    # Reading byte by byte because there is no linebreak after the prompt
    while True:
        # only read chars if there are enough bytes in wait from the buffer
        if ser.in_waiting > len(prompt_string):
            chars = ser.read(ser.in_waiting).decode('ascii')
            debug_serial(chars)

            if prompt_string in chars:
                print(f"U-Boot login successful!")
                break
            else:
                raise RuntimeError("U-Boot login failed :((")

        time.sleep(0.01)


def bootup_set_boot_openwrt(ser: serial.Serial):
    ser.write(b'printenv\n')
    time.sleep(1)
    printenv_return = ser.read(ser.in_waiting).decode('ascii')
    debug_serial(printenv_return)
    boot_openwrt_params = b'setenv bootargs; cp.b 0xee000000 0x1000000 0x1000000; bootm 0x1000000'
    if "boot_openwrt" in printenv_return:
        print("Found existing U-Boot boot_openwrt parameter. Verifying.")
        existing_boot_openwrt_params = re.search(r'boot_openwrt=(.*)\r\n', printenv_return).group(1)
        if boot_openwrt_params.decode('ascii') != existing_boot_openwrt_params:
            error_message = f'''
                    Aborting. Unexpected param for 'boot_openwrt' found.
                    Found: "{existing_boot_openwrt_params}"
                    Expected: "{boot_openwrt_params.decode('ascii')}"
                '''
            raise RuntimeError(error_message)

        print("Existing U-Boot boot_openwrt parameter looks good.")

    else:
        print("Did not find boot_openwrt in U-Boot parameters. Setting it.")
        write_to_serial(ser, b'setenv boot_openwrt "' + boot_openwrt_params + b'"\n')
        time.sleep(0.5)

        write_to_serial(ser, b'setenv bootcmd "run boot_openwrt"\n')
        time.sleep(0.5)

        ser.write(b'saveenv\n')
        time.sleep(2)
        saveenv_return = ser.read(ser.in_waiting).decode('ascii')
        debug_serial(saveenv_return)

        if "Writing to Flash" not in saveenv_return:
            raise RuntimeError("saveenv did not successfully write to flash")


def boot_via_tftp(ser: serial.Serial,
                  tftp_ip: str,
                  new_ap_ip: str):
    new_ap_ip_str = new_ap_ip.encode('ascii')
    tftp_ip_str = tftp_ip.encode('ascii')

    write_to_serial(ser, b'setenv ipaddr ' + new_ap_ip_str + b'\n')
    write_to_serial(ser, b'setenv netmask 255.255.255.0\n')
    write_to_serial(ser, b'setenv serverip ' + tftp_ip_str + b'\n')
    write_to_serial(ser, b'setenv gatewayip ' + tftp_ip_str + b'\n')
    print("Starting TFTP Boot.")
    write_to_serial(ser, b'tftpboot 0x1000000 ' + tftp_ip_str + b':' + tftp_file + b'; bootm\n')
    max_retries = 2
    cur_retries = 0
    while True:
        line = readline_from_serial(ser)

        if "Retry count exceeded" in line:  # TFTP boot failed
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/net/tftp.c#L704
            print(f"Failed booting from TFTP (attempt #{cur_retries}): {line}")
            cur_retries = cur_retries + 1
            if cur_retries > max_retries:
                write_to_serial(ser, b'\x03')
                raise RuntimeError(f"Maximum TFTP retries {max_retries} reached. Aborting")

        elif "Wrong Image Format for bootm command" in line:
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/bootm.c#L974
            print("TFTP boot found wrong image format")

        elif "ERROR: can't get kernel image!" in line:
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/bootm.c#L123
            print(f"Unable to boot initramfs file. Check you provided the correct file. Aborting.")
            import os
            os._exit(1)

        elif "## Booting kernel from FIT Image at" in line:  # with U-Boot v2009.x
            # https://github.com/u-boot/u-boot/blob/f20393c5e787b3776c179d20f82a86bda124d651/common/cmd_bootm.c#L897
            break

        # TODO: check if this works! the original check above might be called different with newer version of U-Boot:
        elif "## Loading kernel from FIT Image at" in line:  # with U-Boot v2013.07 and newer
            # https://github.com/u-boot/u-boot/blob/8c39999acb726ef083d3d5de12f20318ee0e5070/boot/image-fit.c#L2079
            break

        time.sleep(0.01)


def start_tftp_boot_via_serial(name: str,
                               tftp_ip: str,
                               new_ap_ip: str):
    with serial.Serial(port=name, baudrate=115200, timeout=30) as ser:
        print(f"Starting to connect to serial port {ser.name}")

        bootup_interrupt(ser)
        bootup_login(ser)
        bootup_login_verification(ser)
        bootup_set_boot_openwrt(ser)
        boot_via_tftp(ser, tftp_ip, new_ap_ip)


def write_to_serial(ser: serial.Serial, text: bytes, sleep: float = 0) -> str:
    ser.write(text)
    if sleep > 0:
        time.sleep(sleep)

    return_string = ser.readline().decode('ascii')
    debug_serial(return_string)
    return return_string


def readline_from_serial(ser: serial.Serial) -> str:
    bytestring = ser.readline()
    try:
        line = bytestring.decode('ascii')
    except UnicodeDecodeError:
        # We receive non-ascii/non-utf8 chars from the Linux kernel like 0xea or 0x90
        # after "Serial: 8250/16550 driver, 16 ports, IRQ sharing enabled"
        line = str(bytestring)
        line.replace(r'\n', '\n')

    debug_serial(line)
    return line


def main():
    import sys
    assert len(sys.argv) == 2, 'Please specify the serial port'
    serial_port = sys.argv[1]

    start_tftp_boot_via_serial(serial_port, local_ip, '192.168.1.1')


if __name__ == '__main__':
    main()
