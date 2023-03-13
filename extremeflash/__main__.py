#!/usr/bin/env python3
import argparse
import ipaddress
import logging

import serial

from .ws_ap3710i import main


def test_serial_port(potential_serial_port):
    serial.Serial(port=potential_serial_port, baudrate=115200, timeout=5)
    return potential_serial_port


def find_serial_port():
    common_serial_ports = [
        '/dev/ttyUSB1',
        '/dev/ttyUSB0',
        'COM4',
        'COM3',
        'COM2',
        'COM1'  # COM1 needs to be last as it usually always exists
    ]
    for potential_serial_port in common_serial_ports:
        try:
            test_serial_port(potential_serial_port)
            return potential_serial_port
        except serial.serialutil.SerialException as e:
            if (
                    'FileNotFoundError' in str(e)  # Windows
                    or 'No such file or directory' in str(e)  # Linux: [Errno 2] No such file or directory: '/dev/tty..'
            ):
                logging.debug(f"Failed to access {potential_serial_port}.")
                continue
            raise
    raise RuntimeError(f"No valid accessible port found in {common_serial_ports}")


def run():
    parser = argparse.ArgumentParser(
        prog='ExtremeFlash',
        description='This tool helps flashing Extreme Networks or Enterasys access points')

    parser_group_force = parser.add_mutually_exclusive_group()
    parser_group_force.add_argument('-d', '--dryrun', action='store_true',
                                    help='Skip all steps that would make persistent changes')
    # parser_group_force.add_argument('-f', '--force', action='store_true',
    #                                 help='Ignore any safeguards. WARNING: This can be destructive.')

    parser.add_argument('-v', '--verbose', action='store_true', help='Enable debugging output')
    parser.add_argument('-p', '--port', action='store', type=test_serial_port,
                        help='The serial port to use to communicate with the access point', required=False)
    parser.add_argument('-i', '--initramfs', action='store', type=str,
                        help='The path to the initramfs for the access point', required=True)
    parser.add_argument('-j', '--image', action='store', type=str,
                        help='The path to the image that should be flashed on the access point', required=True)
    parser.add_argument('--local-ip', action='store', type=ipaddress.ip_interface,
                        help='The IP of a local interface that will run TFTP and communicate with the access point',
                        required=True)
    parser.add_argument('--ap-ip', action='store', type=ipaddress.ip_interface,
                        help='The (temporary) IP of the access point to communicate with. Defaults to broadcast ip-1.',
                        required=False)

    args = parser.parse_args()

    loglevel = logging.INFO
    if args.verbose:
        loglevel = logging.DEBUG

    logging.basicConfig(level=loglevel)
    logging.getLogger('tftpy').setLevel(logging.WARN if logging.WARN > loglevel else loglevel)  # tftpy is very spammy
    logging.getLogger('paramiko.transport').setLevel(logging.INFO if logging.INFO > loglevel else loglevel)

    serial_port = args.port
    if not args.port:
        serial_port = find_serial_port()

    main(serial_port, args.initramfs, args.image, args.local_ip, args.ap_ip, args.dryrun)


if __name__ == "__main__":
    run()
