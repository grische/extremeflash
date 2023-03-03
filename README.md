# Extreme Flash

This tool allows flashing Enterasys / Extreme Networks access points fully automatically, using OpenWRT's initramfs image.

## Installation

Install all dependencies by running:

```commandline
poetry install
```

or

```commandline
python3 -m pip install .
```

## Usage

### Prerequisites

1. connect a USB serial device to the local machine and to the serial port of the Enterasys AP
2. identify the IP configured on the local machine that will be used to connect to the Enterasys AP
3. download an [OpenWRT Enterasys initramfs-kernel image](https://openwrt.org/toh/enterasys/ws-ap3710i#installation)
4. download
   an [OpenWRT-based Enterasys squashfs-sysupgrade image](https://openwrt.org/toh/enterasys/ws-ap3710i#installation)

### Run the tool

1. Make sure that the serial cable is connected to the access point, but it is not powered on yet

1. Run the tool. If using poetry, run `poetry shell` beforehand.
    * let it autodetect the serial port:

       ```commandline
       ./ws-ap3710i.py --local-ip 192.168.1.70/24 \
       -i ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-extreme-networks_ws-ap3825i-initramfs-kernel.bin \
       -j ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-enterasys_ws-ap3710i-squashfs-sysupgrade.bin
       ```

    * or manually specify the serial port:

       ```commandline
       ./ws-ap3710i.py  --port /dev/ttyUSB0 --local-ip 192.168.1.70/24 \
       -i ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-extreme-networks_ws-ap3825i-initramfs-kernel.bin \
       -j ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-enterasys_ws-ap3710i-squashfs-sysupgrade.bin
       ```

    * For more information run:

       ```commandline
       ./ws-ap3710i.py --help
       ```

1. Power the access point and connect the LAN cable.

1. The tool will flash the access point automatically. When it finishes, the access point
   can be reached via `192.168.1.1` (OpenWRT's default IP).
