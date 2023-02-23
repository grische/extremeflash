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
