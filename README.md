# Extreme Flash

This tool allows flashing Enterasys / Extreme Networks access points fully automatically, using OpenWRT's initramfs image.

## Installation

Install the tool:

```commandline
pipx install extremeflash
```

or

```commandline
pip install extremeflash
```

## Usage

### Prerequisites

1. connect a USB serial device to the local machine and to the serial port of the Enterasys AP
2. identify the IP configured on the local machine that will be used to connect to the Enterasys AP
3. download an OpenWRT initramfs-kernel image, e.g. [for the WS-AP3710i](https://openwrt.org/toh/enterasys/ws-ap3710i#installation)
4. download an OpenWRT-based squashfs-sysupgrade, e.g. [for the WS-AP3710i](https://openwrt.org/toh/enterasys/ws-ap3710i#installation)

**Note**: While it is generally recommended to use the same version for initramfs-kernel and squashfs-sysupgrade, the process
can work with different versions. This is especially important if a downstream OpenWRT firmware (e.g. Gluon) with a different
version should be installed on the router.

### Run the tool

1. Make sure that the serial cable is connected to the access point, but it is not powered on yet

1. Run the tool
    * let it autodetect the serial port:

       ```commandline
       extremeflash --local-ip 192.168.1.70/24 \
       --model AP3710 \
       -i ~/Downloads/openwrt-23.05.0-mpc85xx-p1020-enterasys_ws-ap3710i-initramfs-kernel.bin \
       -j ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-enterasys_ws-ap3710i-squashfs-sysupgrade.bin
       ```

    * or manually specify the serial port:

       ```commandline
       extremeflash  --port /dev/ttyUSB0 --local-ip 192.168.1.70/24 \
       --model AP3710 \
       -i ~/Downloads/openwrt-23.05.0-mpc85xx-p1020-enterasys_ws-ap3710i-initramfs-kernel.bin \
       -j ~/Downloads/openwrt-22.03.3-mpc85xx-p1020-enterasys_ws-ap3710i-squashfs-sysupgrade.bin
       ```

    * For more information run:

       ```commandline
       extremeflash --help
       ```

1. Power the access point and connect the LAN cable to power the AP.\
   **Note**: for APs with two or more LAN ports, make sure the local machine is connected to port 2, not port 1.

1. The tool will flash the access point automatically. When it finishes, the access point
   can be reached via `192.168.1.1` (OpenWRT's default IP).

## Contributing

### Install dependencies

If the dependencies are not already installed, run `poetry install` followed by a `poetry shell` to get an environment with all necessary dependencies.

### Running modified code

After modifying the code, run the tool by executing `python -m extremeflash` inside the repository's folder. For example:

```commandline
python3 -m extremeflash --help
```
