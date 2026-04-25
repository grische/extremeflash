"""Per-AP-model behavior, consolidated from the if/elif chains previously scattered
across `ws.py`.

Each `ApModel` records the U-Boot quirks for one Extreme Networks / Enterasys access
point family: how the OpenWRT boot env-var is constructed, what RAM address to load
the initramfs into via TFTP, the post-load `bootm` step sequence, and how long
`saveenv` takes on that flash type.

Detection:
  - `get_model_from_printenv(printenv)` matches against the U-Boot `MODEL=...`
    line by **prefix**. The four supported model names are prefix-disjoint
    (AP3710, AP3715, AP3825, AP3935), so prefix matching correctly accepts
    AP3935i, AP3935i-FCC, AP3935i-IL, AP3935i-ROW etc. while rejecting any
    hypothetical future model whose name overlaps an existing prefix.

Adding a new model: define one new ApModel record below and add it to the
SUPPORTED_MODELS tuple. Nothing in `ws.py` or `__main__.py` needs touching.
"""

import logging
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ApModel:
    """Per-model U-Boot behavior. Frozen; instances live in the SUPPORTED_MODELS registry."""

    name: str
    boot_openwrt_params: bytes
    tftp_load_address: bytes
    bootm_sequence: tuple[tuple[bytes, float], ...]  # (cmd_with_newline, sleep_after)
    saveenv_wait_seconds: float


_AP3710 = ApModel(
    name="AP3710",
    boot_openwrt_params=b"setenv bootargs; cp.b 0xee000000 0x1000000 0x1000000; bootm 0x1000000",
    tftp_load_address=b"0x1000000",
    # See https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=765f66810a3324cc35fa6471ee8eeee335ba8c2b
    bootm_sequence=((b"bootm\n", 0.1),),
    saveenv_wait_seconds=2.0,
)

_AP3715 = ApModel(
    name="AP3715",
    boot_openwrt_params=b"sf probe 0;sf read 0x2000000 0x140000 0x1000000;bootm 0x2000000;",
    # Same SPI-flash → DDR convention as the boot_openwrt_params; load at 0x2000000.
    # (Pre-PR-2 ws.py omitted AP3715 from boot_via_tftp's TFTP-load dispatch entirely
    # — calling boot_via_tftp with model="AP3715" raised RuntimeError. The omission
    # was a latent bug; this entry fixes it.)
    tftp_load_address=b"0x2000000",
    bootm_sequence=((b"bootm\n", 0.1),),
    saveenv_wait_seconds=6.0,  # AP3715 SPI flash is considerably slower
)

_AP3825 = ApModel(
    name="AP3825",
    # From https://forum.darmstadt.freifunk.net/t/flashing-of-the-extreme-networks-ws-ap3825i/923
    boot_openwrt_params=(
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
    ),
    tftp_load_address=b"0x2000000",
    # Step manually through bootm to avoid fdt relocation.
    # https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=7e614820a89208c4e91a3a5f9de07a5402accdaa
    bootm_sequence=(
        (b"interrupts off\n", 0),
        (b"bootm start 0x2000000\n", 0.2),
        (b"bootm loados\n", 2),
        (b"fdt resize\n", 0.1),
        (b"fdt boardsetup\n", 0.1),
        (b"fdt chosen\n", 0.1),
        (b"bootm prep\n", 0.1),
        (b"bootm go\n", 0.1),
    ),
    saveenv_wait_seconds=2.0,
)

_AP3935 = ApModel(
    name="AP3935",
    # https://git.openwrt.org/?p=openwrt/openwrt.git;a=commit;h=3aef61060e3f51aa43fe494d5ff173e81dd43003
    boot_openwrt_params=b"sf probe 0; sf read 0x41500000 0x003c0000 0x00e10000; bootm 0x41500000",
    tftp_load_address=b"0x42000000",
    # Step manually through bootm to avoid fdt relocation.
    bootm_sequence=(
        (b"bootm start 0x42000000\n", 0.2),
        (b"bootm loados\n", 2),
        (b"bootm prep\n", 0.1),
        (b"bootm go\n", 0.1),
    ),
    saveenv_wait_seconds=2.0,
)


SUPPORTED_MODELS: tuple[ApModel, ...] = (_AP3710, _AP3715, _AP3825, _AP3935)


def get_model_from_printenv(printenv: str) -> ApModel:
    """Parse the `MODEL=...` line from a U-Boot `printenv` dump, returning the matching
    ApModel. Raises RuntimeWarning on missing or unknown model.

    Matching uses prefix comparison. Supported names are prefix-disjoint, so suffixes
    such as `i`, `i-FCC`, `i-IL`, `i-ROW` are all accepted.
    """
    model_match = re.search(r"MODEL=(.*)\r\n", printenv)
    if model_match is None:
        raise RuntimeWarning("no MODEL name found in printenv")
    full_model_name = model_match.group(1)
    logging.info("full model name is: %s", full_model_name)

    for model in SUPPORTED_MODELS:
        if full_model_name.startswith(model.name):
            logging.debug("model found: %s", model.name)
            return model

    raise RuntimeWarning(f"Unexpected Model {full_model_name} found. Aborting to not harm device.")
