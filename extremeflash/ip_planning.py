"""IP planning helpers: derive the AP-side and local-side interface tuples
from a CLI-supplied local IP (and optional explicit AP IP).

Extracted from helpers.py during PR 6's helpers.py dissolution. No behavior change.
"""

import ipaddress
import logging
from typing import Optional, Union


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
