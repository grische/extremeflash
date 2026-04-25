"""Unit tests for IP planning helpers (`setting_up_ips`, `ip_address_fix_prefix`)."""

import ipaddress

import pytest

from extremeflash.ip_planning import ip_address_fix_prefix, setting_up_ips


def test_setting_up_ips_ipv4_with_prefix():
    ap, local = setting_up_ips("192.168.1.70/24")
    assert local.ip == ipaddress.IPv4Address("192.168.1.70")
    assert local.network.prefixlen == 24
    assert ap.ip == ipaddress.IPv4Address("192.168.1.254")  # broadcast - 1
    assert ap.network.prefixlen == 24


def test_setting_up_ips_ipv4_no_prefix_assumes_24():
    ap, local = setting_up_ips("192.168.1.70")
    assert local.network.prefixlen == 24
    assert ap.ip == ipaddress.IPv4Address("192.168.1.254")


def test_setting_up_ips_ipv6_no_prefix_assumes_64():
    ap, local = setting_up_ips("2001:db8::1")
    assert local.network.prefixlen == 64


def test_setting_up_ips_explicit_ap_ip():
    ap, local = setting_up_ips("192.168.1.70/24", "192.168.1.50/24")
    assert ap.ip == ipaddress.IPv4Address("192.168.1.50")


def test_setting_up_ips_collision_raises():
    with pytest.raises(ValueError, match="identical"):
        setting_up_ips("192.168.1.50/24", "192.168.1.50/24")


def test_ip_address_fix_prefix_too_small_raises():
    iface = ipaddress.ip_interface("192.168.1.0/31")
    with pytest.raises(ValueError, match="Too small IP prefix"):
        ip_address_fix_prefix(iface)


def test_ip_address_fix_prefix_passthrough_when_already_sized():
    iface = ipaddress.ip_interface("192.168.1.70/24")
    assert ip_address_fix_prefix(iface) == iface
