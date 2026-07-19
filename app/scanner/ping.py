"""Ping abstractions for ICMP echo requests and OS fingerprinting.

This module provides host reachability checks via ICMP and captures TTL values
for OS fingerprinting heuristics. TTL-based OS guessing is a heuristic only —
the actual OS cannot be definitively determined from TTL alone, as values can
be altered by routing hops, firewalls, or manual configuration.
"""

from __future__ import annotations

import logging
import platform
import socket
import struct
import time
from typing import Optional

from app.scanner.models import OSFingerprint

logger = logging.getLogger("netsentinel.scanner.ping")


def ping_host(host: str, timeout: float = 4.0) -> bool:
    """Ping a host and return whether it responded.

    Uses ICMP echo (platform-dependent: Windows uses icmp.dll, Unix uses raw sockets).
    Returns True if the host responded, False otherwise.
    """
    try:
        if platform.system() == "Windows":
            # Windows: use ICMP
            return _ping_windows(host, timeout)
        else:
            # Unix/Linux: use raw sockets for ICMP
            return _ping_unix(host, timeout)
    except Exception as exc:
        logger.warning("Ping failed for %s: %s", host, exc)
        return False


def ping_with_ttl(host: str, timeout: float = 4.0) -> tuple[bool, Optional[int]]:
    """Ping a host and capture the TTL value from the response.

    Returns a tuple: (responded: bool, ttl_value: Optional[int]).
    The TTL value is extracted from the ICMP echo reply if available.
    """
    try:
        if platform.system() == "Windows":
            return _ping_with_ttl_windows(host, timeout)
        else:
            return _ping_with_ttl_unix(host, timeout)
    except Exception as exc:
        logger.warning("Ping with TTL failed for %s: %s", host, exc)
        return False, None


def guess_os_from_ttl(ttl: int) -> OSFingerprint:
    """Heuristically guess the OS based on TTL value.

    TTL starts at standard values (64 for Linux/Unix, 128 for Windows, 255 for routers)
    and decreases by 1 per hop. This function compares the observed TTL to the nearest
    standard starting value and returns an OS guess with confidence level.

    NOTE: This is a HEURISTIC only. TTL values can be altered by intermediate hops,
    firewalls, or manual OS configuration. Results must be labeled as "likely" in UI
    and code comments, never "confirmed."
    """
    standard_ttls = {
        64: ("Linux/Unix (likely)", "medium"),  # Also MacOS, BSD
        128: ("Windows (likely)", "medium"),  # Also some network devices
        255: ("Network device - Router/Switch (likely)", "medium"),
    }

    # Find the closest standard TTL
    closest_ttl = min(standard_ttls.keys(), key=lambda x: abs(x - ttl))
    distance = abs(closest_ttl - ttl)

    # Determine confidence based on how close the TTL is
    if distance == 0:
        confidence = "high"
    elif distance <= 3:
        confidence = "medium"
    else:
        confidence = "low"

    if distance <= 5:  # Reasonable tolerance for hops
        os_guess, _ = standard_ttls[closest_ttl]
    else:
        os_guess = "Unknown"
        confidence = "low"

    return OSFingerprint(
        guessed_os=os_guess,
        confidence=confidence,
        ttl_observed=ttl,
        method="ttl_heuristic",
    )


def _ping_windows(host: str, timeout: float) -> bool:
    """Windows-specific ICMP ping implementation."""
    try:
        # Create an ICMP socket (Windows-specific)
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        # Prepare ICMP echo request (ping)
        my_checksum = 0
        my_checksum = _calculate_checksum(
            struct.pack("!HHh", 8, 0, my_checksum) + b"data"
        )
        packet = struct.pack("!HHh", 8, 0, my_checksum) + b"data"

        sock.sendto(packet, (host, 1))

        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        finally:
            sock.close()
    except Exception as exc:
        logger.warning("Windows ping failed for %s: %s", host, exc)
        return False


def _ping_unix(host: str, timeout: float) -> bool:
    """Unix/Linux-specific ICMP ping implementation using raw sockets."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        # Prepare ICMP echo request
        my_checksum = 0
        my_checksum = _calculate_checksum(
            struct.pack("!HHh", 8, 0, my_checksum) + b"data"
        )
        packet = struct.pack("!HHh", 8, 0, my_checksum) + b"data"

        sock.sendto(packet, (host, 1))

        try:
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return False
        finally:
            sock.close()
    except Exception as exc:
        logger.warning("Unix ping failed for %s: %s", host, exc)
        return False


def _ping_with_ttl_windows(host: str, timeout: float) -> tuple[bool, Optional[int]]:
    """Windows-specific ICMP ping with TTL extraction."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        my_checksum = 0
        my_checksum = _calculate_checksum(
            struct.pack("!HHh", 8, 0, my_checksum) + b"data"
        )
        packet = struct.pack("!HHh", 8, 0, my_checksum) + b"data"

        sock.sendto(packet, (host, 1))

        try:
            data, _ = sock.recvfrom(1024)
            # Extract TTL from IP header (byte 8, 1 byte)
            if len(data) >= 9:
                ttl = data[8]
                return True, ttl
            return True, None
        except socket.timeout:
            return False, None
        finally:
            sock.close()
    except Exception as exc:
        logger.warning("Windows ping with TTL failed for %s: %s", host, exc)
        return False, None


def _ping_with_ttl_unix(host: str, timeout: float) -> tuple[bool, Optional[int]]:
    """Unix/Linux-specific ICMP ping with TTL extraction."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(timeout)

        my_checksum = 0
        my_checksum = _calculate_checksum(
            struct.pack("!HHh", 8, 0, my_checksum) + b"data"
        )
        packet = struct.pack("!HHh", 8, 0, my_checksum) + b"data"

        sock.sendto(packet, (host, 1))

        try:
            data, _ = sock.recvfrom(1024)
            # Extract TTL from IP header (byte 8, 1 byte)
            if len(data) >= 9:
                ttl = data[8]
                return True, ttl
            return True, None
        except socket.timeout:
            return False, None
        finally:
            sock.close()
    except Exception as exc:
        logger.warning("Unix ping with TTL failed for %s: %s", host, exc)
        return False, None


def _calculate_checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | (data[i + 1] if i + 1 < len(data) else 0)
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum

