"""Traceroute abstractions for network path discovery.

This module provides basic traceroute functionality using ICMP or UDP with
incrementing TTL values to discover the network path to a target host.
Results are returned as lightweight dataclasses, not persisted to the database.

Traceroute typically requires elevated/raw socket permissions on Linux systems.
Failures due to insufficient permissions are handled gracefully with clear
error messages rather than crashing.
"""

from __future__ import annotations

import logging
import platform
import socket
import struct
import time
from typing import Optional

from app.scanner.models import TracerouteHop

logger = logging.getLogger("netsentinel.scanner.traceroute")

# Traceroute configuration
DEFAULT_MAX_HOPS = 30
DEFAULT_PROBE_TIMEOUT = 2.0
DEFAULT_PROBES_PER_HOP = 1


def traceroute(
    host: str,
    max_hops: int = DEFAULT_MAX_HOPS,
    timeout: float = DEFAULT_PROBE_TIMEOUT,
) -> list[TracerouteHop]:
    """Perform a basic traceroute to a target host.

    Uses ICMP (Echo Request with incrementing TTL) or UDP probes depending
    on platform and permissions. Returns a list of hops from source to target.

    Args:
        host: Target hostname or IP address.
        max_hops: Maximum number of hops to trace (default 30).
        timeout: Timeout per probe in seconds (default 2.0).

    Returns:
        A list of TracerouteHop dataclasses representing the network path.
        Returns an empty list if traceroute fails (e.g., permission denied).
    """
    try:
        logger.info("Starting traceroute to %s (max %d hops)", host, max_hops)

        # Resolve target host
        try:
            target_ip = socket.gethostbyname(host)
        except socket.gaierror as exc:
            logger.warning("Failed to resolve %s: %s", host, exc)
            return []

        hops: list[TracerouteHop] = []

        # Platform-specific implementation
        if platform.system() == "Windows":
            hops = _traceroute_windows(target_ip, max_hops, timeout)
        else:
            try:
                hops = _traceroute_unix(target_ip, max_hops, timeout)
            except PermissionError:
                logger.error(
                    "Traceroute requires elevated permissions on Unix/Linux. "
                    "Run with sudo or use a network namespace."
                )
                return []

        logger.info("Traceroute to %s completed with %d hops", host, len(hops))
        return hops

    except Exception as exc:  # pragma: no cover
        logger.exception("Unexpected traceroute failure for %s: %s", host, exc)
        return []


def _traceroute_windows(
    target_ip: str, max_hops: int, timeout: float
) -> list[TracerouteHop]:
    """Windows-specific traceroute using ICMP."""
    hops: list[TracerouteHop] = []

    try:
        for hop_number in range(1, max_hops + 1):
            hop_ip: Optional[str] = None
            hop_rtt: Optional[float] = None

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop_number)
                sock.settimeout(timeout)

                # Send ICMP echo request
                my_checksum = 0
                my_checksum = _calculate_checksum(
                    struct.pack("!HHh", socket.ICMP_ECHO, 0, my_checksum) + b"data"
                )
                packet = struct.pack("!HHh", socket.ICMP_ECHO, 0, my_checksum) + b"data"

                start_time = time.perf_counter()
                try:
                    sock.sendto(packet, (target_ip, 1))
                    data, (hop_ip, _) = sock.recvfrom(1024)
                    hop_rtt = (time.perf_counter() - start_time) * 1000  # ms
                except socket.timeout:
                    hop_ip = None
                    hop_rtt = None
                finally:
                    sock.close()
            except Exception as exc:
                logger.debug("Hop %d probe failed: %s", hop_number, exc)

            hops.append(
                TracerouteHop(
                    hop_number=hop_number,
                    ip_address=hop_ip,
                    round_trip_time_ms=hop_rtt,
                )
            )

            # Stop if we reached the target
            if hop_ip == target_ip:
                break

        return hops

    except Exception as exc:
        logger.error("Windows traceroute failed: %s", exc)
        return []


def _traceroute_unix(
    target_ip: str, max_hops: int, timeout: float
) -> list[TracerouteHop]:
    """Unix/Linux-specific traceroute using raw sockets and incrementing TTL.

    Raises PermissionError if raw socket access is denied.
    """
    hops: list[TracerouteHop] = []

    try:
        for hop_number in range(1, max_hops + 1):
            hop_ip: Optional[str] = None
            hop_rtt: Optional[float] = None

            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, hop_number)
                sock.settimeout(timeout)

                # Send ICMP echo request
                my_checksum = 0
                my_checksum = _calculate_checksum(
                    struct.pack("!HHh", socket.ICMP_ECHO, 0, my_checksum) + b"data"
                )
                packet = struct.pack("!HHh", socket.ICMP_ECHO, 0, my_checksum) + b"data"

                start_time = time.perf_counter()
                try:
                    sock.sendto(packet, (target_ip, 1))
                    data, (hop_ip, _) = sock.recvfrom(1024)
                    hop_rtt = (time.perf_counter() - start_time) * 1000  # ms
                except socket.timeout:
                    hop_ip = None
                    hop_rtt = None
                finally:
                    sock.close()
            except PermissionError:
                logger.error("Raw socket access denied. Elevated permissions required.")
                raise
            except Exception as exc:
                logger.debug("Hop %d probe failed: %s", hop_number, exc)

            hops.append(
                TracerouteHop(
                    hop_number=hop_number,
                    ip_address=hop_ip,
                    round_trip_time_ms=hop_rtt,
                )
            )

            # Stop if we reached the target
            if hop_ip == target_ip:
                break

        return hops

    except PermissionError:
        raise
    except Exception as exc:
        logger.error("Unix traceroute failed: %s", exc)
        return []


def _calculate_checksum(data: bytes) -> int:
    """Calculate ICMP checksum."""
    checksum = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) | (data[i + 1] if i + 1 < len(data) else 0)
        checksum += word
    checksum = (checksum >> 16) + (checksum & 0xFFFF)
    checksum = ~checksum & 0xFFFF
    return checksum
