"""Tests for traceroute network path discovery.

This module tests the traceroute functionality that discovers the network
path to a target host using ICMP with incrementing TTL values.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.models import TracerouteHop
from app.scanner.traceroute import traceroute

logger = logging.getLogger("netsentinel.tests.traceroute")


class TestTracerouteBasic:
    """Basic traceroute functionality tests."""

    def test_traceroute_returns_list(self):
        """traceroute should return a list of TracerouteHop objects."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert isinstance(result, list)

    def test_traceroute_returns_traceroute_hops(self):
        """Each element in result should be a TracerouteHop."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.5),
            TracerouteHop(hop_number=2, ip_address="10.0.0.1", round_trip_time_ms=3.2),
        ]

        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert len(result) == 2
        assert all(isinstance(hop, TracerouteHop) for hop in result)

    def test_traceroute_hop_has_required_fields(self):
        """Each hop should have hop_number and may have ip_address and rtt."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.5),
            TracerouteHop(hop_number=2, ip_address=None, round_trip_time_ms=None),
        ]

        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert result[0].hop_number == 1
        assert result[0].ip_address == "192.168.1.1"
        assert result[1].ip_address is None

    def test_traceroute_returns_empty_on_dns_failure(self):
        """traceroute should return empty list if DNS resolution fails."""
        with patch("socket.gethostbyname", side_effect=IOError("DNS failed")):
            result = traceroute("nonexistent.invalid.local")

        assert result == []

    def test_traceroute_returns_empty_on_permission_error_unix(self):
        """traceroute should return empty list on Unix if permission denied."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_unix", side_effect=PermissionError("Raw socket denied")):
                with patch("platform.system", return_value="Linux"):
                    result = traceroute("google.com")

        assert result == []

    def test_traceroute_returns_empty_on_general_failure(self):
        """traceroute should return empty list on unexpected errors."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", side_effect=Exception("Unexpected error")):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert result == []


class TestTracerouteMultiHop:
    """Tests for multi-hop traceroute scenarios."""

    def test_traceroute_multi_hop_scenario(self):
        """Should correctly handle a multi-hop path."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.5),
            TracerouteHop(hop_number=2, ip_address="10.0.0.1", round_trip_time_ms=3.2),
            TracerouteHop(hop_number=3, ip_address="172.16.0.1", round_trip_time_ms=5.8),
            TracerouteHop(hop_number=4, ip_address="8.8.8.8", round_trip_time_ms=15.2),
        ]

        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert len(result) == 4
        assert result[0].hop_number == 1
        assert result[3].hop_number == 4
        assert result[3].ip_address == "8.8.8.8"

    def test_traceroute_handles_unreachable_hops(self):
        """Should handle hops that don't respond (None ip_address)."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.5),
            TracerouteHop(hop_number=2, ip_address=None, round_trip_time_ms=None),
            TracerouteHop(hop_number=3, ip_address="172.16.0.1", round_trip_time_ms=5.8),
        ]

        with patch("socket.gethostbyname", return_value="172.16.0.1"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("example.com")

        assert len(result) == 3
        assert result[1].ip_address is None
        assert result[2].ip_address is not None

    def test_traceroute_stores_rtt_milliseconds(self):
        """RTT should be stored in milliseconds."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.234),
        ]

        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("router.local")

        assert result[0].round_trip_time_ms == 1.234
        assert isinstance(result[0].round_trip_time_ms, float)


class TestTraceroutePlatformSpecific:
    """Tests for platform-specific traceroute behavior."""

    def test_traceroute_uses_windows_implementation(self):
        """On Windows, should call _traceroute_windows."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]) as mock_win:
                with patch("platform.system", return_value="Windows"):
                    traceroute("google.com")

        mock_win.assert_called_once()

    def test_traceroute_uses_unix_implementation(self):
        """On Unix/Linux, should call _traceroute_unix."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_unix", return_value=[]) as mock_unix:
                with patch("platform.system", return_value="Linux"):
                    traceroute("google.com")

        mock_unix.assert_called_once()

    def test_traceroute_passes_parameters(self):
        """traceroute should pass max_hops and timeout to implementation."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]) as mock_win:
                with patch("platform.system", return_value="Windows"):
                    traceroute("google.com", max_hops=20, timeout=3.0)

        mock_win.assert_called_once_with("8.8.8.8", 20, 3.0)


class TestTracerouteHostnameResolution:
    """Tests for hostname resolution in traceroute."""

    def test_traceroute_resolves_hostname(self):
        """Should resolve hostname to IP before tracing."""
        with patch("socket.gethostbyname", return_value="93.184.216.34") as mock_resolve:
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]):
                with patch("platform.system", return_value="Windows"):
                    traceroute("example.com")

        mock_resolve.assert_called_once_with("example.com")

    def test_traceroute_handles_ip_address_input(self):
        """Should work with IP addresses directly."""
        with patch("socket.gethostbyname", return_value="8.8.8.8") as mock_resolve:
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]):
                with patch("platform.system", return_value="Windows"):
                    traceroute("8.8.8.8")

        mock_resolve.assert_called_once_with("8.8.8.8")

    def test_traceroute_hostname_resolution_error_message(self):
        """DNS failure should be logged clearly."""
        with patch("socket.gethostbyname", side_effect=IOError("getaddrinfo failed")):
            result = traceroute("invalid.local")

        assert result == []


class TestTracerouteOptionalFields:
    """Tests for optional TracerouteHop fields."""

    def test_traceroute_hop_hostname_field(self):
        """TracerouteHop should support optional hostname field."""
        hop = TracerouteHop(
            hop_number=1,
            ip_address="8.8.8.8",
            round_trip_time_ms=15.0,
            hostname="dns.google.com",
        )

        assert hop.hostname == "dns.google.com"

    def test_traceroute_hop_hostname_optional(self):
        """Hostname should be optional (None is valid)."""
        hop = TracerouteHop(
            hop_number=1,
            ip_address="8.8.8.8",
            round_trip_time_ms=15.0,
            hostname=None,
        )

        assert hop.hostname is None


class TestTracerouteIntegration:
    """Integration tests for traceroute with other components."""

    def test_traceroute_result_serializable(self):
        """Traceroute results should be easily serializable for API responses."""
        hops = [
            TracerouteHop(hop_number=1, ip_address="192.168.1.1", round_trip_time_ms=1.5),
        ]

        with patch("socket.gethostbyname", return_value="192.168.1.1"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=hops):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("router.local")

        # Should be convertible to dict-like structure
        hop_dict = {
            "hop_number": result[0].hop_number,
            "ip_address": result[0].ip_address,
            "round_trip_time_ms": result[0].round_trip_time_ms,
        }

        assert isinstance(hop_dict, dict)
        assert "hop_number" in hop_dict

    def test_traceroute_empty_result_handling(self):
        """Empty traceroute results should not cause issues."""
        with patch("socket.gethostbyname", return_value="8.8.8.8"):
            with patch("app.scanner.traceroute._traceroute_windows", return_value=[]):
                with patch("platform.system", return_value="Windows"):
                    result = traceroute("google.com")

        assert result == []
        assert isinstance(result, list)
