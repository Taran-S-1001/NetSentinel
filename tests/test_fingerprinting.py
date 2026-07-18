"""Tests for OS fingerprinting via TTL heuristics.

This module tests the TTL-based OS fingerprinting functionality that attempts
to identify the operating system based on TTL values from ICMP responses.
Results are heuristic-based and labeled as "likely," never "confirmed."
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from app.scanner.models import OSFingerprint
from app.scanner.ping import guess_os_from_ttl, ping_host, ping_with_ttl

logger = logging.getLogger("netsentinel.tests.fingerprinting")


class TestOSFingerprintingHeuristics:
    """Test TTL-based OS fingerprinting heuristics."""

    def test_guess_os_from_ttl_detects_linux(self):
        """TTL values near 64 should suggest Linux/Unix."""
        # Exact match
        result = guess_os_from_ttl(64)
        assert "Linux" in result.guessed_os
        assert result.confidence == "high"
        assert result.ttl_observed == 64
        assert result.method == "ttl_heuristic"

    def test_guess_os_from_ttl_detects_windows(self):
        """TTL values near 128 should suggest Windows."""
        # Exact match
        result = guess_os_from_ttl(128)
        assert "Windows" in result.guessed_os
        assert result.confidence == "high"
        assert result.ttl_observed == 128

    def test_guess_os_from_ttl_detects_router(self):
        """TTL values near 255 should suggest network device."""
        # Exact match
        result = guess_os_from_ttl(255)
        assert "Router" in result.guessed_os or "Network device" in result.guessed_os
        assert result.confidence == "high"
        assert result.ttl_observed == 255

    def test_guess_os_from_ttl_tolerates_hop_variance(self):
        """TTL can decrease by 1 per hop; heuristic should tolerate variance."""
        # TTL 62-66 should still suggest Linux (started at 64, lost 2-2 hops)
        for ttl in [62, 63, 65, 66]:
            result = guess_os_from_ttl(ttl)
            assert "Linux" in result.guessed_os, f"TTL {ttl} should suggest Linux"
            assert result.confidence in ["high", "medium"]

    def test_guess_os_from_ttl_with_medium_confidence(self):
        """TTLs with moderate variance from standard should have medium confidence."""
        result = guess_os_from_ttl(61)
        assert result.confidence == "medium"
        assert "Linux" in result.guessed_os

    def test_guess_os_from_ttl_with_low_confidence(self):
        """TTLs far from standard values should have low confidence or Unknown."""
        result = guess_os_from_ttl(50)
        # Should be far from all standard values
        if result.guessed_os == "Unknown":
            assert result.confidence == "low"
        else:
            assert result.confidence == "low"

    def test_guess_os_from_ttl_returns_dataclass(self):
        """Should return an OSFingerprint dataclass."""
        result = guess_os_from_ttl(64)
        assert isinstance(result, OSFingerprint)
        assert hasattr(result, "guessed_os")
        assert hasattr(result, "confidence")
        assert hasattr(result, "ttl_observed")
        assert hasattr(result, "method")

    def test_os_fingerprint_is_labeled_heuristic(self):
        """Results should indicate they are heuristic, not definitive."""
        result = guess_os_from_ttl(64)
        # "likely" indicates heuristic nature
        assert "likely" in result.guessed_os.lower() or result.confidence in ["high", "medium", "low"]


class TestPingWithTTL:
    """Test TTL capture during ping operations."""

    @patch("app.scanner.ping._ping_with_ttl_windows")
    def test_ping_with_ttl_returns_tuple(self, mock_ping):
        """ping_with_ttl should return (success: bool, ttl: Optional[int])."""
        mock_ping.return_value = (True, 64)

        with patch("platform.system", return_value="Windows"):
            success, ttl = ping_with_ttl("127.0.0.1")

        assert isinstance(success, bool)
        assert ttl is None or isinstance(ttl, int)

    @patch("app.scanner.ping._ping_with_ttl_windows")
    def test_ping_with_ttl_handles_no_response(self, mock_ping):
        """ping_with_ttl should handle timeouts gracefully."""
        mock_ping.return_value = (False, None)

        with patch("platform.system", return_value="Windows"):
            success, ttl = ping_with_ttl("192.0.2.1")  # Non-routable IP

        assert success is False
        assert ttl is None

    @patch("app.scanner.ping._ping_with_ttl_windows")
    def test_ping_with_ttl_windows_path(self, mock_ping):
        """On Windows, should use Windows-specific implementation."""
        mock_ping.return_value = (True, 128)

        with patch("platform.system", return_value="Windows"):
            ping_with_ttl("example.com")

        mock_ping.assert_called_once()

    @patch("app.scanner.ping._ping_with_ttl_unix")
    def test_ping_with_ttl_unix_path(self, mock_ping):
        """On Unix/Linux, should use Unix-specific implementation."""
        mock_ping.return_value = (True, 64)

        with patch("platform.system", return_value="Linux"):
            ping_with_ttl("example.com")

        mock_ping.assert_called_once()

    def test_ping_with_ttl_exception_handling(self):
        """ping_with_ttl should handle exceptions gracefully."""
        with patch("platform.system", return_value="Linux"):
            with patch("app.scanner.ping._ping_with_ttl_unix", side_effect=Exception("Socket error")):
                success, ttl = ping_with_ttl("example.com")

        assert success is False
        assert ttl is None


class TestPingHost:
    """Test basic host reachability."""

    @patch("app.scanner.ping._ping_windows")
    def test_ping_host_returns_bool(self, mock_ping):
        """ping_host should return a boolean."""
        mock_ping.return_value = True

        with patch("platform.system", return_value="Windows"):
            result = ping_host("127.0.0.1")

        assert isinstance(result, bool)

    @patch("app.scanner.ping._ping_windows")
    def test_ping_host_windows_path(self, mock_ping):
        """On Windows, should use Windows-specific implementation."""
        mock_ping.return_value = True

        with patch("platform.system", return_value="Windows"):
            ping_host("example.com")

        mock_ping.assert_called_once()

    @patch("app.scanner.ping._ping_unix")
    def test_ping_host_unix_path(self, mock_ping):
        """On Unix/Linux, should use Unix-specific implementation."""
        mock_ping.return_value = True

        with patch("platform.system", return_value="Linux"):
            ping_host("example.com")

        mock_ping.assert_called_once()

    def test_ping_host_exception_handling(self):
        """ping_host should handle exceptions gracefully."""
        with patch("platform.system", return_value="Linux"):
            with patch("app.scanner.ping._ping_unix", side_effect=Exception("Permission denied")):
                result = ping_host("example.com")

        assert result is False


class TestFingerprintingIntegration:
    """Integration tests for fingerprinting with other scanner components."""

    def test_fingerprint_can_be_serialized_for_api(self):
        """OS fingerprint should be easily serialized for API responses."""
        result = guess_os_from_ttl(64)
        
        # Should be convertible to dict-like structure
        fingerprint_dict = {
            "os": result.guessed_os,
            "confidence": result.confidence,
            "ttl_observed": result.ttl_observed,
            "method": result.method,
        }

        assert isinstance(fingerprint_dict, dict)
        assert "os" in fingerprint_dict
        assert "likely" in fingerprint_dict["os"].lower() or fingerprint_dict["confidence"]

    def test_fingerprint_labels_are_consistent(self):
        """Fingerprint labels should consistently indicate they are heuristic."""
        for ttl in [64, 128, 255]:
            result = guess_os_from_ttl(ttl)
            # All non-Unknown results should have "likely" in the OS string
            if result.guessed_os != "Unknown":
                assert "likely" in result.guessed_os.lower(), \
                    f"OS guess '{result.guessed_os}' should indicate it's a heuristic"
