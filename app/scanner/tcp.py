"""TCP scanning abstractions.

This module provides the initial one-port TCP scanning implementation for
NetSentinel. It validates the target input, attempts a TCP connection using
socket primitives, and returns a typed scan result while handling common
network errors gracefully.
"""

from __future__ import annotations

import errno
import logging
import socket
import time
from concurrent.futures import Future, ThreadPoolExecutor, as_completed, wait
from datetime import datetime, timezone
from typing import Callable, Optional

from app.scanner.constants import DEFAULT_TIMEOUT
from app.scanner.models import ScanResult
from app.scanner.validator import (
    HostnameValidationError,
    IPv4ValidationError,
    IPv6ValidationError,
    PortRangeValidationError,
    PortValidationError,
    ValidationError,
    validate_hostname,
    validate_ipv4,
    validate_ipv6,
    validate_port_number,
    validate_port_range,
)


class TCPScanner:
    """Perform single-port TCP scans with graceful error handling."""

    def __init__(self, timeout: float = DEFAULT_TIMEOUT, logger: Optional[logging.Logger] = None) -> None:
        self.timeout = timeout
        self.logger = logger or logging.getLogger("netsentinel.scanner.tcp")

    def connect(self, host: str, port: int) -> ScanResult:
        """Scan a single TCP port and return a structured scan result."""
        return self.scan_port(host, port)

    def scan_port(self, host: str, port: int) -> ScanResult:
        """Attempt a TCP connection to a single host and port.

        The method validates the host and port, creates a TCP socket, applies a
        configurable timeout, performs the connection attempt with
        ``socket.connect_ex()``, measures the elapsed time, and returns a
        :class:`ScanResult` regardless of the outcome.
        """
        timestamp = self._timestamp()
        service_name = "Unknown"

        try:
            validated_host = self._validate_host(host)
            validated_port = validate_port_number(port)
            service_name = self._resolve_service_name(validated_port)
        except (ValidationError, TypeError) as exc:
            self.logger.warning("Invalid scan input for %s:%s: %s", host, port, exc)
            return ScanResult(
                host=str(host),
                port=int(port) if isinstance(port, int) else 0,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name="Unknown",
                error_message=str(exc),
                timestamp=timestamp,
            )

        sock: Optional[socket.socket] = None
        start_time = time.perf_counter()

        try:
            self.logger.info("Scanning TCP %s:%s", validated_host, validated_port)
            family, _, _, _, sockaddr = self._resolve_address(validated_host, validated_port)
            sock = socket.socket(family, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            result_code = sock.connect_ex(sockaddr)
            elapsed = round(time.perf_counter() - start_time, 6)

            if result_code == 0:
                status = "OPEN"
                error_message = None
            elif result_code in {
                errno.ECONNREFUSED,
                getattr(errno, "WSAECONNREFUSED", None),
            }:
                status = "CLOSED"
                error_message = None
            else:
                status = "FILTERED"
                error_message = None

            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status=status,
                response_time=elapsed,
                service_name=service_name,
                error_message=error_message,
                timestamp=timestamp,
            )
        except socket.timeout as exc:
            self.logger.warning("TCP scan timed out for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="FILTERED",
                response_time=round(time.perf_counter() - start_time, 6),
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except ConnectionRefusedError as exc:
            self.logger.warning("Connection refused for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="CLOSED",
                response_time=round(time.perf_counter() - start_time, 6),
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except socket.gaierror as exc:
            self.logger.error("DNS lookup failed for %s: %s", validated_host, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except OSError as exc:
            self.logger.error("TCP scan error for %s:%s: %s", validated_host, validated_port, exc)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        except Exception as exc:  # pragma: no cover - defensive guard
            self.logger.exception("Unexpected TCP scan failure for %s:%s", validated_host, validated_port)
            return ScanResult(
                host=validated_host,
                port=validated_port,
                protocol="tcp",
                status="ERROR",
                response_time=None,
                service_name=service_name,
                error_message=str(exc),
                timestamp=timestamp,
            )
        finally:
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    self.logger.debug("Socket close failed for %s:%s", validated_host, validated_port)

    def scan_ports(self, host: str, ports: list[int]) -> list[ScanResult]:
        """Scan multiple TCP ports for a single host in order.

        The method validates the supplied list of ports, reuses :meth:`scan_port`
        for each port, preserves the requested order, and continues scanning even
        if an individual port raises an error.
        """
        if not isinstance(ports, list):
            raise TypeError("ports must be provided as a list of integers")

        if not ports:
            self.logger.info("No ports supplied for TCP scan on %s", host)
            return []

        results: list[ScanResult] = []
        for port in ports:
            self.logger.info("Scanning port %s for host %s", port, host)
            try:
                results.append(self.scan_port(host, port))
            except Exception as exc:  # pragma: no cover - defensive guard
                self.logger.exception("Unexpected failure while scanning %s:%s", host, port)
                results.append(
                    ScanResult(
                        host=str(host),
                        port=int(port) if isinstance(port, int) else 0,
                        protocol="tcp",
                        status="ERROR",
                        response_time=None,
                        service_name="Unknown",
                        error_message=str(exc),
                        timestamp=self._timestamp(),
                    )
                )

        return results

    def scan_range(self, host: str, start_port: int, end_port: int) -> list[ScanResult]:
        """Scan every TCP port in a range for a single host.

        The method validates the full range, builds a sequential list of ports,
        and delegates each scan to :meth:`scan_port` through :meth:`scan_ports`.
        """
        try:
            start, end = validate_port_range(start_port, end_port)
        except (PortValidationError, PortRangeValidationError, TypeError) as exc:
            self.logger.warning("Invalid port range %s-%s: %s", start_port, end_port, exc)
            raise

        ports = list(range(start, end + 1))
        self.logger.info("Scanning TCP range %s-%s for host %s", start, end, host)
        return self.scan_ports(host, ports)

    def scan_ports_threaded(
        self,
        host: str,
        ports: list[int],
        max_workers: int = 10,
        progress_callback: Optional[Callable[[ScanResult, int, int], None]] = None,
    ) -> list[ScanResult]:
        """Scan multiple TCP ports concurrently while preserving request order.

        The method validates the worker count, submits each port to a
        :class:`ThreadPoolExecutor`, reuses :meth:`scan_port` for the actual
        work, and preserves the original order of results by collecting them by
        index.

        If a ``progress_callback`` is provided, it will be called for each
        completed port scan with arguments: (scan_result, completed_count, total_count).
        This allows decoupled progress reporting without coupling the scanner
        to any transport or messaging layer (e.g., WebSockets).
        """
        if not isinstance(ports, list):
            raise TypeError("ports must be provided as a list of integers")

        if not ports:
            self.logger.info("No ports supplied for threaded TCP scan on %s", host)
            return []

        if not isinstance(max_workers, int) or max_workers < 1:
            raise ValueError("max_workers must be a positive integer")

        self.logger.info(
            "Starting threaded TCP scan for %s with %s workers over %s ports",
            host,
            max_workers,
            len(ports),
        )

        start_time = time.perf_counter()
        results: list[ScanResult] = [ScanResult(host=host, port=0, protocol="tcp", status="ERROR") for _ in ports]
        futures_to_index: dict[Future[ScanResult], int] = {}

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for index, port in enumerate(ports):
                self.logger.debug("Submitting port %s for host %s", port, host)
                future = executor.submit(self.scan_port, host, port)
                futures_to_index[future] = index

            completed_count = 0
            for future in as_completed(futures_to_index.keys()):
                index = futures_to_index[future]
                try:
                    result = future.result()
                    results[index] = result
                    completed_count += 1
                    self.logger.debug("Completed scan for port %s", ports[index])

                    # Call the progress callback if provided, allowing the caller
                    # to emit events, log, or otherwise react to each result.
                    if progress_callback is not None:
                        try:
                            progress_callback(result, completed_count, len(ports))
                        except Exception as callback_exc:  # pragma: no cover
                            self.logger.warning(
                                "Progress callback raised exception: %s", callback_exc
                            )
                except Exception as exc:  # pragma: no cover - defensive guard
                    self.logger.exception("Future failed for %s:%s", host, ports[index])
                    result = ScanResult(
                        host=str(host),
                        port=int(ports[index]) if isinstance(ports[index], int) else 0,
                        protocol="tcp",
                        status="ERROR",
                        response_time=None,
                        service_name="Unknown",
                        error_message=str(exc),
                        timestamp=self._timestamp(),
                    )
                    results[index] = result
                    completed_count += 1

                    if progress_callback is not None:
                        try:
                            progress_callback(result, completed_count, len(ports))
                        except Exception as callback_exc:  # pragma: no cover
                            self.logger.warning(
                                "Progress callback raised exception: %s", callback_exc
                            )

        duration = round(time.perf_counter() - start_time, 6)
        self.logger.info(
            "Completed threaded TCP scan for %s in %.6fs",
            host,
            duration,
        )
        return results

    def _validate_host(self, host: str) -> str:
        """Validate the scan target using the shared scanner validators."""
        if not isinstance(host, str) or not host.strip():
            raise ValidationError("Host cannot be empty")

        candidate = host.strip()

        try:
            return validate_ipv4(candidate)
        except IPv4ValidationError:
            pass

        try:
            return validate_ipv6(candidate)
        except IPv6ValidationError:
            pass

        try:
            return validate_hostname(candidate)
        except HostnameValidationError as exc:
            raise ValidationError(f"Invalid host: {exc}") from exc

    def _resolve_address(self, host: str, port: int) -> tuple[int, str, int, str, tuple[object, ...]]:
        """Resolve the host and port to a socket address tuple."""
        try:
            address_info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
        except socket.gaierror as exc:
            raise socket.gaierror(f"Unable to resolve host {host}: {exc}") from exc

        family, _, _, _, sockaddr = address_info[0]
        return family, "", 0, "", sockaddr

    def _resolve_service_name(self, port: int) -> str:
        """Return the well-known service name for the given port if known."""
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "Unknown"

    def _timestamp(self) -> str:
        """Create an ISO 8601 timestamp for scan results."""
        return datetime.now(timezone.utc).isoformat()
