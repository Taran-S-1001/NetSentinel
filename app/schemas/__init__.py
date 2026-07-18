"""Schema layer for data transfer objects and validation models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(slots=True)
class ServiceChange:
    """Represents a service change observed for a single port."""

    port: int
    previous_service: Optional[str]
    current_service: Optional[str]


@dataclass(slots=True)
class ComparisonReport:
    """Represents the delta between two scan sessions."""

    new_open_ports: list[int]
    closed_ports: list[dict[str, object]]
    service_changes: list[ServiceChange]
    risk_score_difference: int
    duration_difference: float
    statistics_difference: dict[str, int]


@dataclass(slots=True)
class Recommendation:
    """A single security recommendation derived from a scan result."""

    port: int
    recommendation: str
    severity: str
    risk_score: int


@dataclass(slots=True)
class SecurityReport:
    """A report containing all security recommendations for a host scan."""

    target_host: str
    recommendations: list[Recommendation]


@dataclass(slots=True)
class HomePageData:
    """Simple DTO for the home page view model."""

    title: str
    subtitle: str
    scan_count: int
    status: str


@dataclass(slots=True)
class InfrastructureOverview:
    """Operational summary of the scanned infrastructure environment."""

    scanned_hosts: int
    open_ports: int
    critical_hosts: int
    detected_services: int
    last_scan_time: str
    last_scan_at: Optional[str]
    system_health_status: str
    system_health_badge_color: str


@dataclass(slots=True)
class SecurityFinding:
    """A structured security finding identified during assessment."""

    title: str
    severity: str
    description: str


@dataclass(slots=True)
class AdvisorRecommendation:
    """A prioritized recommendation produced by the security advisor."""

    text: str
    priority: str


@dataclass(slots=True)
class SecurityAssessment:
    """AI-assisted security assessment for a completed scan."""

    risk_score: int
    risk_level: str
    executive_summary: str
    findings: list[SecurityFinding]
    recommendations: list[AdvisorRecommendation]
    confidence: int


@dataclass(slots=True)
class HostScanResult:
    """Structured DTO representing the outcome of a completed host scan."""

    scan_id: int
    target_host: str
    scan_type: str
    protocol: str
    total_ports: int
    open_ports: int
    closed_ports: int
    filtered_ports: int
    duration: Optional[float]
    scan_speed: float
    first_open_port: Optional[int]
    last_open_port: Optional[int]
    most_common_service: str
    status: str
    created_at: Optional[str] = None
    open_ports_list: Optional[list[int]] = None
    os_guess: Optional[str] = None  # e.g., "Linux (likely)", "Windows (likely)"
    traceroute_hops: Optional[list[dict[str, object]]] = None  # List of hop dicts
