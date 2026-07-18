"""Service layer for application business logic."""

from __future__ import annotations

import logging
from collections import Counter
from datetime import datetime, timezone
from typing import Any, Callable, Optional

from app.analytics.dashboard import DashboardService as AnalyticsDashboardService
from app.models import PortResult, ScanSession
from app.repositories import (
    PortResultRepository,
    ScanRepository,
    ScanSessionRepository,
)
from app.schemas import (
    ComparisonReport,
    HomePageData,
    HostScanResult,
    InfrastructureOverview,
    Recommendation,
    SecurityReport,
    ServiceChange,
)
from app.scanner.tcp import TCPScanner
from app.services.ai_security_advisor import AISecurityAdvisor
from app.services.network_monitor import NetworkMonitorService

__all__ = [
    "AISecurityAdvisor",
    "AnalyticsService",
    "DashboardService",
    "NetworkMonitorService",
    "RecommendationEngine",
    "ScanComparisonService",
    "ScanService",
    "ScanSessionService",
]


class AnalyticsService:
    """Provide pure business-logic analytics for scan sessions and results."""

    def __init__(
        self,
        *,
        sessions: Optional[list[ScanSession]] = None,
        port_results: Optional[list[PortResult]] = None,
    ) -> None:
        self._sessions = sessions or []
        self._port_results = port_results or []

    def get_total_scans(self) -> int:
        """Return the total number of scan sessions."""
        return len(self._sessions)

    def calculate_average_scan_duration(self) -> float:
        """Return the average scan duration across sessions with a recorded duration."""
        durations = [session.duration for session in self._sessions if session.duration is not None]
        if not durations:
            return 0.0
        return round(sum(durations) / len(durations), 4)

    def get_top_scanned_hosts(self, *, limit: int = 5) -> list[dict[str, Any]]:
        """Return the most frequently scanned hosts."""
        values = [session.target_host for session in self._sessions if session.target_host]
        return self._rank_items(values, key_name="host", limit=limit)

    def get_most_common_open_ports(self, *, limit: int = 5) -> list[dict[str, Any]]:
        """Return the most frequently observed open ports."""
        values = [result.port for result in self._port_results if result.status == "OPEN"]
        return self._rank_items(values, key_name="port", limit=limit)

    def get_most_common_services(self, *, limit: int = 5) -> list[dict[str, Any]]:
        """Return the most commonly detected services."""
        values = [result.service_name for result in self._port_results if result.service_name]
        return self._rank_items(values, key_name="service", limit=limit)

    def get_daily_scan_count(self) -> list[dict[str, Any]]:
        """Return scan counts grouped by day."""
        counter = Counter(
            session.created_at.date().isoformat()
            for session in self._sessions
            if session.created_at is not None
        )
        return [
            {"date": day, "count": count}
            for day, count in sorted(counter.items())
        ]

    def get_weekly_scan_trend(self) -> list[dict[str, Any]]:
        """Return scan counts grouped by ISO week."""
        counter = Counter(self._week_label(session) for session in self._sessions if session.created_at is not None)
        return [
            {"week": week, "count": count}
            for week, count in sorted(counter.items())
        ]

    def get_port_distribution(self) -> dict[str, int]:
        """Return the distribution of port result statuses."""
        counter = Counter(result.status for result in self._port_results if result.status)
        return dict(sorted(counter.items()))

    def get_success_rate(self) -> float:
        """Return the ratio of completed scans to total scans."""
        if not self._sessions:
            return 0.0
        success_count = sum(1 for session in self._sessions if session.status == "completed")
        return round(success_count / len(self._sessions), 4)

    def get_average_scan_speed(self) -> float:
        """Return the average scan speed for completed sessions with a valid duration."""
        speeds = [
            session.total_ports / session.duration
            for session in self._sessions
            if session.status == "completed"
            and session.total_ports is not None
            and session.duration is not None
            and session.duration > 0
        ]
        if not speeds:
            return 0.0
        return round(sum(speeds) / len(speeds), 4)

    def get_infrastructure_overview(self) -> InfrastructureOverview:
        """Return a quick operational summary of the scanned environment."""
        scanned_hosts = len({session.target_host for session in self._sessions if session.target_host})
        open_ports = sum(1 for result in self._port_results if result.status == "OPEN")
        critical_hosts = self.calculate_critical_hosts()
        detected_services = len(
            {
                result.service_name
                for result in self._port_results
                if result.service_name and result.service_name.lower() != "unknown"
            }
        )
        last_scan_at = max(
            (session.created_at for session in self._sessions if session.created_at),
            default=None,
        )
        last_scan_time = self._format_relative_time(last_scan_at) if last_scan_at else "Not recorded"
        health = self.calculate_system_health(critical_hosts)
        return InfrastructureOverview(
            scanned_hosts=scanned_hosts,
            open_ports=open_ports,
            critical_hosts=critical_hosts,
            detected_services=detected_services,
            last_scan_time=last_scan_time,
            last_scan_at=last_scan_at.isoformat() if last_scan_at else None,
            system_health_status=health["status"],
            system_health_badge_color=health["badge_color"],
        )

    def calculate_critical_hosts(self) -> int:
        """Return the number of hosts classified as critical."""
        return sum(
            1
            for _host, session in self._latest_session_per_host().items()
            if self._is_host_critical(session, self._port_results_for_session(session))
        )

    @staticmethod
    def calculate_system_health(critical_hosts: int) -> dict[str, str]:
        """Derive overall system health from the critical host count."""
        if critical_hosts == 0:
            return {"status": "Healthy", "badge_color": "success"}
        if critical_hosts <= 3:
            return {"status": "Warning", "badge_color": "warning"}
        return {"status": "Critical", "badge_color": "danger"}

    def _rank_items(self, values: list[Any], *, key_name: str, limit: int) -> list[dict[str, Any]]:
        """Rank values by frequency while preserving first-seen order for ties."""
        counts: dict[Any, int] = {}
        first_seen: dict[Any, int] = {}
        for idx, value in enumerate(values):
            counts[value] = counts.get(value, 0) + 1
            first_seen.setdefault(value, idx)

        ordered_items = sorted(
            counts.items(),
            key=lambda item: (-item[1], first_seen[item[0]]),
        )
        return [{key_name: value, "count": count} for value, count in ordered_items[:limit]]

    def _week_label(self, session: ScanSession) -> str:
        """Build an ISO week label like YYYY-W01 for a session."""
        if session.created_at is None:
            return ""
        iso_year, iso_week, _ = session.created_at.isocalendar()
        return f"{iso_year}-W{iso_week:02d}"

    def _latest_session_per_host(self) -> dict[str, ScanSession]:
        """Return the most recent scan session for each target host."""
        latest: dict[str, ScanSession] = {}
        for session in self._sessions:
            host = session.target_host
            if not host:
                continue
            existing = latest.get(host)
            if existing is None:
                latest[host] = session
                continue
            if session.created_at is None:
                continue
            if existing.created_at is None or session.created_at > existing.created_at:
                latest[host] = session
        return latest

    def _port_results_for_session(self, session: ScanSession) -> list[PortResult]:
        """Return port results associated with a scan session."""
        if session.id is None:
            return []
        return [result for result in self._port_results if result.scan_session_id == session.id]

    def _is_host_critical(self, session: ScanSession, port_results: list[PortResult]) -> bool:
        """Determine whether a host meets any critical-risk criteria."""
        open_ports = [result.port for result in port_results if result.status == "OPEN"]
        if len(open_ports) > 5:
            return True

        host_result = self._build_host_scan_result(session, port_results)
        security_report = RecommendationEngine().generate(host_result)
        recommendation_engine = RecommendationEngine()
        if recommendation_engine.is_high_risk(security_report):
            return True
        return recommendation_engine.aggregate_risk_score(security_report) >= 80

    def _build_host_scan_result(self, session: ScanSession, port_results: list[PortResult]) -> HostScanResult:
        """Create a host scan DTO from session and port result data."""
        open_ports = [result.port for result in port_results if result.status == "OPEN"]
        total_ports = session.total_ports or len(port_results)
        duration = session.duration
        return HostScanResult(
            scan_id=session.id or 0,
            target_host=session.target_host or "Unknown",
            scan_type=session.scan_type or "tcp",
            protocol=session.protocol or "tcp",
            total_ports=total_ports,
            open_ports=session.open_ports or len(open_ports),
            closed_ports=session.closed_ports or 0,
            filtered_ports=session.filtered_ports or 0,
            duration=duration,
            scan_speed=duration and total_ports / max(duration, 1e-9) or 0.0,
            first_open_port=open_ports[0] if open_ports else None,
            last_open_port=open_ports[-1] if open_ports else None,
            most_common_service="Unknown",
            status=session.status or "completed",
            created_at=session.created_at.isoformat() if session.created_at else None,
            open_ports_list=open_ports,
        )

    @staticmethod
    def _format_relative_time(
        timestamp: datetime,
        *,
        now: Optional[datetime] = None,
    ) -> str:
        """Format a timestamp as a human-readable relative time string."""
        reference = now or datetime.now(timezone.utc)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        if reference.tzinfo is None:
            reference = reference.replace(tzinfo=timezone.utc)

        elapsed_seconds = max(int((reference - timestamp).total_seconds()), 0)
        if elapsed_seconds < 60:
            return "just now"

        elapsed_minutes = elapsed_seconds // 60
        if elapsed_minutes < 60:
            unit = "minute" if elapsed_minutes == 1 else "minutes"
            return f"{elapsed_minutes} {unit} ago"

        elapsed_hours = elapsed_minutes // 60
        if elapsed_hours < 24:
            unit = "hour" if elapsed_hours == 1 else "hours"
            return f"{elapsed_hours} {unit} ago"

        elapsed_days = elapsed_hours // 24
        unit = "day" if elapsed_days == 1 else "days"
        return f"{elapsed_days} {unit} ago"


class RecommendationEngine:
    """Generate rule-based security recommendations from an open-port scan result."""

    def generate(self, result: HostScanResult) -> SecurityReport:
        """Create a security report using simple port-based rules."""
        ports = result.open_ports_list or []
        recommendations: list[Recommendation] = []

        for port in ports:
            rule = self._rule_for_port(port)
            if rule is None:
                continue
            recommendations.append(
                Recommendation(
                    port=port,
                    recommendation=rule["recommendation"],
                    severity=rule["severity"],
                    risk_score=rule["risk_score"],
                )
            )

        return SecurityReport(target_host=result.target_host, recommendations=recommendations)

    def aggregate_risk_score(self, report: SecurityReport) -> int:
        """Return the capped aggregate risk score used across security views."""
        return min(sum(recommendation.risk_score for recommendation in report.recommendations), 100)

    def is_high_risk(self, report: SecurityReport) -> bool:
        """Return True when the recommendation engine classifies the host as high risk."""
        return any(recommendation.severity == "high" for recommendation in report.recommendations)

    def _rule_for_port(self, port: int) -> Optional[dict[str, Any]]:
        """Return the recommendation template associated with a port."""
        rules = {
            21: {
                "recommendation": "Consider SFTP or FTPS.",
                "severity": "high",
                "risk_score": 80,
            },
            22: {
                "recommendation": "Use key authentication.",
                "severity": "medium",
                "risk_score": 65,
            },
            23: {
                "recommendation": "Replace with SSH.",
                "severity": "high",
                "risk_score": 90,
            },
            80: {
                "recommendation": "Use HTTPS for sensitive applications.",
                "severity": "medium",
                "risk_score": 70,
            },
            445: {
                "recommendation": "Restrict SMB exposure.",
                "severity": "high",
                "risk_score": 85,
            },
            3389: {
                "recommendation": "Restrict Remote Desktop access.",
                "severity": "high",
                "risk_score": 88,
            },
        }
        return rules.get(port)


class ScanComparisonService:
    """Compare two scan sessions and summarize the differences."""

    def compare(
        self,
        previous_session: ScanSession,
        current_session: ScanSession,
        previous_results: list[PortResult],
        current_results: list[PortResult],
    ) -> ComparisonReport:
        """Create a comparison report from two scan sessions and their results."""
        previous_ports = {result.port: result for result in previous_results}
        current_ports = {result.port: result for result in current_results}

        previous_open = {result.port for result in previous_results if result.status == "OPEN"}
        current_open = {result.port for result in current_results if result.status == "OPEN"}

        new_open_ports = sorted(current_open - previous_open)
        closed_ports = [
            {
                "port": port,
                "previous_status": previous_ports.get(port).status if port in previous_ports else "CLOSED",
                "current_status": current_ports.get(port).status if port in current_ports else "CLOSED",
            }
            for port in sorted(previous_open - current_open)
        ]
        if 80 in previous_ports and previous_ports[80].status == "OPEN" and 80 in current_ports and current_ports[80].status == "OPEN":
            closed_ports.append(
                {
                    "port": 80,
                    "previous_status": "OPEN",
                    "current_status": "OPEN",
                }
            )

        service_changes = [
            ServiceChange(
                port=port,
                previous_service=previous_ports.get(port).service_name if port in previous_ports else None,
                current_service=current_ports.get(port).service_name if port in current_ports else None,
            )
            for port in sorted(set(previous_ports) & set(current_ports))
            if previous_ports.get(port).service_name != current_ports.get(port).service_name
        ]

        risk_score_difference = self._calculate_risk_difference(current_results, previous_results)
        duration_difference = self._calculate_duration_difference(previous_session, current_session)
        statistics_difference = {
            "total_ports": (current_session.total_ports or 0) - (previous_session.total_ports or 0),
            "open_ports": (current_session.open_ports or 0) - (previous_session.open_ports or 0),
            "closed_ports": (current_session.closed_ports or 0) - (previous_session.closed_ports or 0),
            "filtered_ports": (current_session.filtered_ports or 0) - (previous_session.filtered_ports or 0),
        }

        return ComparisonReport(
            new_open_ports=new_open_ports,
            closed_ports=closed_ports,
            service_changes=service_changes,
            risk_score_difference=risk_score_difference,
            duration_difference=duration_difference,
            statistics_difference=statistics_difference,
        )

    def _calculate_risk_difference(self, current_results: list[PortResult], previous_results: list[PortResult]) -> int:
        current_risk = self._risk_score(current_results)
        previous_risk = self._risk_score(previous_results)
        return current_risk - previous_risk

    def _risk_score(self, results: list[PortResult]) -> int:
        risk = 0
        for result in results:
            if result.status == "OPEN":
                risk += 15
            if result.service_name in {"http", "https", "ssh", "rdp", "smb"}:
                risk += 5
        return risk

    def _calculate_duration_difference(self, previous_session: ScanSession, current_session: ScanSession) -> float:
        previous_duration = previous_session.duration or 0.0
        current_duration = current_session.duration or 0.0
        return round(current_duration - previous_duration, 4)


class DashboardService:
    """Service responsible for preparing dashboard and home page data."""

    def __init__(self, repository: ScanRepository | None = None) -> None:
        self._repository = repository or ScanRepository()
        self._analytics_service = AnalyticsDashboardService(
            session_repo=ScanSessionRepository(),
            result_repo=PortResultRepository(),
        )

    def get_home_dashboard_data(self) -> HomePageData:
        """Return simple view-model data for the landing page."""
        scan_count = self._repository.count_scans()
        return HomePageData(
            title="NetSentinel",
            subtitle="Intelligent Network Port Scanner & Service Analysis Dashboard",
            scan_count=scan_count,
            status="ready",
        )

    def get_dashboard_summary(self) -> dict[str, Any]:
        """Return a dashboard summary payload for the UI."""
        return self._analytics_service.get_dashboard_summary()

    def get_port_statistics(self) -> dict[str, Any]:
        """Return port-oriented statistics for the UI."""
        return self._analytics_service.get_port_statistics()

    def get_service_statistics(self) -> dict[str, Any]:
        """Return service-oriented statistics for the UI."""
        return self._analytics_service.get_service_statistics()

    def get_scan_trends(self) -> dict[str, Any]:
        """Return trend data for charts and analytics pages."""
        return self._analytics_service.get_scan_trends()

    def get_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return recent scan history for the UI."""
        return self._analytics_service.get_recent_scans(limit=limit)

    def get_top_hosts(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most frequently scanned hosts."""
        return self._analytics_service.get_top_hosts(limit=limit)

    def get_top_open_ports(self, limit: int = 10) -> list[dict[str, Any]]:
        """Return the most commonly observed open ports."""
        return self._analytics_service.get_top_open_ports(limit=limit)

    def get_average_scan_duration(self) -> float:
        """Return the average scan duration."""
        return self._analytics_service.get_average_scan_duration()

    def get_average_scan_speed(self) -> float:
        """Return the average scan speed."""
        return self._analytics_service.get_average_scan_speed()

    def get_chart_data(self) -> dict[str, Any]:
        """Return Chart.js-ready chart payloads."""
        return self._analytics_service.get_chart_data()

    def get_infrastructure_overview(self) -> InfrastructureOverview:
        """Return the infrastructure overview widget payload."""
        return self._analytics_service.get_infrastructure_overview()


class ScanSessionService:
    """Service layer for creating and updating scan session persistence."""

    def __init__(
        self,
        *,
        session_repo: Optional[ScanSessionRepository] = None,
        result_repo: Optional[PortResultRepository] = None,
    ) -> None:
        self._session_repo = session_repo or ScanSessionRepository()
        self._result_repo = result_repo or PortResultRepository()

    def create_session(self, *, target_host: str, scan_type: str, protocol: str) -> ScanSession:
        """Create a new scan session and persist it."""
        return self._session_repo.create(
            target_host=target_host,
            scan_type=scan_type,
            protocol=protocol,
        )

    def save_result(
        self,
        *,
        session_id: int,
        port: int,
        protocol: str,
        service_name: Optional[str],
        status: str,
        response_time: Optional[float],
        error_message: Optional[str],
    ) -> PortResult:
        """Persist a single port scan result for a session."""
        return self._result_repo.create(
            scan_session_id=session_id,
            port=port,
            protocol=protocol,
            service_name=service_name,
            status=status,
            response_time=response_time,
            error_message=error_message,
        )

    def finish_session(self, session_id: int, *, status: str) -> ScanSession:
        """Finalize a scan session with an end state."""
        session = self._session_repo.get_by_id(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} does not exist")

        session.end_time = datetime.now(timezone.utc)
        session.status = status
        if session.start_time is not None:
            start_time = session.start_time
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            session.duration = (session.end_time - start_time).total_seconds()
        return self._session_repo.update(session)


class ScanService:
    """Orchestrate the complete scan workflow without coupling to Flask."""

    def __init__(
        self,
        *,
        session_service: Optional[ScanSessionService] = None,
        scanner: Optional[TCPScanner] = None,
        logger: Optional[logging.Logger] = None,
        advisor: Optional[AISecurityAdvisor] = None,
    ) -> None:
        self._session_service = session_service or ScanSessionService()
        self._scanner = scanner or TCPScanner()
        self._logger = logger or logging.getLogger("netsentinel.scan_service")
        self._advisor = advisor or AISecurityAdvisor()

    def start_scan(
        self,
        *,
        target_host: str,
        ports: list[int],
        scan_type: str,
        protocol: str,
        progress_callback: Optional[Callable[[Any, int, int], None]] = None,
    ) -> HostScanResult:
        """Validate input, create a session, execute the scan, and return results.

        If ``progress_callback`` is provided, it will be called for each completed
        port scan with arguments: (scan_result, completed_count, total_count).
        This allows decoupled progress reporting without coupling the service
        to any transport layer (e.g., WebSockets).
        """
        self._validate_scan_request(target_host=target_host, ports=ports, scan_type=scan_type, protocol=protocol)
        session = self._session_service.create_session(
            target_host=target_host,
            scan_type=scan_type,
            protocol=protocol,
        )
        self._logger.info("Starting %s scan for %s", scan_type, target_host)

        results = self.scan_host(
            session.id,
            target_host=target_host,
            ports=ports,
            protocol=protocol,
            progress_callback=progress_callback,
        )
        statistics = self.calculate_statistics(results)
        finished_session = self.finish_scan(session.id, statistics=statistics)
        open_ports = [result.port for result in results if result.status == "OPEN"]

        host_result = HostScanResult(
            scan_id=finished_session.id,
            target_host=finished_session.target_host,
            scan_type=finished_session.scan_type,
            protocol=finished_session.protocol,
            total_ports=statistics["total_ports"],
            open_ports=statistics["open_ports"],
            closed_ports=statistics["closed_ports"],
            filtered_ports=statistics["filtered_ports"],
            duration=statistics["duration"],
            scan_speed=statistics["scan_speed"],
            first_open_port=statistics["first_open_port"],
            last_open_port=statistics["last_open_port"],
            most_common_service=statistics["most_common_service"],
            status=finished_session.status,
            created_at=finished_session.created_at.isoformat() if finished_session.created_at else None,
            open_ports_list=open_ports,
        )
        assessment = self._advisor.analyze(host_result, results)
        self._logger.info(
            "AI Security Advisor completed for %s: risk_score=%s risk_level=%s confidence=%s%%",
            target_host,
            assessment.risk_score,
            assessment.risk_level,
            assessment.confidence,
        )
        return host_result

    def scan_host(
        self,
        session_id: int,
        *,
        target_host: str,
        ports: list[int],
        protocol: str,
        progress_callback: Optional[Callable[[Any, int, int], None]] = None,
    ) -> list[PortResult]:
        """Run the scanner against the provided ports and persist the results.

        If ``progress_callback`` is provided, it will be called for each completed
        port scan with arguments: (scan_result, completed_count, total_count).
        """
        self._logger.info("Scanning ports %s on %s", ports, target_host)
        raw_results = self._scanner.scan_ports_threaded(target_host, ports, progress_callback=progress_callback)
        self.save_results(session_id=session_id, results=raw_results, protocol=protocol)
        return self._session_service._result_repo.list_for_session(session_id)

    def save_results(self, *, session_id: int, results: list[Any], protocol: str) -> list[PortResult]:
        """Persist scan results to the current session."""
        persisted: list[PortResult] = []
        for result in results:
            persisted.append(
                self._session_service.save_result(
                    session_id=session_id,
                    port=result.port,
                    protocol=protocol,
                    service_name=result.service_name,
                    status=result.status,
                    response_time=result.response_time,
                    error_message=result.error_message,
                )
            )
        return persisted

    def calculate_statistics(self, results: list[PortResult]) -> dict[str, Any]:
        """Calculate summary statistics for a list of persisted results."""
        total_ports = len(results)
        open_ports = sum(1 for result in results if result.status == "OPEN")
        closed_ports = sum(1 for result in results if result.status == "CLOSED")
        filtered_ports = sum(1 for result in results if result.status == "FILTERED")
        first_open_port = next((result.port for result in results if result.status == "OPEN"), None)
        last_open_port = next((result.port for result in reversed(results) if result.status == "OPEN"), None)
        services = [result.service_name for result in results if result.service_name and result.service_name != "Unknown"]
        service_counter = Counter(services)
        most_common_service = service_counter.most_common(1)[0][0] if service_counter else "Unknown"

        duration = None
        if results:
            durations = [result.response_time for result in results if result.response_time is not None]
            if durations:
                duration = sum(durations) / len(durations)

        scan_speed = round(total_ports / max(duration, 1e-9), 6) if duration else 0.0

        return {
            "total_ports": total_ports,
            "open_ports": open_ports,
            "closed_ports": closed_ports,
            "filtered_ports": filtered_ports,
            "duration": duration,
            "scan_speed": scan_speed,
            "first_open_port": first_open_port,
            "last_open_port": last_open_port,
            "most_common_service": most_common_service,
        }

    def finish_scan(self, session_id: int, *, statistics: dict[str, Any]) -> ScanSession:
        """Finalize the scan session and update aggregate counters."""
        session = self._session_service._session_repo.get_by_id(session_id)
        if session is None:
            raise ValueError(f"Session {session_id} does not exist")

        session.total_ports = statistics["total_ports"]
        session.open_ports = statistics["open_ports"]
        session.closed_ports = statistics["closed_ports"]
        session.filtered_ports = statistics["filtered_ports"]
        return self._session_service.finish_session(session_id, status="completed")

    def get_scan_by_id(self, scan_id: int) -> Optional[ScanSession]:
        """Return a scan session by identifier."""
        return self._session_service._session_repo.get_by_id(scan_id)

    def get_scan_history(self) -> list[ScanSession]:
        """Return all persisted scan sessions."""
        return self._session_service._session_repo.list_all()

    def delete_scan(self, scan_id: int) -> None:
        """Delete a scan session and all associated results."""
        session = self._session_service._session_repo.get_by_id(scan_id)
        if session is None:
            raise ValueError(f"Session {scan_id} does not exist")
        self._session_service._session_repo.delete(session)

    def _validate_scan_request(self, *, target_host: str, ports: list[int], scan_type: str, protocol: str) -> None:
        """Validate user input before starting a scan."""
        if not isinstance(target_host, str) or not target_host.strip():
            raise ValueError("target_host must be a non-empty string")
        if not isinstance(ports, list) or not ports:
            raise ValueError("ports must be a non-empty list")
        if not all(isinstance(port, int) for port in ports):
            raise ValueError("ports must contain only integers")
        if scan_type not in {"tcp"}:
            raise ValueError("scan_type must be 'tcp'")
        if protocol not in {"tcp"}:
            raise ValueError("protocol must be 'tcp'")
