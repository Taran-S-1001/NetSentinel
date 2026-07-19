"""Dashboard analytics service for NetSentinel."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Any

from app.analytics.charts import ChartBuilder
from app.analytics.statistics import StatisticsBuilder
from app.analytics.trends import TrendBuilder
from app.models import PortResult, ScanSession, TracerouteHop
from app.repositories import (
    PortResultRepository,
    ScanSessionRepository,
    TracerouteHopRepository,
)
from app.schemas import InfrastructureOverview

logger = logging.getLogger("netsentinel.analytics.dashboard")


class DashboardService:
    """Provide dashboard analytics using repository-backed read models."""

    def __init__(
        self,
        *,
        session_repo: ScanSessionRepository | None = None,
        result_repo: PortResultRepository | None = None,
        hop_repo: TracerouteHopRepository | None = None,
    ) -> None:
        self._session_repo = session_repo or ScanSessionRepository()
        self._result_repo = result_repo or PortResultRepository()
        self._hop_repo = hop_repo or TracerouteHopRepository()

    def get_dashboard_summary(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        summary = statistics.build_summary()
        summary["top_services"] = statistics.top_services(limit=10)
        summary["top_hosts"] = statistics.top_hosts(limit=10)
        summary["top_open_ports"] = statistics.top_open_ports(limit=10)
        summary["recent_scans"] = statistics.recent_scans(limit=10)
        trends = self.get_scan_trends()
        summary["daily"] = trends["daily"]
        summary["weekly"] = trends["weekly"]
        summary["monthly"] = trends["monthly"]
        infrastructure_overview = self.get_infrastructure_overview()
        summary["infrastructure_overview"] = infrastructure_overview
        summary["high_risk_hosts"] = infrastructure_overview.critical_hosts
        return summary

    def get_infrastructure_overview(self) -> InfrastructureOverview:
        """Return the infrastructure overview widget payload."""
        from app.services import AnalyticsService

        sessions = self._load_sessions()
        port_results = self._load_port_results(sessions)
        return AnalyticsService(sessions=sessions, port_results=port_results).get_infrastructure_overview()

    def get_port_statistics(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        return {
            "open_ports": statistics.open_ports(),
            "closed_ports": statistics.closed_ports(),
            "filtered_ports": statistics.filtered_ports(),
            "top_open_ports": statistics.top_open_ports(limit=10),
        }

    def get_service_statistics(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        return {"top_services": statistics.top_services(limit=10)}

    def get_scan_trends(self) -> dict[str, Any]:
        sessions = self._load_sessions()
        trend_builder = TrendBuilder(sessions=sessions)
        return {
            "daily": trend_builder.daily_scan_count(),
            "weekly": trend_builder.weekly_scan_count(),
            "monthly": trend_builder.monthly_scan_count(),
        }

    def get_recent_scans(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.recent_scans(limit=limit)

    def get_top_hosts(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.top_hosts(limit=limit)

    def get_top_open_ports(self, limit: int = 10) -> list[dict[str, Any]]:
        statistics = self._build_statistics()
        return statistics.top_open_ports(limit=limit)

    def get_average_scan_duration(self) -> float:
        statistics = self._build_statistics()
        return statistics.average_scan_duration()

    def get_average_scan_speed(self) -> float:
        statistics = self._build_statistics()
        return statistics.average_scan_speed()

    def get_chart_data(self) -> dict[str, Any]:
        statistics = self._build_statistics()
        chart_builder = ChartBuilder(statistics)
        return {
            "service_distribution": chart_builder.pie_chart(
                label="Services",
                values=[{"label": item["service"], "value": item["count"]} for item in statistics.top_services(limit=10)],
            ),
            "port_distribution": chart_builder.doughnut_chart(
                label="Open Ports",
                values=[{"label": str(item["port"]), "value": item["count"]} for item in statistics.top_open_ports(limit=10)],
            ),
            "scan_trend": chart_builder.line_chart(
                label="Scans",
                values=[{"label": item["label"], "value": item["value"]} for item in TrendBuilder(sessions=self._load_sessions()).daily_scan_count()],
            ),
        }

    def get_network_topology(self) -> dict[str, Any]:
        """Aggregate historical traceroute hops into a force-directed graph.

        Returns a payload shaped as::

            {
                "nodes": [{"id", "label", "type": "source"|"hop"|"target", "os_guess"?}],
                "edges": [{"from", "to", "avg_latency_ms"}],
                "empty": bool,
            }

        Duplicate hop IPs across sessions collapse to a single node; edge
        weights are the average ``round_trip_time_ms`` across observations.
        """
        hops = self._hop_repo.list_all()
        if not hops:
            logger.info("No traceroute hops available for topology graph")
            return {"nodes": [], "edges": [], "empty": True}

        sessions = self._load_sessions()
        session_by_id = {session.id: session for session in sessions}
        os_by_host = {
            session.target_host: session.os_guess
            for session in sessions
            if session.target_host and session.os_guess
        }

        nodes: dict[str, dict[str, Any]] = {
            "source": {"id": "source", "label": "Scanner", "type": "source"},
        }
        edge_latencies: dict[tuple[str, str], list[float]] = defaultdict(list)

        hops_by_session: dict[int, list[TracerouteHop]] = defaultdict(list)
        for hop in hops:
            hops_by_session[hop.scan_session_id].append(hop)

        for session_id, session_hops in hops_by_session.items():
            session = session_by_id.get(session_id)
            if session is None:
                continue

            target_id = f"target:{session.target_host}"
            self._ensure_target_node(nodes, target_id, session, os_by_host)

            ordered = sorted(session_hops, key=lambda item: item.hop_number)
            path_ids = ["source"]
            path_rtts: list[float | None] = []

            for hop in ordered:
                if not hop.ip_address:
                    continue
                if hop.ip_address == session.target_host:
                    node_id = target_id
                else:
                    node_id = f"hop:{hop.ip_address}"
                    self._ensure_hop_node(nodes, node_id, hop.ip_address, os_by_host)

                if path_ids and path_ids[-1] == node_id:
                    # Prefer the latest RTT observation for a repeated consecutive hop
                    if path_rtts:
                        path_rtts[-1] = hop.round_trip_time_ms
                    continue

                path_ids.append(node_id)
                path_rtts.append(hop.round_trip_time_ms)

            if path_ids[-1] != target_id:
                path_ids.append(target_id)
                path_rtts.append(None)

            for index in range(len(path_ids) - 1):
                edge_key = (path_ids[index], path_ids[index + 1])
                rtt = path_rtts[index] if index < len(path_rtts) else None
                if rtt is not None:
                    edge_latencies[edge_key].append(float(rtt))
                else:
                    # Keep the edge even when latency was not observed
                    edge_latencies.setdefault(edge_key, [])

        edges = [
            {
                "from": source,
                "to": destination,
                "avg_latency_ms": (
                    round(sum(latencies) / len(latencies), 2) if latencies else None
                ),
            }
            for (source, destination), latencies in edge_latencies.items()
        ]

        logger.info(
            "Built network topology with %d nodes and %d edges",
            len(nodes),
            len(edges),
        )
        return {"nodes": list(nodes.values()), "edges": edges, "empty": False}

    @staticmethod
    def _ensure_target_node(
        nodes: dict[str, dict[str, Any]],
        target_id: str,
        session: ScanSession,
        os_by_host: dict[str, str],
    ) -> None:
        """Create or refresh a target node from a scan session."""
        os_guess = session.os_guess or os_by_host.get(session.target_host)
        if target_id not in nodes:
            node: dict[str, Any] = {
                "id": target_id,
                "label": session.target_host,
                "type": "target",
            }
            if os_guess:
                node["os_guess"] = os_guess
                node["label"] = f"{session.target_host} ({os_guess})"
            nodes[target_id] = node
            return

        if os_guess and not nodes[target_id].get("os_guess"):
            nodes[target_id]["os_guess"] = os_guess
            nodes[target_id]["label"] = f"{session.target_host} ({os_guess})"

    @staticmethod
    def _ensure_hop_node(
        nodes: dict[str, dict[str, Any]],
        node_id: str,
        ip_address: str,
        os_by_host: dict[str, str],
    ) -> None:
        """Create a hop node, merging duplicates by IP address."""
        if node_id in nodes:
            return
        os_guess = os_by_host.get(ip_address)
        node: dict[str, Any] = {
            "id": node_id,
            "label": ip_address,
            "type": "hop",
        }
        if os_guess:
            node["os_guess"] = os_guess
            node["label"] = f"{ip_address} ({os_guess})"
        nodes[node_id] = node

    def _build_statistics(self) -> StatisticsBuilder:
        sessions = self._load_sessions()
        port_results = self._load_port_results(sessions)
        return StatisticsBuilder(sessions=sessions, port_results=port_results)

    def _load_sessions(self) -> list[ScanSession]:
        return self._session_repo.list_all()

    def _load_port_results(self, sessions: list[ScanSession]) -> list[PortResult]:
        results: list[PortResult] = []
        for session in sessions:
            results.extend(self._result_repo.list_for_session(session.id))
        return results
