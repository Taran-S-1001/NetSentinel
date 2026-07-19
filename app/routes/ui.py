"""UI routes for the NetSentinel dashboard experience."""

from __future__ import annotations

from io import BytesIO
from typing import Any
from flask_login import login_required, current_user
from flask import (
    Blueprint,
    Response,
    abort,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)

from app.models import PortResult
from app.reporting.report_service import ReportingService
from app.repositories import PortResultRepository, ScheduledScanRepository
from app.schemas import HostScanResult
from app.services import (
    AISecurityAdvisor,
    DashboardService,
    RecommendationEngine,
    ScanComparisonService,
    ScanService,
)

ui_bp = Blueprint("ui", __name__)

@ui_bp.route("/")
@login_required
def dashboard() -> str:
    """Render the main dashboard page."""
    dashboard_service = DashboardService()
    summary = dashboard_service.get_dashboard_summary()
    return render_template(
        "dashboard.html",
        summary=summary,
        title="Dashboard",
        recent_activity=summary.get("recent_scans", []),
    )


@ui_bp.route("/scan", methods=["GET", "POST"])
@login_required
def scan_page() -> str:
    """Render the scan submission page and process new scans."""
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        start_port = request.form.get("start_port", "")
        end_port = request.form.get("end_port", "")
        threads = request.form.get("threads", "10")
        timeout = request.form.get("timeout", "10")

        errors: list[str] = []
        if not host:
            errors.append("Host/IP is required.")
        if not start_port.isdigit() or not end_port.isdigit():
            errors.append("Ports must be numeric.")
        else:
            start = int(start_port)
            end = int(end_port)
            if start < 1 or end < 1 or start > end:
                errors.append("Start port must be less than or equal to end port.")
        if not threads.isdigit() or int(threads) < 1:
            errors.append("Thread count must be a positive integer.")
        if not timeout.isdigit() or int(timeout) < 1:
            errors.append("Timeout must be a positive integer.")

        if errors:
            for message in errors:
                flash(message, "danger")
            return render_template(
                "scan.html",
                host=host,
                start_port=start_port,
                end_port=end_port,
                threads=threads,
                timeout=timeout,
                title="New Scan",
            )

        try:
            current_app.config["DEFAULT_THREADS"] = int(threads)
            current_app.config["DEFAULT_TIMEOUT"] = int(timeout)
            scan_service = ScanService()
            scan_service.start_scan(
                target_host=host,
                ports=list(range(int(start_port), int(end_port) + 1)),
                scan_type="tcp",
                protocol="tcp",
            )
            flash("Scan started successfully.", "success")
            return redirect(url_for("ui.history"))
        except Exception as exc:  # pragma: no cover - defensive guard
            flash(f"Unable to start scan: {exc}", "danger")
            return render_template(
                "scan.html",
                host=host,
                start_port=start_port,
                end_port=end_port,
                threads=threads,
                timeout=timeout,
                title="New Scan",
            )

    return render_template(
        "scan.html",
        title="New Scan",
        threads=current_app.config.get("DEFAULT_THREADS", 10),
        timeout=current_app.config.get("DEFAULT_TIMEOUT", 10),
    )


@ui_bp.route("/history")
@login_required
def history() -> str:
    """Render the scan history page."""
    query = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "").strip().lower()
    scan_service = ScanService()
    scans = scan_service.get_scan_history()

    filtered_scans = []
    for session in scans:
        if query and query not in (session.target_host or "").lower():
            continue
        if status and (session.status or "").lower() != status:
            continue
        filtered_scans.append(session)

    return render_template(
        "history.html",
        scans=filtered_scans,
        title="Scan History",
        query=query,
        status=status,
    )


<<<<<<< HEAD
@ui_bp.route("/schedules", methods=["GET", "POST"])
@login_required
def schedules() -> str:
    """Render the scheduled scans management page."""
    repository = ScheduledScanRepository()
    errors: list[str] = []
    if request.method == "POST":
        host = request.form.get("host", "").strip()
        start_port = request.form.get("start_port", "")
        end_port = request.form.get("end_port", "")
        interval_seconds = request.form.get("interval_seconds", "")
        alert_email = request.form.get("alert_email", "").strip() or None
        alert_webhook = request.form.get("alert_webhook", "").strip() or None
        enabled = request.form.get("enabled") == "on"

        if not host:
            errors.append("Host/IP is required.")
        if not start_port.isdigit() or not end_port.isdigit():
            errors.append("Start port and end port must be numeric.")
        else:
            start = int(start_port)
            end = int(end_port)
            if start < 1 or end < 1 or start > end:
                errors.append("Invalid port range.")
        if not interval_seconds.isdigit() or int(interval_seconds) < 60:
            errors.append("Interval must be at least 60 seconds.")

        if not errors:
            schedule = repository.create(
                target_host=host,
                scan_type="tcp",
                protocol="tcp",
                start_port=int(start_port),
                end_port=int(end_port),
                interval_seconds=int(interval_seconds),
                enabled=enabled,
                alert_email=alert_email,
                alert_webhook=alert_webhook,
            )
            if current_app.config.get("SCHEDULER_ENABLED") and hasattr(current_app, "scheduled_scan_manager"):
                current_app.scheduled_scan_manager.register_schedule(schedule)
            flash("Scheduled scan created successfully.", "success")
            return redirect(url_for("ui.schedules"))

        for message in errors:
            flash(message, "danger")

    schedules = repository.list_all()
    return render_template(
        "schedules.html",
        title="Scheduled Scans",
        schedules=schedules,
=======
@ui_bp.route("/topology")
def topology() -> str:
    """Render the historical network topology graph."""
    dashboard_service = DashboardService()
    topology_data = dashboard_service.get_network_topology()
    return render_template(
        "topology.html",
        topology=topology_data,
        title="Topology",
>>>>>>> origin/feature/realtime-progress-fingerprinting
    )


@ui_bp.route("/scan/<int:scan_id>", methods=["GET"])
@login_required
def scan_details(scan_id: int) -> str:
    """Render the scan detail page for an individual scan."""
    scan_service = ScanService()
    scan = scan_service.get_scan_by_id(scan_id)
    if scan is None:
        abort(404)

    port_results = PortResultRepository().list_for_session(scan_id)
    host_result = _build_host_result(scan, port_results)
    recommendations = RecommendationEngine().generate(host_result)
    security_assessment = AISecurityAdvisor().analyze(host_result, port_results)
    comparison_results = []

    previous_sessions = [item for item in scan_service.get_scan_history() if item.id != scan_id]
    if previous_sessions:
        previous_scan = max(previous_sessions, key=lambda item: item.created_at or item.start_time or item.end_time)
        previous_results = PortResultRepository().list_for_session(previous_scan.id)
        comparison_results = ScanComparisonService().compare(
            previous_scan,
            scan,
            previous_results,
            port_results,
        )

    return render_template(
        "scan_detail.html",
        scan=scan,
        scan_result=host_result,
        port_results=port_results,
        recommendations=recommendations.recommendations,
        security_assessment=security_assessment,
        comparison_results=comparison_results,
        title="Scan Details",
    )


@ui_bp.route("/scan/<int:scan_id>/delete", methods=["POST"])
@login_required
def delete_scan(scan_id: int) -> str:
    """Delete a scan session and redirect back to history."""
    scan_service = ScanService()
    try:
        scan_service.delete_scan(scan_id)
        flash("Scan deleted successfully.", "success")
    except ValueError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("ui.history"))


@ui_bp.route("/analytics")
@login_required
def analytics() -> str:
    """Render the analytics page."""
    dashboard_service = DashboardService()
    summary = dashboard_service.get_dashboard_summary()
    charts = dashboard_service.get_chart_data()
    return render_template("analytics.html", summary=summary, charts=charts, title="Analytics")


@ui_bp.route("/reports")
@login_required
def reports() -> str:
    """Render the enterprise-style reporting page."""
    scan_service = ScanService()
    scans = scan_service.get_scan_history()
    latest_scan = scans[0] if scans else None
    latest_report = None

    if latest_scan is not None:
        port_results = PortResultRepository().list_for_session(latest_scan.id)
        host_result = _build_host_result(latest_scan, port_results)
        security_report = RecommendationEngine().generate(host_result)
        security_assessment = AISecurityAdvisor().analyze(host_result, port_results)
        latest_report = ReportingService().generate_json_report(
            host_result,
            security_report,
            security_assessment,
        )

    return render_template(
        "reports.html",
        scans=scans,
        latest_scan=latest_scan,
        latest_report=latest_report,
        title="Reports",
    )


@ui_bp.route("/reports/<int:scan_id>/<string:report_format>")
@login_required
def download_report(scan_id: int, report_format: str) -> Response | Any:
    """Download a report for a specific scan in PDF, CSV, or JSON format."""
    scan_service = ScanService()
    scan = scan_service.get_scan_by_id(scan_id)
    if scan is None:
        abort(404)

    port_results = PortResultRepository().list_for_session(scan_id)
    host_result = _build_host_result(scan, port_results)
    security_report = RecommendationEngine().generate(host_result)
    security_assessment = AISecurityAdvisor().analyze(host_result, port_results)
    reporting_service = ReportingService()

    if report_format == "pdf":
        content = reporting_service.generate_pdf_report(host_result, security_report, security_assessment)
        return send_file(
            BytesIO(content),
            download_name=f"scan_{scan_id}.pdf",
            mimetype="application/pdf",
        )
    if report_format == "csv":
        content = reporting_service.generate_csv_report(
            host_result,
            port_results=port_results,
            security_assessment=security_assessment,
        )
        return Response(
            content,
            mimetype="text/csv",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.csv"},
        )
    if report_format == "json":
        return Response(
            __import__("json").dumps(
                reporting_service.generate_json_report(host_result, security_report, security_assessment),
                indent=2,
            ),
            mimetype="application/json",
            headers={"Content-Disposition": f"attachment; filename=scan_{scan_id}.json"},
        )
    abort(404)


@ui_bp.route("/settings", methods=["GET", "POST"])
def settings() -> str:
    """Render and persist lightweight system settings for the demo UI."""
    if request.method == "POST":
        current_app.config["DEFAULT_THREADS"] = int(request.form.get("threads", current_app.config.get("DEFAULT_THREADS", 10)))
        current_app.config["DEFAULT_TIMEOUT"] = int(request.form.get("timeout", current_app.config.get("DEFAULT_TIMEOUT", 10)))
        current_app.config["THEME"] = request.form.get("theme", current_app.config.get("THEME", "defense"))
        current_app.config["SCANNER_MODE"] = request.form.get("scanner_mode", current_app.config.get("SCANNER_MODE", "balanced"))
        flash("Settings updated successfully.", "success")
        return redirect(url_for("ui.settings"))

    return render_template(
        "settings.html",
        title="Settings",
        settings={
            "threads": current_app.config.get("DEFAULT_THREADS", 10),
            "timeout": current_app.config.get("DEFAULT_TIMEOUT", 10),
            "theme": current_app.config.get("THEME", "defense"),
            "scanner_mode": current_app.config.get("SCANNER_MODE", "balanced"),
        },
    )


@ui_bp.route("/about")
def about() -> str:
    """Render the product overview and engineering context page."""
    return render_template("about.html", title="About")


def _build_host_result(scan: Any, port_results: list[PortResult]) -> HostScanResult:
    """Create a schema DTO from repository-backed session data."""
    open_ports = [result.port for result in port_results if result.status == "OPEN"]
    statistics = {
        "total_ports": scan.total_ports or len(port_results),
        "open_ports": scan.open_ports or len(open_ports),
        "closed_ports": scan.closed_ports or 0,
        "filtered_ports": scan.filtered_ports or 0,
        "duration": scan.duration,
        "scan_speed": scan.duration and (scan.total_ports or len(port_results)) / max(scan.duration, 1e-9) or 0.0,
        "first_open_port": open_ports[0] if open_ports else None,
        "last_open_port": open_ports[-1] if open_ports else None,
    }
    return HostScanResult(
        scan_id=scan.id,
        target_host=scan.target_host or "Unknown",
        scan_type=scan.scan_type or "tcp",
        protocol=scan.protocol or "tcp",
        total_ports=statistics["total_ports"],
        open_ports=statistics["open_ports"],
        closed_ports=statistics["closed_ports"],
        filtered_ports=statistics["filtered_ports"],
        duration=statistics["duration"],
        scan_speed=statistics["scan_speed"],
        first_open_port=statistics["first_open_port"],
        last_open_port=statistics["last_open_port"],
        most_common_service="Unknown",
        status=scan.status or "completed",
        created_at=scan.created_at.isoformat() if scan.created_at else None,
        open_ports_list=open_ports,
    )
