"""Scheduled scan execution and alert delivery.

This module adds recurring scan orchestration using APScheduler and sends
alerts for port changes, service changes, or closed ports via email and
webhook endpoints.
"""

from __future__ import annotations

import logging
import smtplib
from datetime import datetime, timezone
from email.message import EmailMessage
from typing import Optional

import requests
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from flask import Flask, current_app

from app.models import ScanSession, ScheduledScan
from app.repositories import (
    PortResultRepository,
    ScanSessionRepository,
    ScheduledScanRepository,
)
from app.schemas import ComparisonReport
from app.services import ScanComparisonService, ScanService

logger = logging.getLogger("netsentinel.scheduled_scan")


class ScheduledScanManager:
    """Manage scheduled scan jobs and alert delivery."""

    def __init__(
        self,
        app: Flask,
        *,
        schedule_repo: Optional[ScheduledScanRepository] = None,
        scan_service: Optional[ScanService] = None,
        comparison_service: Optional[ScanComparisonService] = None,
    ) -> None:
        self.app = app
        self.scheduler = BackgroundScheduler(timezone=timezone.utc)
        self._schedule_repo = schedule_repo or ScheduledScanRepository()
        self._scan_service = scan_service or ScanService()
        self._comparison_service = comparison_service or ScanComparisonService()

    def start(self) -> None:
        """Start the scheduler and register active jobs."""
        with self.app.app_context():
            for schedule in self._schedule_repo.list_active():
                self._register_job(schedule)

        self.scheduler.start()
        logger.info(
            "Scheduled scan manager started with %s registered jobs",
            len(self.scheduler.get_jobs()),
        )

    def shutdown(self) -> None:
        """Stop the background scheduler."""
        if self.scheduler.running:
            self.scheduler.shutdown(wait=False)
        logger.info("Scheduled scan manager stopped")

    def register_schedule(self, schedule: ScheduledScan) -> None:
        """Register a schedule with the running scheduler."""
        if schedule.enabled:
            self._register_job(schedule)

    def remove_schedule(self, schedule_id: int) -> None:
        """Remove a scheduled job by schedule identifier."""
        job_id = self._job_id(schedule_id)
        try:
            self.scheduler.remove_job(job_id)
        except Exception as exc:
            logger.warning("Unable to remove scheduled scan job %s: %s", job_id, exc)

    def _register_job(self, schedule: ScheduledScan) -> None:
        if not schedule.interval_seconds or schedule.interval_seconds < 1:
            logger.warning(
                "Scheduled scan %s has invalid interval_seconds=%s, skipping",
                schedule.id,
                schedule.interval_seconds,
            )
            return

        self.scheduler.add_job(
            func=self._run_job,
            trigger=IntervalTrigger(seconds=schedule.interval_seconds),
            id=self._job_id(schedule.id),
            args=[schedule.id],
            replace_existing=True,
            coalesce=False,
            max_instances=1,
        )
        logger.info(
            "Scheduled scan job registered: %s every %s seconds",
            self._job_id(schedule.id),
            schedule.interval_seconds,
        )

    def _job_id(self, schedule_id: int) -> str:
        return f"scheduled_scan_{schedule_id}"

    def _run_job(self, schedule_id: int) -> None:
        with self.app.app_context():
            schedule = self._schedule_repo.get_by_id(schedule_id)
            if schedule is None:
                logger.warning("Scheduled scan id %s no longer exists", schedule_id)
                return

            if not schedule.enabled:
                logger.info("Skipping disabled scheduled scan %s", schedule_id)
                return

            try:
                logger.info(
                    "Running scheduled scan %s for %s",
                    schedule.id,
                    schedule.target_host,
                )
                result = self._scan_service.start_scan(
                    target_host=schedule.target_host,
                    ports=list(range(schedule.start_port, schedule.end_port + 1)),
                    scan_type=schedule.scan_type,
                    protocol=schedule.protocol,
                    user_id=schedule.user_id,
                )

                current_session = self._scan_service.get_scan_by_id(
                    result.scan_id,
                    user_id=schedule.user_id,
                )
                previous_session = self._find_previous_session(
                    schedule.target_host,
                    current_session.id if current_session else None,
                )

                if previous_session is not None and current_session is not None:
                    previous_results = PortResultRepository().list_for_session(previous_session.id)
                    current_results = PortResultRepository().list_for_session(current_session.id)
                    comparison = self._comparison_service.compare(
                        previous_session,
                        current_session,
                        previous_results,
                        current_results,
                    )
                    if self._should_alert(comparison):
                        self._raise_alert(schedule, comparison, previous_session, current_session)

                schedule.last_run_at = datetime.now(timezone.utc)
                schedule.last_status = "completed"
            except Exception:
                logger.exception("Scheduled scan %s failed", schedule_id)
                schedule.last_run_at = datetime.now(timezone.utc)
                schedule.last_status = "failed"
            finally:
                self._schedule_repo.update(schedule)

    def _find_previous_session(
        self,
        target_host: str,
        current_scan_id: Optional[int],
    ) -> Optional[ScanSession]:
        sessions = ScanSessionRepository().list_by_host(target_host)
        previous = [session for session in sessions if session.id != current_scan_id]
        if not previous:
            return None
        return max(
            previous,
            key=lambda session: session.created_at or session.start_time or datetime(1970, 1, 1, tzinfo=timezone.utc),
        )

    @staticmethod
    def _should_alert(comparison: ComparisonReport) -> bool:
        return bool(
            comparison.new_open_ports
            or comparison.closed_ports
            or comparison.service_changes
        )

    def _raise_alert(
        self,
        schedule: ScheduledScan,
        comparison: ComparisonReport,
        previous: ScanSession,
        current: ScanSession,
    ) -> None:
        subject = f"NetSentinel scheduled scan alert for {schedule.target_host}"
        body_lines = [
            f"Scheduled scan {schedule.id} detected changes for {schedule.target_host}.",
            f"Port range: {schedule.start_port}-{schedule.end_port}",
            "",
        ]

        if comparison.new_open_ports:
            body_lines.append(
                f"New open ports: {', '.join(str(port) for port in comparison.new_open_ports)}"
            )

        if comparison.closed_ports:
            closed_ports = ", ".join(str(port_info["port"]) for port_info in comparison.closed_ports)
            body_lines.append(f"Closed ports: {closed_ports}")

        if comparison.service_changes:
            body_lines.append("Service changes:")
            for change in comparison.service_changes:
                body_lines.append(
                    f" - Port {change.port}: {change.previous_service or 'Unknown'} → {change.current_service or 'Unknown'}"
                )

        body_lines.extend(
            [
                "",
                f"Previous scan: {previous.id} at {previous.created_at.isoformat() if previous.created_at else 'unknown'}",
                f"Current scan: {current.id} at {current.created_at.isoformat() if current.created_at else 'unknown'}",
            ]
        )
        body = "\n".join(body_lines)

        if schedule.alert_email:
            try:
                self._send_email(schedule.alert_email, subject, body)
            except Exception:
                logger.exception("Failed to send scheduled scan email alert for schedule %s", schedule.id)

        if schedule.alert_webhook:
            try:
                self._send_webhook(schedule.alert_webhook, subject, body, schedule)
            except Exception:
                logger.exception("Failed to send scheduled scan webhook for schedule %s", schedule.id)

    @staticmethod
    def _send_email(recipients: str, subject: str, body: str) -> None:
        recipients_list = [email.strip() for email in recipients.split(",") if email.strip()]
        if not recipients_list:
            raise ValueError("No valid alert email recipient configured")

        message = EmailMessage()
        message["Subject"] = subject
        message["From"] = current_app.config.get(
            "ALERT_SMTP_SENDER",
            "netsentinel@example.com",
        )
        message["To"] = ", ".join(recipients_list)
        message.set_content(body)

        smtp_server = current_app.config.get("ALERT_SMTP_SERVER", "localhost")
        smtp_port = int(current_app.config.get("ALERT_SMTP_PORT", 25))
        use_tls = bool(current_app.config.get("ALERT_SMTP_USE_TLS", False))
        username = current_app.config.get("ALERT_SMTP_USERNAME")
        password = current_app.config.get("ALERT_SMTP_PASSWORD")

        with smtplib.SMTP(smtp_server, smtp_port, timeout=10) as smtp:
            if use_tls:
                smtp.starttls()
            if username and password:
                smtp.login(username, password)
            smtp.send_message(message)

        logger.info("Sent scheduled scan email alert to %s", recipients_list)

    @staticmethod
    def _send_webhook(
        webhook_url: str,
        subject: str,
        body: str,
        schedule: ScheduledScan,
    ) -> None:
        payload = {
            "subject": subject,
            "message": body,
            "schedule_id": schedule.id,
            "target_host": schedule.target_host,
            "interval_seconds": schedule.interval_seconds,
            "scan_type": schedule.scan_type,
            "protocol": schedule.protocol,
            "start_port": schedule.start_port,
            "end_port": schedule.end_port,
        }
        response = requests.post(
            webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        logger.info("Sent scheduled scan webhook alert to %s", webhook_url)
