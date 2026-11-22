"""
BACHAO+ Central Security Event Engine
Dispatches, streams, and persists system-wide telemetry and incident logs.
"""

import logging
from typing import Optional
from database.db import insert_event

# Configure standard Python runtime logger
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] [%(levelname)s] [BACHAO+ EventEngine] %(message)s"
)
logger = logging.getLogger("SecurityTelemetry")


class SecurityEventEngine:
    """Centralized security telemetry event engine persisting to SQLite."""

    @staticmethod
    def log(
        event_type: str,
        severity: str,
        category: str,
        description: str,
        user_id: Optional[str] = None,
        source_ip: str = "127.0.0.1"
    ) -> str:
        """
        Record a security event to runtime logging and the central SQLite audit repository.

        Standard Event Types:
            - PHISHING_ANALYSIS_COMPLETED
            - HIGH_RISK_URL_DETECTED
            - PASSWORD_BREACH_MATCH
            - FAILED_LOGIN
            - USER_REGISTERED
            - USER_LOGGED_IN
            - USER_LOGGED_OUT
            - EMERGENCY_REPORTED
            - INCIDENT_RESOLVED
            - INCIDENT_STATUS_UPDATED
        """
        user_label = user_id or "ANONYMOUS"
        log_line = f"[{category.upper()}] [{severity.upper()}] {event_type} | User: {user_label} | {description}"

        if severity.upper() in ("CRITICAL", "HIGH"):
            logger.error(log_line)
        elif severity.upper() == "MEDIUM":
            logger.warning(log_line)
        else:
            logger.info(log_line)

        # Persist event in SQLite
        return insert_event(
            event_type=event_type,
            severity=severity,
            category=category,
            description=description,
            user_id=user_label,
            source_ip=source_ip
        )


# Shorthand helper functions
def log_phishing_analysis(description: str, is_high_risk: bool, user_id: Optional[str] = None) -> str:
    evt_type = "HIGH_RISK_URL_DETECTED" if is_high_risk else "PHISHING_ANALYSIS_COMPLETED"
    severity = "HIGH" if is_high_risk else "INFO"
    return SecurityEventEngine.log(evt_type, severity, "PHISHING", description, user_id)


def log_password_breach(description: str, user_id: Optional[str] = None) -> str:
    return SecurityEventEngine.log("PASSWORD_BREACH_MATCH", "HIGH", "PASSWORD", description, user_id)


def log_emergency_sos(zone: str, user_id: Optional[str] = None) -> str:
    return SecurityEventEngine.log(
        "EMERGENCY_REPORTED", "CRITICAL", "CAMPUS_SAFETY",
        f"Emergency SOS panic signal broadcasted from {zone}", user_id
    )


def log_incident_resolution(incident_id: str, resolved_by: str) -> str:
    return SecurityEventEngine.log(
        "INCIDENT_RESOLVED", "INFO", "CAMPUS_SAFETY",
        f"Incident {incident_id} marked as Resolved by {resolved_by}", resolved_by
    )


def log_auth_event(event_type: str, username: str, success: bool, reason: str = "") -> str:
    severity = "INFO" if success else "HIGH"
    desc = f"Authentication {'succeeded' if success else 'failed'} for {username}. {reason}".strip()
    return SecurityEventEngine.log(event_type, severity, "ACCESS", desc, username)
