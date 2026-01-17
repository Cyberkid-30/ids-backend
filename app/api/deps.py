"""
API dependencies module.

Provides common dependencies for FastAPI route handlers,
including database sessions and service instances.
"""

from typing import Generator
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.database.session import get_db
from app.services.detector import DetectionEngine, get_detection_engine
from app.services.alert_manager import AlertManager, get_alert_manager


def get_database() -> Generator[Session, None, None]:
    """
    Dependency that provides database session.

    FastAPI dependency injection wrapper for database session.

    Yields:
        Session: SQLAlchemy database session
    """
    yield from get_db()


def get_detector() -> DetectionEngine:
    """
    Dependency that provides detection engine instance.

    Returns:
        DetectionEngine: Global detection engine
    """
    return get_detection_engine()


def get_alerts_manager() -> AlertManager:
    """
    Dependency that provides alert manager instance.

    Returns:
        AlertManager: Global alert manager
    """
    return get_alert_manager()


def require_detection_running(
    detector: DetectionEngine = Depends(get_detector),
) -> DetectionEngine:
    """
    Dependency that requires detection engine to be running.

    Raises HTTP 503 if detection is not active.

    Args:
        detector: Detection engine instance

    Returns:
        DetectionEngine: Running detection engine

    Raises:
        HTTPException: If detection is not running
    """
    if not detector.is_running:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Detection engine is not running",
        )
    return detector


class Pagination:
    """
    Pagination parameters dependency.

    Provides standardized pagination for list endpoints.
    """

    def __init__(self, page: int = 1, page_size: int = 50):
        """
        Initialize pagination parameters.

        Args:
            page: Page number (1-indexed)
            page_size: Number of items per page (max 100)
        """
        # Validate and constrain values
        self.page = max(1, page)
        self.page_size = min(max(1, page_size), 100)

        # Calculate offset
        self.skip = (self.page - 1) * self.page_size
        self.limit = self.page_size

    def get_response_meta(self, total: int) -> dict:
        """
        Generate pagination metadata for response.

        Args:
            total: Total number of items

        Returns:
            dict: Pagination metadata
        """
        return {
            "total": total,
            "page": self.page,
            "page_size": self.page_size,
            "total_pages": (total + self.page_size - 1) // self.page_size,
        }
