"""
Detection engine service.

Orchestrates the detection pipeline: sniffer -> parser -> matcher -> alert.
This is the main service that coordinates all components.
"""

from typing import List, Optional
from datetime import datetime
import threading
from sqlalchemy.orm import Session

from app.services.sniffer import PacketSniffer, CapturedPacket, get_sniffer
from app.services.parser import PacketParser, get_parser
from app.services.matcher import SignatureMatcher, MatchResult, get_matcher
from app.services.alert_manager import AlertManager, get_alert_manager
from app.models.signature import Signature
from app.database.session import get_session
from app.core.logging import ids_logger


class DetectionEngine:
    """
    Main detection engine that coordinates the IDS pipeline.

    Flow: Capture -> Parse -> Match -> Alert

    Attributes:
        sniffer: Packet capture service
        parser: Packet parsing service
        matcher: Signature matching service
        alert_manager: Alert generation service
        is_running: Whether detection is active
    """

    def __init__(
        self,
        sniffer: Optional[PacketSniffer] = None,
        parser: Optional[PacketParser] = None,
        matcher: Optional[SignatureMatcher] = None,
        alert_manager: Optional[AlertManager] = None,
    ):
        """
        Initialize the detection engine.

        Args:
            sniffer: Packet sniffer (default: global instance)
            parser: Packet parser (default: global instance)
            matcher: Signature matcher (default: global instance)
            alert_manager: Alert manager (default: global instance)
        """
        self.sniffer = sniffer or get_sniffer()
        self.parser = parser or get_parser()
        self.matcher = matcher or get_matcher()
        self.alert_manager = alert_manager or get_alert_manager()

        self.is_running = False
        self._signatures: List[Signature] = []
        self._signatures_lock = threading.Lock()
        self._stats = DetectionStats()

        ids_logger.info("DetectionEngine initialized")

    def load_signatures(self, db: Session) -> int:
        """
        Load enabled signatures from database.

        Args:
            db: Database session

        Returns:
            int: Number of signatures loaded
        """
        with self._signatures_lock:
            self._signatures = (
                db.query(Signature).filter(Signature.enabled).all()
            )
            count = len(self._signatures)

        ids_logger.info(f"Loaded {count} signatures for detection")
        return count

    def reload_signatures(self) -> int:
        """
        Reload signatures from database.

        Returns:
            int: Number of signatures loaded
        """
        db = get_session()
        try:
            return self.load_signatures(db)
        finally:
            db.close()

    def process_packet(
        self, captured: CapturedPacket, db: Session
    ) -> List[MatchResult]:
        """
        Process a single captured packet through the detection pipeline.

        Args:
            captured: Raw captured packet
            db: Database session for storing alerts

        Returns:
            list: List of matching results
        """
        self._stats.packets_processed += 1

        # Parse the packet
        parsed = self.parser.parse(captured)

        # Match against signatures
        with self._signatures_lock:
            matches = self.matcher.match_packet(parsed, self._signatures)

        # Generate alerts for matches
        for match in matches:
            if match.matched and match.signature:
                self._stats.alerts_generated += 1
                self.alert_manager.create_alert(
                    db=db, signature=match.signature, packet=parsed
                )

        return matches

    def start_detection(self) -> bool:
        """
        Start the detection engine.

        Loads signatures and begins packet capture.

        Returns:
            bool: True if started successfully
        """
        if self.is_running:
            ids_logger.warning("Detection engine already running")
            return False

        # Load signatures
        db = get_session()
        try:
            sig_count = self.load_signatures(db)
            if sig_count == 0:
                ids_logger.warning(
                    "No signatures loaded - detection may be ineffective"
                )
        finally:
            db.close()

        # Start packet capture
        self.is_running = True
        self._stats.start_time = datetime.utcnow()

        success = self.sniffer.start_async_capture(callback=self._on_packet_captured)

        if success:
            ids_logger.info("Detection engine started")
        else:
            self.is_running = False
            ids_logger.error("Failed to start detection engine")

        return success

    def stop_detection(self):
        """Stop the detection engine."""
        if not self.is_running:
            return

        ids_logger.info("Stopping detection engine...")
        self.sniffer.stop_capture()
        self.is_running = False

        # Log final stats
        ids_logger.info(
            f"Detection stopped - Processed: {self._stats.packets_processed}, "
            f"Alerts: {self._stats.alerts_generated}"
        )

    def _on_packet_captured(self, captured: CapturedPacket):
        """
        Callback for async packet capture.

        Args:
            captured: Captured packet from sniffer
        """
        if not self.is_running:
            return

        # Create new session for thread safety
        db = get_session()
        try:
            self.process_packet(captured, db)
            db.commit()
        except Exception as e:
            ids_logger.error(f"Error processing packet: {e}")
            db.rollback()
        finally:
            db.close()

    def get_status(self) -> dict:
        """
        Get current detection engine status.

        Returns:
            dict: Status information
        """
        with self._signatures_lock:
            sig_count = len(self._signatures)

        return {
            "running": self.is_running,
            "signatures_loaded": sig_count,
            "packets_processed": self._stats.packets_processed,
            "alerts_generated": self._stats.alerts_generated,
            "start_time": (
                self._stats.start_time.isoformat() if self._stats.start_time else None
            ),
            "uptime_seconds": self._stats.get_uptime_seconds(),
            "interface": self.sniffer.interface,
            "capture_filter": self.sniffer.filter,
        }


class DetectionStats:
    """Statistics tracking for the detection engine."""

    def __init__(self):
        self.packets_processed: int = 0
        self.alerts_generated: int = 0
        self.start_time: Optional[datetime] = None

    def get_uptime_seconds(self) -> float:
        """Get uptime in seconds."""
        if self.start_time is None:
            return 0.0
        delta = datetime.utcnow() - self.start_time
        return delta.total_seconds()

    def reset(self):
        """Reset all statistics."""
        self.packets_processed = 0
        self.alerts_generated = 0
        self.start_time = None


# Global detection engine instance
_engine: Optional[DetectionEngine] = None


def get_detection_engine() -> DetectionEngine:
    """Get or create global detection engine instance."""
    global _engine
    if _engine is None:
        _engine = DetectionEngine()
    return _engine
