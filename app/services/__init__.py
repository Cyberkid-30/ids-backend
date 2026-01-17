"""
Services package initialization.

Exports all service classes and factory functions.
"""

from app.services.sniffer import (
    PacketSniffer,
    CapturedPacket,
    get_sniffer,
)
from app.services.parser import (
    PacketParser,
    ParsedPacket,
    get_parser,
)
from app.services.matcher import (
    SignatureMatcher,
    MatchResult,
    get_matcher,
)
from app.services.detector import (
    DetectionEngine,
    DetectionStats,
    get_detection_engine,
)
from app.services.alert_manager import (
    AlertManager,
    get_alert_manager,
)

__all__ = [
    # Sniffer
    "PacketSniffer",
    "CapturedPacket",
    "get_sniffer",
    # Parser
    "PacketParser",
    "ParsedPacket",
    "get_parser",
    # Matcher
    "SignatureMatcher",
    "MatchResult",
    "get_matcher",
    # Detector
    "DetectionEngine",
    "DetectionStats",
    "get_detection_engine",
    # Alert Manager
    "AlertManager",
    "get_alert_manager",
]
