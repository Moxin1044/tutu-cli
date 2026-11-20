from __future__ import annotations

from typing import Dict, List, Optional, Type

from .base import Source
from .exploitdb import ExploitDbSource
from .github_advisory import GithubAdvisorySource
from .kev import CisaKevSource
from .loudong import LoudongSource
from .mitre import MitreCveSource
from .nsfocus import NsfocusSource
from .nvd import NvdSource
from .osv import OsvSource
from .ransomlook import RansomlookSource
from .ransomware_live import RansomwareLiveSource
from .ransomwatch import RansomwatchSource
from .redhat import RedHatSource
from .socradar import SocradarRansomwareSource
from .socradar_cve import SocradarCveSource
from .socradar_ioc import SocradarIocSource
from .sploitus import SploitusSource
from .threatbook import ThreatBookSource
from .ti360 import Ti360Source
from .vulnrichment import VulnrichmentSource
from .vulnx import VulnxSource

VULN_SOURCE_CLASSES: List[Type[Source]] = [
    NvdSource,
    CisaKevSource,
    MitreCveSource,
    OsvSource,
    VulnrichmentSource,
    VulnxSource,
    SocradarCveSource,
    ExploitDbSource,
    SploitusSource,
    RedHatSource,
    GithubAdvisorySource,
]

INTEL_SOURCE_CLASSES: List[Type[Source]] = [
    NsfocusSource,
    Ti360Source,
    ThreatBookSource,
    LoudongSource,
    SocradarIocSource,
    RansomwareLiveSource,
    RansomlookSource,
    SocradarRansomwareSource,
    RansomwatchSource,
]

VULN_SOURCES: Dict[str, Type[Source]] = {cls.name: cls for cls in VULN_SOURCE_CLASSES}
INTEL_SOURCES: Dict[str, Type[Source]] = {cls.name: cls for cls in INTEL_SOURCE_CLASSES}

DEFAULT_VULN_SOURCES = [
    "nvd",
    "kev",
    "mitre",
    "osv",
    "vulnrichment",
    "vulnx",
    "socradar_cve",
    "exploitdb",
    "sploitus",
    "redhat",
]
DEFAULT_INTEL_SOURCES = [
    "nsfocus",
    "360",
    "threatbook",
    "loudong",
    "socradar_ioc",
    "ransomware_live",
    "ransomlook",
    "socradar",
    "ransomwatch",
]


def build_sources(kind: str, names: Optional[List[str]] = None) -> List[Source]:
    registry = VULN_SOURCES if kind == "vuln" else INTEL_SOURCES
    defaults = DEFAULT_VULN_SOURCES if kind == "vuln" else DEFAULT_INTEL_SOURCES
    selected = names if names else defaults
    out: List[Source] = []
    for name in selected:
        cls = registry.get(name)
        if cls is not None:
            out.append(cls())
    return out
