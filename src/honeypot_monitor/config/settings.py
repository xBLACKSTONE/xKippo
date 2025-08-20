"""
Settings data class - placeholder for task 3.1.
"""

from dataclasses import dataclass
from typing import List


@dataclass
class HoneypotSettings:
    """Honeypot configuration settings."""
    log_path: str = "/opt/kippo/log/kippo.log"
    log_format: str = "kippo_default"


@dataclass
class MonitoringSettings:
    """Monitoring configuration settings."""
    refresh_interval: float = 1.0
    max_entries_memory: int = 10000


@dataclass
class AnalysisSettings:
    """Analysis configuration settings."""
    threat_threshold: str = "medium"
    custom_rules_path: str = "./rules/"


@dataclass
class IRCSettings:
    """IRC configuration settings."""
    enabled: bool = True
    server: str = "irc.freenode.net"
    port: int = 6667
    channel: str = "#security-alerts"
    nickname: str = "honeypot-monitor"
    ssl: bool = False
    alert_types: List[str] = None
    
    def __post_init__(self):
        if self.alert_types is None:
            self.alert_types = ["new_host", "high_threat", "interesting_traffic"]


@dataclass
class InterfaceSettings:
    """Interface configuration settings."""
    theme: str = "dark"
    key_bindings: str = "default"


@dataclass
class Settings:
    """Main settings container - placeholder for task 3.1."""
    honeypot: HoneypotSettings = None
    monitoring: MonitoringSettings = None
    analysis: AnalysisSettings = None
    irc: IRCSettings = None
    interface: InterfaceSettings = None
    
    def __post_init__(self):
        if self.honeypot is None:
            self.honeypot = HoneypotSettings()
        if self.monitoring is None:
            self.monitoring = MonitoringSettings()
        if self.analysis is None:
            self.analysis = AnalysisSettings()
        if self.irc is None:
            self.irc = IRCSettings()
        if self.interface is None:
            self.interface = InterfaceSettings()