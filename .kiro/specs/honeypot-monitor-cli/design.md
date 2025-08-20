# Design Document

## Overview

The Honeypot Monitor CLI is a Python-based terminal user interface (TUI) application designed to monitor and analyze Kippo honeypot activity. The application uses a modular architecture with separate components for log parsing, data analysis, user interface, and configuration management. The design emphasizes real-time monitoring capabilities while providing comprehensive historical analysis tools.

## Architecture

The application follows a layered architecture pattern:

```
┌─────────────────────────────────────────┐
│              TUI Layer                  │
│  (Rich/Textual - Interface Components)  │
├─────────────────────────────────────────┤
│            Application Layer            │
│     (Controllers, Event Handlers)      │
├─────────────────────────────────────────┤
│             Service Layer               │
│  (Log Parser, Analyzer, File Monitor)  │
├─────────────────────────────────────────┤
│              Data Layer                 │
│    (Models, Storage, Configuration)     │
└─────────────────────────────────────────┘
```

### Core Components

1. **TUI Framework**: Built using Python's `textual` library for rich terminal interfaces
2. **Log Monitor**: Real-time file monitoring using `watchdog` library
3. **Data Parser**: Kippo log format parser with structured data extraction
4. **Analysis Engine**: Pattern detection and threat categorization
5. **IRC Notification System**: Real-time alerts to IRC channels for admin notifications
6. **Configuration Manager**: Settings and rule management
7. **Installation System**: Interactive setup and dependency management

## Components and Interfaces

### 1. TUI Components

**Main Dashboard**
- Real-time activity feed
- Connection statistics panel
- Alert/notification area
- IRC connection status indicator
- Navigation menu

**Log Viewer**
- Paginated log display
- Search and filter controls
- Export functionality
- Detail drill-down views

**Analysis Panel**
- Threat categorization display
- Pattern analysis results
- Custom rule configuration
- Statistical summaries

### 2. Core Services

**LogMonitor Service**
```python
class LogMonitor:
    def start_monitoring(self, log_path: str) -> None
    def stop_monitoring(self) -> None
    def get_recent_entries(self, count: int) -> List[LogEntry]
    def register_callback(self, callback: Callable) -> None
```

**LogParser Service**
```python
class KippoLogParser:
    def parse_entry(self, raw_line: str) -> LogEntry
    def validate_format(self, log_path: str) -> bool
    def get_supported_formats(self) -> List[str]
```

**AnalysisEngine Service**
```python
class ThreatAnalyzer:
    def analyze_entry(self, entry: LogEntry) -> ThreatAssessment
    def detect_patterns(self, entries: List[LogEntry]) -> List[Pattern]
    def apply_custom_rules(self, entry: LogEntry) -> List[Alert]
```

**IRCNotifier Service**
```python
class IRCNotifier:
    def connect(self, server: str, channel: str, nickname: str) -> None
    def disconnect(self) -> None
    def send_alert(self, alert_type: str, message: str) -> None
    def send_new_host_alert(self, ip: str, first_seen: datetime) -> None
    def send_threat_alert(self, threat: ThreatAssessment, source_ip: str) -> None
    def send_interesting_traffic_alert(self, activity: str, details: str) -> None
```

### 3. Configuration System

**Configuration Structure**
```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"
  
monitoring:
  refresh_interval: 1.0
  max_entries_memory: 10000
  
analysis:
  threat_threshold: "medium"
  custom_rules_path: "./rules/"
  
irc:
  enabled: true
  server: "irc.freenode.net"
  port: 6667
  channel: "#security-alerts"
  nickname: "honeypot-monitor"
  ssl: false
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"
  
interface:
  theme: "dark"
  key_bindings: "default"
```

## Data Models

### LogEntry Model
```python
@dataclass
class LogEntry:
    timestamp: datetime
    session_id: str
    event_type: str
    source_ip: str
    message: str
    command: Optional[str] = None
    file_path: Optional[str] = None
    threat_level: Optional[str] = None
```

### Session Model
```python
@dataclass
class Session:
    session_id: str
    source_ip: str
    start_time: datetime
    end_time: Optional[datetime]
    commands: List[str]
    files_accessed: List[str]
    threat_score: float
```

### ThreatAssessment Model
```python
@dataclass
class ThreatAssessment:
    severity: str  # low, medium, high, critical
    category: str  # reconnaissance, exploitation, persistence
    confidence: float
    indicators: List[str]
    recommended_action: str
```

### IRCAlert Model
```python
@dataclass
class IRCAlert:
    alert_type: str  # new_host, high_threat, interesting_traffic
    timestamp: datetime
    source_ip: str
    message: str
    severity: str
    sent: bool = False
```

## Error Handling

### Log File Access Errors
- Implement retry logic with exponential backoff
- Graceful degradation when log files are unavailable
- User notification of connection issues
- Automatic reconnection attempts

### Parsing Errors
- Skip malformed log entries with warning logs
- Maintain parsing statistics for monitoring
- Fallback to raw text display for unparseable entries
- Configuration validation on startup

### TUI Error Handling
- Graceful handling of terminal resize events
- Recovery from rendering errors
- Input validation and sanitization
- Memory management for large datasets

### IRC Connection Errors
- Automatic reconnection with exponential backoff
- Fallback to local logging when IRC is unavailable
- Connection status display in TUI
- Graceful handling of network interruptions
- Rate limiting for alert messages to prevent flooding

## Testing Strategy

### Unit Testing
- **Log Parser Tests**: Validate parsing of various Kippo log formats
- **Analysis Engine Tests**: Test threat detection algorithms
- **Configuration Tests**: Validate configuration loading and validation
- **Data Model Tests**: Test serialization and validation

### Integration Testing
- **File Monitor Integration**: Test real-time log monitoring
- **TUI Component Integration**: Test interface component interactions
- **End-to-End Workflows**: Test complete user scenarios

### Performance Testing
- **Memory Usage**: Monitor memory consumption with large log files
- **Response Time**: Measure interface responsiveness
- **Concurrent Operations**: Test simultaneous monitoring and analysis

### Installation Testing
- **Multi-Platform Testing**: Test installation on various Linux distributions
- **Dependency Resolution**: Validate automatic dependency installation
- **Configuration Detection**: Test automatic honeypot detection

## Installation and Deployment

### Installation Script Design
```bash
#!/bin/bash
# Interactive installation with:
# - Python environment detection
# - Dependency installation via pip
# - Kippo installation detection
# - Configuration file generation
# - Service setup (optional)
```

### Package Structure
```
honeypot-monitor/
├── install.sh
├── requirements.txt
├── setup.py
├── src/
│   ├── honeypot_monitor/
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── tui/
│   │   ├── services/
│   │   ├── models/
│   │   └── config/
├── config/
│   ├── default.yaml
│   └── rules/
└── tests/
```

### Deployment Options
1. **Standalone Installation**: Direct installation on honeypot host
2. **Virtual Environment**: Isolated Python environment
3. **Container Deployment**: Docker container for easy deployment
4. **System Service**: Optional systemd service configuration