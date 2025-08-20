# Configuration Examples

This document provides configuration examples for different deployment scenarios of the Honeypot Monitor CLI application.

## Table of Contents

1. [Basic Configurations](#basic-configurations)
2. [Production Deployments](#production-deployments)
3. [High-Volume Environments](#high-volume-environments)
4. [Multi-Honeypot Setups](#multi-honeypot-setups)
5. [Security-Focused Configurations](#security-focused-configurations)
6. [Development and Testing](#development-and-testing)

## Basic Configurations

### Minimal Configuration

For simple deployments with basic monitoring:

```yaml
# ~/.honeypot-monitor/config/config.yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 5000

analysis:
  threat_threshold: "medium"

irc:
  enabled: false

interface:
  theme: "dark"
  
logging:
  level: "INFO"
```

### Home Lab Setup

For personal honeypots and learning environments:

```yaml
honeypot:
  log_path: "/home/user/kippo/log/kippo.log"
  log_format: "kippo_default"
  backup_paths:
    - "/opt/kippo/log/kippo.log"
    - "/var/log/kippo/kippo.log"

monitoring:
  refresh_interval: 0.5
  max_entries_memory: 10000
  file_check_interval: 2.0

analysis:
  threat_threshold: "low"
  pattern_detection: true
  session_timeout: 1800
  ip_tracking: true

irc:
  enabled: true
  server: "irc.libera.chat"
  port: 6667
  channel: "#my-honeypot"
  nickname: "homelab-monitor"
  ssl: false
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"
  rate_limit: 10

interface:
  theme: "dark"
  key_bindings: "default"
  refresh_rate: 30
  log_buffer_size: 1000
  enable_colors: true
  show_timestamps: true

logging:
  level: "INFO"
  file: "~/.honeypot-monitor/logs/app.log"
  max_size: "10MB"
  backup_count: 3
```

### Small Business Configuration

For small business environments with moderate security requirements:

```yaml
honeypot:
  log_path: "/var/log/kippo/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 15000
  file_check_interval: 5.0
  reconnect_delay: 30.0

analysis:
  threat_threshold: "medium"
  custom_rules_path: "/etc/honeypot-monitor/rules/"
  pattern_detection: true
  session_timeout: 3600
  ip_tracking: true

irc:
  enabled: true
  server: "irc.company.com"
  port: 6697
  channel: "#security-alerts"
  nickname: "honeypot-monitor"
  ssl: true
  password: "secure_password"
  alert_types:
    - "new_host"
    - "high_threat"
  rate_limit: 5
  reconnect_attempts: 10

interface:
  theme: "dark"
  key_bindings: "default"
  refresh_rate: 30
  log_buffer_size: 2000

logging:
  level: "INFO"
  file: "/var/log/honeypot-monitor/app.log"
  max_size: "50MB"
  backup_count: 10
```

## Production Deployments

### Enterprise Configuration

For large enterprise environments with high security requirements:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"
  backup_paths:
    - "/var/log/kippo/kippo.log"
    - "/backup/kippo/kippo.log"

monitoring:
  refresh_interval: 2.0
  max_entries_memory: 50000
  file_check_interval: 10.0
  reconnect_delay: 60.0

analysis:
  threat_threshold: "low"
  custom_rules_path: "/etc/honeypot-monitor/rules/"
  pattern_detection: true
  session_timeout: 7200
  ip_tracking: true

irc:
  enabled: true
  server: "irc.internal.company.com"
  port: 6697
  channel: "#soc-alerts"
  nickname: "honeypot-prod"
  ssl: true
  password: "${IRC_PASSWORD}"
  alert_types:
    - "new_host"
    - "high_threat"
    - "interesting_traffic"
  rate_limit: 3
  reconnect_attempts: 20

interface:
  theme: "dark"
  key_bindings: "default"
  refresh_rate: 20
  log_buffer_size: 5000
  enable_colors: true

logging:
  level: "WARNING"
  file: "/var/log/honeypot-monitor/app.log"
  max_size: "100MB"
  backup_count: 30

# Custom threat detection rules
custom_rules:
  - name: "APT Indicators"
    patterns:
      - "powershell.*-enc"
      - "certutil.*-decode"
      - "bitsadmin.*transfer"
    severity: "critical"
    category: "exploitation"
  
  - name: "Cryptocurrency Mining"
    patterns:
      - "(xmrig|cpuminer|minerd)"
      - "stratum\\+tcp://"
    severity: "high"
    category: "exploitation"
```

### Cloud Deployment

For cloud-based honeypots with auto-scaling considerations:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.5
  max_entries_memory: 25000
  file_check_interval: 5.0
  reconnect_delay: 45.0

analysis:
  threat_threshold: "medium"
  pattern_detection: true
  session_timeout: 3600
  ip_tracking: true

irc:
  enabled: true
  server: "${IRC_SERVER}"
  port: 6697
  channel: "${IRC_CHANNEL}"
  nickname: "honeypot-${INSTANCE_ID}"
  ssl: true
  password: "${IRC_PASSWORD}"
  alert_types:
    - "new_host"
    - "high_threat"
  rate_limit: 5

interface:
  theme: "dark"
  refresh_rate: 25
  log_buffer_size: 3000

logging:
  level: "INFO"
  file: "/var/log/honeypot-monitor/app.log"
  max_size: "25MB"
  backup_count: 5

# Cloud-specific settings
cloud:
  instance_metadata: true
  auto_scaling: true
  health_check_endpoint: "/health"
  metrics_endpoint: "/metrics"
```

## High-Volume Environments

### High-Traffic Honeypot

For honeypots receiving high volumes of traffic:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 3.0
  max_entries_memory: 100000
  file_check_interval: 15.0
  reconnect_delay: 120.0
  batch_processing: true
  batch_size: 100

analysis:
  threat_threshold: "high"
  pattern_detection: false  # Disabled for performance
  session_timeout: 1800
  ip_tracking: true
  analysis_threads: 4

irc:
  enabled: true
  server: "irc.example.com"
  port: 6697
  channel: "#high-volume-alerts"
  nickname: "honeypot-hv"
  ssl: true
  alert_types:
    - "high_threat"  # Only high-priority alerts
  rate_limit: 2  # Strict rate limiting
  batch_alerts: true

interface:
  theme: "dark"
  refresh_rate: 10  # Lower refresh rate
  log_buffer_size: 10000
  enable_colors: false  # Disable for performance

logging:
  level: "WARNING"  # Reduce log verbosity
  file: "/var/log/honeypot-monitor/app.log"
  max_size: "500MB"
  backup_count: 50

# Performance optimizations
performance:
  memory_limit: "2GB"
  cpu_limit: 4
  gc_threshold: 10000
  compression: true
```

### Distributed Processing

For environments requiring distributed processing:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 2.0
  max_entries_memory: 50000
  distributed_processing: true

analysis:
  threat_threshold: "medium"
  distributed_analysis: true
  worker_nodes:
    - "analyzer-1.internal:8080"
    - "analyzer-2.internal:8080"
    - "analyzer-3.internal:8080"

irc:
  enabled: true
  server: "irc.internal.com"
  port: 6697
  channel: "#distributed-alerts"
  nickname: "honeypot-dist"
  ssl: true

# Message queue configuration
message_queue:
  type: "redis"
  host: "redis.internal.com"
  port: 6379
  db: 0
  password: "${REDIS_PASSWORD}"

# Load balancing
load_balancer:
  algorithm: "round_robin"
  health_check_interval: 30
  failover_enabled: true
```

## Multi-Honeypot Setups

### Centralized Monitoring

For monitoring multiple honeypots from a central location:

```yaml
# Central monitor configuration
honeypots:
  - name: "honeypot-dmz"
    host: "192.168.1.10"
    log_path: "/opt/kippo/log/kippo.log"
    ssh_key: "/etc/honeypot-monitor/keys/dmz_key"
  
  - name: "honeypot-internal"
    host: "10.0.1.20"
    log_path: "/opt/kippo/log/kippo.log"
    ssh_key: "/etc/honeypot-monitor/keys/internal_key"
  
  - name: "honeypot-cloud"
    host: "cloud.example.com"
    log_path: "/opt/kippo/log/kippo.log"
    ssh_key: "/etc/honeypot-monitor/keys/cloud_key"

monitoring:
  refresh_interval: 2.0
  max_entries_memory: 75000
  centralized_logging: true

analysis:
  threat_threshold: "medium"
  cross_honeypot_correlation: true
  global_ip_tracking: true

irc:
  enabled: true
  server: "irc.company.com"
  port: 6697
  channel: "#multi-honeypot"
  nickname: "central-monitor"
  ssl: true
  alert_format: "[{honeypot_name}] {message}"

# Aggregation settings
aggregation:
  enabled: true
  window_size: 300  # 5 minutes
  correlation_rules:
    - name: "Coordinated Attack"
      condition: "same_ip_multiple_honeypots"
      threshold: 2
      severity: "critical"
```

### Federated Setup

For organizations with multiple independent honeypot deployments:

```yaml
# Federation configuration
federation:
  enabled: true
  node_id: "org-east-coast"
  peers:
    - id: "org-west-coast"
      endpoint: "https://honeypot-west.org.com/api"
      api_key: "${WEST_API_KEY}"
    - id: "org-europe"
      endpoint: "https://honeypot-eu.org.com/api"
      api_key: "${EU_API_KEY}"

honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.5
  max_entries_memory: 30000
  share_threat_intel: true

analysis:
  threat_threshold: "medium"
  federated_analysis: true
  threat_sharing: true

irc:
  enabled: true
  server: "irc.federation.org"
  port: 6697
  channel: "#fed-alerts"
  nickname: "honeypot-east"
  ssl: true

# Threat intelligence sharing
threat_intel:
  sharing_enabled: true
  anonymize_data: true
  share_categories:
    - "high_threat"
    - "new_techniques"
  retention_period: "30d"
```

## Security-Focused Configurations

### Maximum Security

For environments requiring maximum security and monitoring:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"
  integrity_checking: true
  log_encryption: true

monitoring:
  refresh_interval: 0.5
  max_entries_memory: 20000
  real_time_alerts: true
  anomaly_detection: true

analysis:
  threat_threshold: "low"
  custom_rules_path: "/etc/honeypot-monitor/rules/"
  pattern_detection: true
  behavioral_analysis: true
  machine_learning: true
  session_timeout: 900

irc:
  enabled: true
  server: "irc.secure.internal"
  port: 6697
  channel: "#security-critical"
  nickname: "honeypot-secure"
  ssl: true
  certificate_validation: true
  alert_types:
    - "new_host"
    - "low_threat"
    - "medium_threat"
    - "high_threat"
    - "critical_threat"
    - "interesting_traffic"
    - "anomaly_detected"
  rate_limit: 20

# Security hardening
security:
  file_permissions: "600"
  log_tampering_detection: true
  encrypted_storage: true
  audit_logging: true
  access_control: true

# Advanced analysis
advanced_analysis:
  geolocation_lookup: true
  reputation_checking: true
  malware_analysis: true
  network_correlation: true

logging:
  level: "DEBUG"
  file: "/var/log/honeypot-monitor/app.log"
  max_size: "100MB"
  backup_count: 50
  encryption: true
```

### Compliance Configuration

For environments requiring regulatory compliance:

```yaml
honeypot:
  log_path: "/opt/kippo/log/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 1.0
  max_entries_memory: 25000
  audit_trail: true
  data_retention: "2555d"  # 7 years

analysis:
  threat_threshold: "low"
  compliance_reporting: true
  data_classification: true

irc:
  enabled: true
  server: "irc.compliance.internal"
  port: 6697
  channel: "#compliance-alerts"
  nickname: "honeypot-compliance"
  ssl: true
  message_retention: "2555d"

# Compliance settings
compliance:
  standard: "ISO27001"
  data_protection: true
  privacy_controls: true
  audit_logging: true
  retention_policy: "7_years"
  anonymization: true

# Reporting
reporting:
  automated_reports: true
  report_schedule: "daily"
  report_formats: ["pdf", "json"]
  report_recipients:
    - "security@company.com"
    - "compliance@company.com"
```

## Development and Testing

### Development Environment

For development and testing purposes:

```yaml
honeypot:
  log_path: "/tmp/test_kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 0.1
  max_entries_memory: 1000
  demo_mode: true

analysis:
  threat_threshold: "low"
  test_mode: true

irc:
  enabled: false

interface:
  theme: "light"
  debug_mode: true
  show_debug_info: true

logging:
  level: "DEBUG"
  file: "/tmp/honeypot-monitor-dev.log"
  console_output: true

# Development settings
development:
  mock_data: true
  test_alerts: true
  performance_profiling: true
  memory_debugging: true
```

### Testing Configuration

For automated testing environments:

```yaml
honeypot:
  log_path: "/tmp/test_logs/kippo.log"
  log_format: "kippo_default"

monitoring:
  refresh_interval: 0.01
  max_entries_memory: 100
  test_mode: true

analysis:
  threat_threshold: "low"
  test_rules_only: true

irc:
  enabled: false

interface:
  headless_mode: true
  test_interface: true

logging:
  level: "DEBUG"
  file: "/tmp/test-output.log"
  structured_logging: true

# Testing settings
testing:
  mock_irc_server: true
  synthetic_data: true
  performance_testing: true
  load_testing: false
  unit_test_mode: true
```

### Demo Configuration

For demonstrations and training:

```yaml
honeypot:
  log_path: "demo"  # Uses built-in demo data
  log_format: "kippo_default"

monitoring:
  refresh_interval: 2.0
  max_entries_memory: 5000
  demo_mode: true
  simulated_threats: true

analysis:
  threat_threshold: "low"
  demo_analysis: true

irc:
  enabled: true
  server: "irc.demo.local"
  port: 6667
  channel: "#demo-alerts"
  nickname: "demo-monitor"
  ssl: false
  demo_mode: true

interface:
  theme: "dark"
  tutorial_mode: true
  help_overlay: true

# Demo settings
demo:
  realistic_data: true
  threat_scenarios: true
  interactive_tutorial: true
  sample_attacks: true
```

## Environment-Specific Variables

### Using Environment Variables

Many configurations can be overridden with environment variables:

```bash
# Basic settings
export HONEYPOT_LOG_PATH="/custom/path/kippo.log"
export HONEYPOT_THREAT_THRESHOLD="high"

# IRC settings
export HONEYPOT_IRC_SERVER="irc.example.com"
export HONEYPOT_IRC_CHANNEL="#alerts"
export HONEYPOT_IRC_PASSWORD="secret"

# Performance settings
export HONEYPOT_MAX_MEMORY="50000"
export HONEYPOT_REFRESH_INTERVAL="2.0"

# Security settings
export HONEYPOT_LOG_ENCRYPTION="true"
export HONEYPOT_SSL_VERIFY="true"
```

### Docker Environment

For containerized deployments:

```yaml
# docker-compose.yml environment
environment:
  - HONEYPOT_LOG_PATH=/logs/kippo.log
  - HONEYPOT_IRC_SERVER=irc.company.com
  - HONEYPOT_IRC_CHANNEL=#docker-alerts
  - HONEYPOT_IRC_PASSWORD_FILE=/run/secrets/irc_password
  - HONEYPOT_CONFIG_FILE=/config/honeypot-monitor.yaml
```

### Kubernetes Configuration

For Kubernetes deployments:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: honeypot-monitor-config
data:
  config.yaml: |
    honeypot:
      log_path: "/logs/kippo.log"
    monitoring:
      refresh_interval: 1.0
    irc:
      enabled: true
      server: "irc.cluster.local"
      channel: "#k8s-alerts"
---
apiVersion: v1
kind: Secret
metadata:
  name: honeypot-monitor-secrets
data:
  irc_password: <base64-encoded-password>
```

This completes the configuration examples covering various deployment scenarios. Each example is tailored to specific use cases and environments, providing practical starting points for different types of deployments.