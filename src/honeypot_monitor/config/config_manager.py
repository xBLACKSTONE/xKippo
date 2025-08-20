"""
Configuration manager for loading and validating YAML configuration files.
"""

import os
import yaml
import glob
from pathlib import Path
from typing import Dict, Any, Optional, List
from .settings import (
    Settings, 
    HoneypotSettings, 
    MonitoringSettings, 
    AnalysisSettings, 
    IRCSettings, 
    InterfaceSettings
)


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""
    pass


class ConfigManager:
    """Manages loading and validation of YAML configuration files."""
    
    def __init__(self):
        self._default_config_path = Path(__file__).parent.parent.parent.parent / "config" / "default.yaml"
    
    def load_config(self, config_path: Optional[str] = None) -> Settings:
        """
        Load configuration from YAML file with validation and defaults.
        
        Args:
            config_path: Path to configuration file. If None, uses default config.
            
        Returns:
            Settings object with validated configuration.
            
        Raises:
            ConfigValidationError: If configuration is invalid.
            FileNotFoundError: If config file doesn't exist.
        """
        if config_path is None:
            config_path = self._default_config_path
        
        config_data = self._load_yaml_file(config_path)
        return self._validate_and_create_settings(config_data)
    
    def _load_yaml_file(self, config_path: Path | str) -> Dict[str, Any]:
        """Load YAML configuration file."""
        config_path = Path(config_path)
        
        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")
        
        try:
            with open(config_path, 'r', encoding='utf-8') as file:
                config_data = yaml.safe_load(file)
                
            if config_data is None:
                config_data = {}
                
            return config_data
        except yaml.YAMLError as e:
            raise ConfigValidationError(f"Invalid YAML in configuration file: {e}")
        except Exception as e:
            raise ConfigValidationError(f"Error reading configuration file: {e}")
    
    def _validate_and_create_settings(self, config_data: Dict[str, Any]) -> Settings:
        """Validate configuration data and create Settings object."""
        try:
            # Extract and validate honeypot settings
            honeypot_data = config_data.get('honeypot', {})
            honeypot_settings = self._validate_honeypot_settings(honeypot_data)
            
            # Extract and validate monitoring settings
            monitoring_data = config_data.get('monitoring', {})
            monitoring_settings = self._validate_monitoring_settings(monitoring_data)
            
            # Extract and validate analysis settings
            analysis_data = config_data.get('analysis', {})
            analysis_settings = self._validate_analysis_settings(analysis_data)
            
            # Extract and validate IRC settings
            irc_data = config_data.get('irc', {})
            irc_settings = self._validate_irc_settings(irc_data)
            
            # Extract and validate interface settings
            interface_data = config_data.get('interface', {})
            interface_settings = self._validate_interface_settings(interface_data)
            
            return Settings(
                honeypot=honeypot_settings,
                monitoring=monitoring_settings,
                analysis=analysis_settings,
                irc=irc_settings,
                interface=interface_settings
            )
        except Exception as e:
            raise ConfigValidationError(f"Configuration validation failed: {e}")
    
    def _validate_honeypot_settings(self, data: Dict[str, Any]) -> HoneypotSettings:
        """Validate honeypot configuration section."""
        log_path = data.get('log_path', '/opt/kippo/log/kippo.log')
        log_format = data.get('log_format', 'kippo_default')
        
        # Validate log_path is a string
        if not isinstance(log_path, str):
            raise ConfigValidationError("honeypot.log_path must be a string")
        
        # Validate log_format is a string
        if not isinstance(log_format, str):
            raise ConfigValidationError("honeypot.log_format must be a string")
        
        # Validate log_format is supported
        supported_formats = ['kippo_default', 'cowrie', 'custom']
        if log_format not in supported_formats:
            raise ConfigValidationError(f"honeypot.log_format must be one of: {supported_formats}")
        
        return HoneypotSettings(log_path=log_path, log_format=log_format)
    
    def _validate_monitoring_settings(self, data: Dict[str, Any]) -> MonitoringSettings:
        """Validate monitoring configuration section."""
        refresh_interval = data.get('refresh_interval', 1.0)
        max_entries_memory = data.get('max_entries_memory', 10000)
        
        # Validate refresh_interval
        if not isinstance(refresh_interval, (int, float)):
            raise ConfigValidationError("monitoring.refresh_interval must be a number")
        if refresh_interval <= 0:
            raise ConfigValidationError("monitoring.refresh_interval must be positive")
        
        # Validate max_entries_memory
        if not isinstance(max_entries_memory, int):
            raise ConfigValidationError("monitoring.max_entries_memory must be an integer")
        if max_entries_memory <= 0:
            raise ConfigValidationError("monitoring.max_entries_memory must be positive")
        
        return MonitoringSettings(
            refresh_interval=float(refresh_interval),
            max_entries_memory=max_entries_memory
        )
    
    def _validate_analysis_settings(self, data: Dict[str, Any]) -> AnalysisSettings:
        """Validate analysis configuration section."""
        threat_threshold = data.get('threat_threshold', 'medium')
        custom_rules_path = data.get('custom_rules_path', './rules/')
        
        # Validate threat_threshold
        if not isinstance(threat_threshold, str):
            raise ConfigValidationError("analysis.threat_threshold must be a string")
        
        valid_thresholds = ['low', 'medium', 'high', 'critical']
        if threat_threshold not in valid_thresholds:
            raise ConfigValidationError(f"analysis.threat_threshold must be one of: {valid_thresholds}")
        
        # Validate custom_rules_path
        if not isinstance(custom_rules_path, str):
            raise ConfigValidationError("analysis.custom_rules_path must be a string")
        
        return AnalysisSettings(
            threat_threshold=threat_threshold,
            custom_rules_path=custom_rules_path
        )
    
    def _validate_irc_settings(self, data: Dict[str, Any]) -> IRCSettings:
        """Validate IRC configuration section."""
        enabled = data.get('enabled', True)
        server = data.get('server', 'irc.freenode.net')
        port = data.get('port', 6667)
        channel = data.get('channel', '#security-alerts')
        nickname = data.get('nickname', 'honeypot-monitor')
        ssl = data.get('ssl', False)
        alert_types = data.get('alert_types', ['new_host', 'high_threat', 'interesting_traffic'])
        
        # Validate enabled
        if not isinstance(enabled, bool):
            raise ConfigValidationError("irc.enabled must be a boolean")
        
        # Validate server
        if not isinstance(server, str):
            raise ConfigValidationError("irc.server must be a string")
        if not server.strip():
            raise ConfigValidationError("irc.server cannot be empty")
        
        # Validate port
        if not isinstance(port, int):
            raise ConfigValidationError("irc.port must be an integer")
        if not (1 <= port <= 65535):
            raise ConfigValidationError("irc.port must be between 1 and 65535")
        
        # Validate channel
        if not isinstance(channel, str):
            raise ConfigValidationError("irc.channel must be a string")
        if not channel.strip():
            raise ConfigValidationError("irc.channel cannot be empty")
        
        # Validate nickname
        if not isinstance(nickname, str):
            raise ConfigValidationError("irc.nickname must be a string")
        if not nickname.strip():
            raise ConfigValidationError("irc.nickname cannot be empty")
        
        # Validate ssl
        if not isinstance(ssl, bool):
            raise ConfigValidationError("irc.ssl must be a boolean")
        
        # Validate alert_types
        if not isinstance(alert_types, list):
            raise ConfigValidationError("irc.alert_types must be a list")
        
        valid_alert_types = ['new_host', 'high_threat', 'interesting_traffic']
        for alert_type in alert_types:
            if not isinstance(alert_type, str):
                raise ConfigValidationError("irc.alert_types items must be strings")
            if alert_type not in valid_alert_types:
                raise ConfigValidationError(f"Invalid alert type '{alert_type}'. Must be one of: {valid_alert_types}")
        
        return IRCSettings(
            enabled=enabled,
            server=server,
            port=port,
            channel=channel,
            nickname=nickname,
            ssl=ssl,
            alert_types=alert_types
        )
    
    def _validate_interface_settings(self, data: Dict[str, Any]) -> InterfaceSettings:
        """Validate interface configuration section."""
        theme = data.get('theme', 'dark')
        key_bindings = data.get('key_bindings', 'default')
        
        # Validate theme
        if not isinstance(theme, str):
            raise ConfigValidationError("interface.theme must be a string")
        
        valid_themes = ['dark', 'light', 'auto']
        if theme not in valid_themes:
            raise ConfigValidationError(f"interface.theme must be one of: {valid_themes}")
        
        # Validate key_bindings
        if not isinstance(key_bindings, str):
            raise ConfigValidationError("interface.key_bindings must be a string")
        
        valid_bindings = ['default', 'vim', 'emacs']
        if key_bindings not in valid_bindings:
            raise ConfigValidationError(f"interface.key_bindings must be one of: {valid_bindings}")
        
        return InterfaceSettings(theme=theme, key_bindings=key_bindings)
    
    def validate_config_file(self, config_path: str) -> bool:
        """
        Validate a configuration file without loading it into Settings.
        
        Args:
            config_path: Path to configuration file to validate.
            
        Returns:
            True if configuration is valid.
            
        Raises:
            ConfigValidationError: If configuration is invalid.
        """
        try:
            self.load_config(config_path)
            return True
        except (ConfigValidationError, FileNotFoundError):
            raise
    
    def detect_honeypot_paths(self) -> List[str]:
        """
        Automatically detect potential honeypot installation paths.
        
        Returns:
            List of detected honeypot log file paths.
        """
        potential_paths = [
            # Common Kippo installation paths
            "/opt/kippo/log/kippo.log",
            "/usr/local/kippo/log/kippo.log",
            "/home/*/kippo/log/kippo.log",
            "/var/log/kippo/kippo.log",
            
            # Common Cowrie installation paths
            "/opt/cowrie/var/log/cowrie/cowrie.log",
            "/usr/local/cowrie/var/log/cowrie/cowrie.log",
            "/home/*/cowrie/var/log/cowrie/cowrie.log",
            "/var/log/cowrie/cowrie.log",
            
            # Docker/container paths
            "/var/log/honeypot/*.log",
            "/logs/*.log",
            
            # Custom installation paths
            "/srv/honeypot/log/*.log",
            "/data/honeypot/log/*.log",
        ]
        
        detected_paths = []
        
        for pattern in potential_paths:
            try:
                # Use glob to expand wildcards and find matching files
                matches = glob.glob(pattern, recursive=True)
                for match in matches:
                    path = Path(match)
                    if path.exists() and path.is_file() and path.stat().st_size > 0:
                        detected_paths.append(str(path))
            except (OSError, PermissionError):
                # Skip paths we can't access
                continue
        
        # Remove duplicates and sort
        return sorted(list(set(detected_paths)))
    
    def generate_config_file(self, output_path: str, settings: Settings) -> None:
        """
        Generate a YAML configuration file from Settings object.
        
        Args:
            output_path: Path where to save the configuration file.
            settings: Settings object to serialize to YAML.
            
        Raises:
            ConfigValidationError: If unable to write configuration file.
        """
        try:
            config_data = {
                'honeypot': {
                    'log_path': settings.honeypot.log_path,
                    'log_format': settings.honeypot.log_format,
                },
                'monitoring': {
                    'refresh_interval': settings.monitoring.refresh_interval,
                    'max_entries_memory': settings.monitoring.max_entries_memory,
                },
                'analysis': {
                    'threat_threshold': settings.analysis.threat_threshold,
                    'custom_rules_path': settings.analysis.custom_rules_path,
                },
                'irc': {
                    'enabled': settings.irc.enabled,
                    'server': settings.irc.server,
                    'port': settings.irc.port,
                    'channel': settings.irc.channel,
                    'nickname': settings.irc.nickname,
                    'ssl': settings.irc.ssl,
                    'alert_types': settings.irc.alert_types,
                },
                'interface': {
                    'theme': settings.interface.theme,
                    'key_bindings': settings.interface.key_bindings,
                }
            }
            
            output_path = Path(output_path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            
            with open(output_path, 'w', encoding='utf-8') as file:
                yaml.dump(config_data, file, default_flow_style=False, indent=2, sort_keys=False)
                
        except Exception as e:
            raise ConfigValidationError(f"Failed to generate configuration file: {e}")
    
    def create_default_config(self, output_path: str, honeypot_log_path: Optional[str] = None) -> Settings:
        """
        Create a default configuration file with optional custom honeypot path.
        
        Args:
            output_path: Path where to save the configuration file.
            honeypot_log_path: Optional custom honeypot log path. If None, uses default.
            
        Returns:
            Settings object with the generated configuration.
            
        Raises:
            ConfigValidationError: If unable to create configuration file.
        """
        # Start with default settings
        settings = Settings()
        
        # Override honeypot log path if provided
        if honeypot_log_path:
            settings.honeypot.log_path = honeypot_log_path
            
            # Try to detect log format based on path
            path_lower = honeypot_log_path.lower()
            if 'cowrie' in path_lower:
                settings.honeypot.log_format = 'cowrie'
            elif 'kippo' in path_lower:
                settings.honeypot.log_format = 'kippo_default'
        
        # Generate the configuration file
        self.generate_config_file(output_path, settings)
        
        return settings
    
    def interactive_config_setup(self) -> Settings:
        """
        Interactive configuration setup for first-time users.
        
        Returns:
            Settings object with user-configured values.
        """
        print("Welcome to Honeypot Monitor CLI Configuration Setup!")
        print("=" * 50)
        
        # Detect honeypot installations
        print("\nDetecting honeypot installations...")
        detected_paths = self.detect_honeypot_paths()
        
        # Honeypot configuration
        print("\n1. Honeypot Configuration")
        print("-" * 25)
        
        if detected_paths:
            print("Detected honeypot log files:")
            for i, path in enumerate(detected_paths, 1):
                print(f"  {i}. {path}")
            print(f"  {len(detected_paths) + 1}. Enter custom path")
            
            while True:
                try:
                    choice = input(f"\nSelect honeypot log file (1-{len(detected_paths) + 1}) [1]: ").strip()
                    if not choice:
                        choice = "1"
                    
                    choice_num = int(choice)
                    if 1 <= choice_num <= len(detected_paths):
                        log_path = detected_paths[choice_num - 1]
                        break
                    elif choice_num == len(detected_paths) + 1:
                        log_path = input("Enter custom honeypot log path: ").strip()
                        if log_path and Path(log_path).exists():
                            break
                        else:
                            print("Invalid path or file does not exist.")
                    else:
                        print(f"Please enter a number between 1 and {len(detected_paths) + 1}")
                except ValueError:
                    print("Please enter a valid number.")
        else:
            print("No honeypot installations detected.")
            log_path = input("Enter honeypot log file path [/opt/kippo/log/kippo.log]: ").strip()
            if not log_path:
                log_path = "/opt/kippo/log/kippo.log"
        
        # Detect log format
        log_format = "kippo_default"
        if 'cowrie' in log_path.lower():
            log_format = "cowrie"
        
        format_choice = input(f"Log format (kippo_default/cowrie/custom) [{log_format}]: ").strip()
        if format_choice:
            log_format = format_choice
        
        # Monitoring configuration
        print("\n2. Monitoring Configuration")
        print("-" * 27)
        
        refresh_interval = input("Refresh interval in seconds [1.0]: ").strip()
        if not refresh_interval:
            refresh_interval = 1.0
        else:
            try:
                refresh_interval = float(refresh_interval)
            except ValueError:
                refresh_interval = 1.0
        
        max_entries = input("Maximum entries in memory [10000]: ").strip()
        if not max_entries:
            max_entries = 10000
        else:
            try:
                max_entries = int(max_entries)
            except ValueError:
                max_entries = 10000
        
        # Analysis configuration
        print("\n3. Analysis Configuration")
        print("-" * 25)
        
        threat_threshold = input("Threat detection threshold (low/medium/high/critical) [medium]: ").strip()
        if not threat_threshold or threat_threshold not in ['low', 'medium', 'high', 'critical']:
            threat_threshold = "medium"
        
        # IRC configuration
        print("\n4. IRC Notification Configuration")
        print("-" * 34)
        
        irc_enabled = input("Enable IRC notifications? (y/n) [y]: ").strip().lower()
        irc_enabled = irc_enabled != 'n'
        
        irc_server = "irc.freenode.net"
        irc_port = 6667
        irc_channel = "#security-alerts"
        irc_nickname = "honeypot-monitor"
        irc_ssl = False
        
        if irc_enabled:
            irc_server = input(f"IRC server [{irc_server}]: ").strip() or irc_server
            
            port_input = input(f"IRC port [{irc_port}]: ").strip()
            if port_input:
                try:
                    irc_port = int(port_input)
                except ValueError:
                    pass
            
            irc_channel = input(f"IRC channel [{irc_channel}]: ").strip() or irc_channel
            irc_nickname = input(f"IRC nickname [{irc_nickname}]: ").strip() or irc_nickname
            
            ssl_input = input("Use SSL? (y/n) [n]: ").strip().lower()
            irc_ssl = ssl_input == 'y'
        
        # Interface configuration
        print("\n5. Interface Configuration")
        print("-" * 26)
        
        theme = input("Interface theme (dark/light/auto) [dark]: ").strip()
        if not theme or theme not in ['dark', 'light', 'auto']:
            theme = "dark"
        
        key_bindings = input("Key bindings (default/vim/emacs) [default]: ").strip()
        if not key_bindings or key_bindings not in ['default', 'vim', 'emacs']:
            key_bindings = "default"
        
        # Create settings object
        settings = Settings(
            honeypot=HoneypotSettings(log_path=log_path, log_format=log_format),
            monitoring=MonitoringSettings(refresh_interval=refresh_interval, max_entries_memory=max_entries),
            analysis=AnalysisSettings(threat_threshold=threat_threshold, custom_rules_path="./rules/"),
            irc=IRCSettings(
                enabled=irc_enabled,
                server=irc_server,
                port=irc_port,
                channel=irc_channel,
                nickname=irc_nickname,
                ssl=irc_ssl,
                alert_types=["new_host", "high_threat", "interesting_traffic"]
            ),
            interface=InterfaceSettings(theme=theme, key_bindings=key_bindings)
        )
        
        print("\n" + "=" * 50)
        print("Configuration setup complete!")
        
        return settings