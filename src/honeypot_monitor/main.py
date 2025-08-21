"""
Main entry point for the Honeypot Monitor CLI application.
"""

import sys
import argparse
from pathlib import Path
from .config.config_manager import ConfigManager
from .tui.main_app import HoneypotMonitorApp


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="Honeypot Monitor CLI - Monitor and analyze Kippo honeypot activity"
    )
    parser.add_argument(
        "--config", 
        type=str, 
        default="config/default.yaml",
        help="Path to configuration file"
    )
    parser.add_argument(
        "--log-path",
        type=str,
        help="Override log path from configuration"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"Honeypot Monitor CLI {__import__('honeypot_monitor').__version__}"
    )
    
    args = parser.parse_args()
    
    try:
        # Load configuration
        print(f"DEBUG: Loading config from: {args.config}")  # Debug output
        config_manager = ConfigManager()
        config = config_manager.load_config(args.config)
        print(f"DEBUG: Config loaded successfully")  # Debug output
        print(f"DEBUG: Log path: {config.honeypot.log_path}")  # Debug output
        print(f"DEBUG: Log format: {config.honeypot.log_format}")  # Debug output
        
        # Override log path if provided
        if args.log_path:
            print(f"DEBUG: Overriding log path to: {args.log_path}")  # Debug output
            config.honeypot.log_path = args.log_path
            
            # Verify log file exists
            if not Path(args.log_path).exists():
                print(f"Log file not found: {args.log_path}")
                sys.exit(1)
        else:
            # Verify default log file exists
            if not Path(config.honeypot.log_path).exists():
                print(f"Default log file not found: {config.honeypot.log_path}")
                print("Please provide a valid log file path with --log-path option")
                sys.exit(1)
        
        # Start the TUI application with integrated services
        print("DEBUG: Starting TUI application...")  # Debug output
        app = HoneypotMonitorApp(config=config)
        app.run()
        
    except KeyboardInterrupt:
        print("\nApplication interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"Error starting application: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()