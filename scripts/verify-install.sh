#!/bin/bash

# Verification script for Honeypot Monitor CLI installation
# Tests that all components are properly installed and configured

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test results
TESTS_PASSED=0
TESTS_FAILED=0

print_header() {
    echo -e "${BLUE}================================${NC}"
    echo -e "${BLUE}  Installation Verification${NC}"
    echo -e "${BLUE}================================${NC}"
    echo
}

print_test() {
    echo -e "${BLUE}[TEST]${NC} $1"
}

print_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((TESTS_PASSED++))
}

print_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((TESTS_FAILED++))
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Test Python installation
test_python() {
    print_test "Checking Python installation..."
    
    if command -v python3 >/dev/null 2>&1; then
        PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2)
        if python3 -c "import sys; exit(0 if sys.version_info >= (3, 8) else 1)" 2>/dev/null; then
            print_pass "Python $PYTHON_VERSION is installed and compatible"
        else
            print_fail "Python version $PYTHON_VERSION is too old (need 3.8+)"
        fi
    else
        print_fail "Python 3 is not installed or not in PATH"
    fi
}

# Test package installation
test_package() {
    print_test "Checking package installation..."
    
    if python3 -c "import honeypot_monitor" 2>/dev/null; then
        print_pass "honeypot_monitor package is importable"
    else
        print_fail "honeypot_monitor package is not installed or not importable"
    fi
}

# Test dependencies
test_dependencies() {
    print_test "Checking dependencies..."
    
    local deps=("textual" "watchdog" "yaml" "irc" "rich")
    local missing_deps=()
    
    for dep in "${deps[@]}"; do
        if python3 -c "import $dep" 2>/dev/null; then
            print_pass "Dependency '$dep' is available"
        else
            print_fail "Dependency '$dep' is missing"
            missing_deps+=("$dep")
        fi
    done
    
    if [ ${#missing_deps[@]} -eq 0 ]; then
        print_pass "All dependencies are installed"
    else
        print_fail "Missing dependencies: ${missing_deps[*]}"
    fi
}

# Test command line interface
test_cli() {
    print_test "Checking command line interface..."
    
    if command -v honeypot-monitor >/dev/null 2>&1; then
        print_pass "honeypot-monitor command is available"
        
        # Test help command
        if honeypot-monitor --help >/dev/null 2>&1; then
            print_pass "honeypot-monitor --help works"
        else
            print_fail "honeypot-monitor --help failed"
        fi
    else
        print_fail "honeypot-monitor command is not in PATH"
    fi
}

# Test configuration
test_config() {
    print_test "Checking configuration..."
    
    local config_locations=(
        "$HOME/.honeypot-monitor/config/config.yaml"
        "./config/default.yaml"
    )
    
    local found_config=false
    for config_path in "${config_locations[@]}"; do
        if [ -f "$config_path" ]; then
            print_pass "Configuration file found at $config_path"
            found_config=true
            
            # Test YAML syntax
            if python3 -c "import yaml; yaml.safe_load(open('$config_path'))" 2>/dev/null; then
                print_pass "Configuration file has valid YAML syntax"
            else
                print_fail "Configuration file has invalid YAML syntax"
            fi
            break
        fi
    done
    
    if [ "$found_config" = false ]; then
        print_warning "No configuration file found (this is OK for development)"
    fi
}

# Test virtual environment (if applicable)
test_venv() {
    print_test "Checking virtual environment..."
    
    if [ -n "$VIRTUAL_ENV" ]; then
        print_pass "Running in virtual environment: $VIRTUAL_ENV"
        
        # Check if honeypot-monitor is installed in this venv
        local venv_bin="$VIRTUAL_ENV/bin/honeypot-monitor"
        if [ -f "$venv_bin" ]; then
            print_pass "honeypot-monitor is installed in virtual environment"
        else
            print_warning "honeypot-monitor not found in virtual environment bin"
        fi
    else
        print_info "Not running in a virtual environment"
    fi
}

# Test file permissions
test_permissions() {
    print_test "Checking file permissions..."
    
    # Check if install script is executable
    if [ -x "./install.sh" ]; then
        print_pass "install.sh is executable"
    else
        print_warning "install.sh is not executable"
    fi
    
    # Check if build script is executable
    if [ -x "./scripts/build-dist.sh" ]; then
        print_pass "build-dist.sh is executable"
    else
        print_warning "build-dist.sh is not executable"
    fi
}

# Test import functionality
test_imports() {
    print_test "Testing module imports..."
    
    local modules=(
        "honeypot_monitor.main"
        "honeypot_monitor.config.config_manager"
        "honeypot_monitor.models.log_entry"
        "honeypot_monitor.services.log_parser"
        "honeypot_monitor.tui.main_app"
    )
    
    for module in "${modules[@]}"; do
        if python3 -c "import $module" 2>/dev/null; then
            print_pass "Module '$module' imports successfully"
        else
            print_fail "Module '$module' failed to import"
        fi
    done
}

# Test basic functionality
test_functionality() {
    print_test "Testing basic functionality..."
    
    # Test configuration loading
    if python3 -c "
from honeypot_monitor.config.config_manager import ConfigManager
try:
    config = ConfigManager()
    print('Configuration manager works')
except Exception as e:
    print(f'Configuration manager failed: {e}')
    exit(1)
" 2>/dev/null; then
        print_pass "Configuration manager works"
    else
        print_fail "Configuration manager failed"
    fi
    
    # Test log entry creation
    if python3 -c "
from honeypot_monitor.models.log_entry import LogEntry
from datetime import datetime
try:
    entry = LogEntry(
        timestamp=datetime.now(),
        session_id='test',
        event_type='test',
        source_ip='127.0.0.1',
        message='test'
    )
    print('LogEntry model works')
except Exception as e:
    print(f'LogEntry model failed: {e}')
    exit(1)
" 2>/dev/null; then
        print_pass "LogEntry model works"
    else
        print_fail "LogEntry model failed"
    fi
}

# Main verification function
main() {
    print_header
    
    test_python
    test_package
    test_dependencies
    test_cli
    test_config
    test_venv
    test_permissions
    test_imports
    test_functionality
    
    echo
    echo -e "${BLUE}================================${NC}"
    echo -e "${GREEN}Tests Passed: $TESTS_PASSED${NC}"
    echo -e "${RED}Tests Failed: $TESTS_FAILED${NC}"
    echo -e "${BLUE}================================${NC}"
    
    if [ $TESTS_FAILED -eq 0 ]; then
        echo -e "${GREEN}All tests passed! Installation appears to be working correctly.${NC}"
        exit 0
    else
        echo -e "${RED}Some tests failed. Please check the installation.${NC}"
        exit 1
    fi
}

# Run verification
main "$@"