#!/bin/bash

# Build distribution packages for Honeypot Monitor CLI
# This script creates source and wheel distributions

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${GREEN}[STEP]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check if we're in the right directory
if [ ! -f "setup.py" ]; then
    print_error "setup.py not found. Please run this script from the project root."
    exit 1
fi

print_step "Building distribution packages..."

# Clean previous builds
print_info "Cleaning previous builds..."
rm -rf build/ dist/ *.egg-info/

# Install build dependencies
print_info "Installing build dependencies..."
pip install --upgrade pip setuptools wheel build twine

# Run tests before building
if [ -d "tests" ]; then
    print_info "Running tests..."
    if command -v pytest >/dev/null 2>&1; then
        pytest tests/ || {
            print_warning "Tests failed, but continuing with build..."
        }
    else
        print_warning "pytest not found, skipping tests"
    fi
fi

# Build source distribution
print_info "Building source distribution..."
python -m build --sdist

# Build wheel distribution
print_info "Building wheel distribution..."
python -m build --wheel

# Check the distributions
print_info "Checking distributions..."
twine check dist/*

# Display results
print_success "Distribution packages built successfully!"
echo
print_info "Generated files:"
ls -la dist/
echo

print_info "To upload to PyPI:"
echo "  twine upload dist/*"
echo

print_info "To install locally:"
echo "  pip install dist/*.whl"
echo

print_info "To test installation:"
echo "  pip install --user dist/*.whl"
echo "  honeypot-monitor --help"