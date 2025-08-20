"""
Setup script for Honeypot Monitor CLI.
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read the README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path, "r", encoding="utf-8") as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith("#")
        ]

setup(
    name="honeypot-monitor-cli",
    version="0.1.0",
    author="Security Team",
    author_email="security@example.com",
    description="CLI-based monitoring application for Kippo honeypot traffic analysis",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/honeypot-monitor-cli",
    project_urls={
        "Bug Reports": "https://github.com/example/honeypot-monitor-cli/issues",
        "Source": "https://github.com/example/honeypot-monitor-cli",
        "Documentation": "https://github.com/example/honeypot-monitor-cli/wiki",
    },
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: System :: Monitoring",
        "Topic :: System :: Systems Administration",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
        "Environment :: Console :: Curses",
    ],
    keywords="honeypot kippo security monitoring cli tui terminal",
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=22.0.0",
            "flake8>=5.0.0",
            "mypy>=1.0.0",
            "pre-commit>=2.20.0",
        ],
        "test": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "pytest-mock>=3.10.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "honeypot-monitor=honeypot_monitor.main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "honeypot_monitor": [
            "config/*.yaml",
            "tui/*.tcss",
        ],
    },
    data_files=[
        ("share/honeypot-monitor/config", ["config/default.yaml"]),
        ("share/honeypot-monitor/systemd", ["systemd/honeypot-monitor.service"]),
        ("share/doc/honeypot-monitor", ["README.md"]),
    ],
    zip_safe=False,
)