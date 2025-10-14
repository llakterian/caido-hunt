#!/usr/bin/env python3
"""
Setup script for Caido Hunt - Ultimate Bug Bounty Scanner
"""

from setuptools import setup, find_packages
import os

# Read README
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Read requirements
with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="caido-hunt",
    version="4.0.0",
    author="Security Research Team",
    author_email="security@research.team",
    description="Ultimate Bug Bounty Scanner - Comprehensive vulnerability detection tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/llakterian/caido-hunt",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "caido-hunt=caido_hunt.hunt:main",
            "caido-scanner=caido_hunt.main_scanner:main",
        ],
    },
    include_package_data=True,
    package_data={
        "caido_hunt": ["configs/*.json", "wordlists/*.txt"],
    },
)
