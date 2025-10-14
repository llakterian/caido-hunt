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
    requirements = [
        line.strip() for line in fh if line.strip() and not line.startswith("#")
    ]

setup(
    name="caido-hunt",
    version="2.0.0",
    author="Llakterian",
    author_email="llakterian@gmail.com",
    description="Advanced Bug Bounty Scanner - Comprehensive vulnerability detection tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/llakterian/caido-hunt",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "caido-hunt=caido_hunt.hunt:main",
            "caido-scanner=caido_hunt.main_scanner_fixed:main",
            "caido-ultimate=ultimate_scanner_challenge:main",
        ],
    },
    include_package_data=True,
    package_data={
        "caido_hunt": ["configs/*.json", "wordlists/*.txt"],
    },
)
