#!/usr/bin/env python3
"""
pyIKEv2 Setup Script
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="pyikev2",
    version="1.0.0",
    author="pyIKEv2 Contributors",
    author_email="",
    description="A complete Python3 implementation of IKEv2 (RFC 7296)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/yourusername/pyikev2",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Topic :: System :: Networking",
        "Topic :: Security :: Cryptography",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pyikev2=pyikev2.cli:main",
        ],
    },
    package_data={
        "pyikev2": ["config/*.yaml", "config/*.json"],
    },
    include_package_data=True,
    zip_safe=False,
)