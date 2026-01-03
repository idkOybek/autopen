"""Setup script for Pentest Automation CLI."""

from pathlib import Path

from setuptools import find_packages, setup

# Read README
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text() if readme_file.exists() else ""

# Read version from cli/__init__.py
version = "1.0.0"

setup(
    name="pentest-cli",
    version=version,
    description="Command-line interface for Automated Penetration Testing Platform",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Pentest Automation Team",
    author_email="admin@example.com",
    url="https://github.com/your-org/autopen",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "httpx>=0.25.0",
        "pyyaml>=6.0",
        "websockets>=12.0",
        "prompt-toolkit>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.10.0",
            "flake8>=6.1.0",
            "mypy>=1.6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "pentest-cli=cli.main:cli",
            "pentest=cli.main:cli",  # Short alias
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
        "Environment :: Console",
    ],
    keywords="pentest security automation cli penetration-testing",
    project_urls={
        "Bug Reports": "https://github.com/your-org/autopen/issues",
        "Source": "https://github.com/your-org/autopen",
        "Documentation": "https://docs.example.com/autopen",
    },
)
