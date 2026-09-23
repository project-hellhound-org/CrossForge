"""
RAVAGER SSRF Agent — System Installation
=============================================
After installing, run the agent as:

  rage --input spider.json http://target.com

Install:
  pip install -e .               # development install (editable)
  pip install .                  # production install

Or install for the current user only:
  pip install --user -e .
  # Make sure ~/.local/bin is in your PATH

Uninstall:
  pip uninstall ravager
"""

from pathlib import Path
from setuptools import setup, find_packages

_HERE = Path(__file__).parent

setup(
    name="ravager",
    version="2.0.0",
    description="Enterprise SSRF Detection, Exploitation & Verification Agent",
    
    long_description=(_HERE / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="Project Hellhound",
    python_requires=">=3.10",

 
    packages=find_packages(include=["core", "core.*"]),
    py_modules=["main"],
    package_data={
        "core": [
            "payloads/*",
            "config.yaml",
        ],
    },
    include_package_data=True,
    
    zip_safe=False,

    install_requires=[
        "httpx[http2]>=0.27.0",
        "PyYAML>=6.0.1",
        "rich>=13.7.1",
        "dnslib>=0.9.24",
    ],
    extras_require={
        "dns": ["dnspython>=2.6.1", "tldextract>=5.1.2"],
        "render": ["playwright>=1.44.0"],
        "dev": ["pytest>=8.1.1", "pytest-asyncio>=0.23.6"],
    },

    # Primary: rage, Alias: ravager
    entry_points={
        "console_scripts": [
            "rage=main:main",
            "ravager=main:main",
        ],
    },

    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "License :: OSI Approved :: MIT License",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
        "Environment :: Console",
    ],
)
