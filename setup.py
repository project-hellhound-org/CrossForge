"""
CrossForge SSRF Agent — System Installation
=============================================
After installing, run the agent as:

  crossforge --input spider.json http://target.com

Install:
  pip install -e .               # development install (editable)
  pip install .                  # production install

Or install for the current user only:
  pip install --user -e .
  # Make sure ~/.local/bin is in your PATH

Uninstall:
  pip uninstall crossforge
"""

from pathlib import Path
from setuptools import setup, find_packages

_HERE = Path(__file__).parent

setup(
    name="crossforge",
    version="1.1.0",
    description="Enterprise SSRF Detection, Exploitation & Verification Agent",
    # BUG FIX: open("README.md") used the process's CURRENT WORKING
    # DIRECTORY, not setup.py's own location. `pip install .` from any cwd
    # other than the project root (or a build backend copying setup.py into
    # a temp build dir, which some do) would raise FileNotFoundError before
    # setup() even runs. Anchoring to __file__ makes this robust regardless
    # of invocation cwd.
    long_description=(_HERE / "README.md").read_text(encoding="utf-8"),
    long_description_content_type="text/markdown",
    author="CrossForge Project",
    python_requires=">=3.10",

    # Include the core package and payload data files.
    # BUG FIX (main.py inclusion): find_packages() only discovers directories
    # with __init__.py (i.e. "core"). main.py is a standalone top-level
    # module, and without an explicit py_modules entry it was silently NOT
    # included in installed distributions — `pip install .` / `pip install
    # -e .` would succeed, but the installed `crossforge` console script
    # (entry_points below) would fail with `ModuleNotFoundError: No module
    # named 'main'`, because console-script shims don't get the project
    # directory auto-added to sys.path the way `python3 main.py` does.
    #
    # BUG FIX (payloads/config.yaml — the more serious one): package_data
    # keys are PACKAGE NAMES, and glob patterns are resolved relative to
    # that package's own source directory. The previous config used key ""
    # with patterns "payloads/*.json" and "config.yaml" — since "core" is
    # the only real package here, that pattern was checked against
    # core/payloads/*.json and core/config.yaml, which didn't exist (both
    # lived at the project root, siblings of core/, not inside it). I
    # verified this empirically by building a wheel: config.yaml and every
    # payloads/*.json file were completely absent from the archive. Every
    # runtime module that loads one of these (context_classifier.py,
    # evidence_engine.py, waf_detector.py, known_exploits.py, feedback.py,
    # agent.py's default-config lookup) does `with open(path) as f:
    # json.load(f)` at IMPORT TIME with no error handling — so a real
    # `pip install .` would make `crossforge` crash immediately on any
    # invocation with FileNotFoundError, before even reaching argument
    # parsing. Fixed at the source by physically relocating payloads/ and
    # config.yaml to live inside core/ (core/payloads/, core/config.yaml)
    # and updating every path reference accordingly — package_data below
    # is now keyed correctly to "core" and actually matches real files.
    packages=find_packages(include=["core", "core.*"]),
    py_modules=["main"],
    package_data={
        "core": [
            "payloads/*.json",
            "config.yaml",
        ],
    },
    include_package_data=True,
    # zip_safe=False: several core/*.py modules read package_data files at
    # import time via plain `open()`/`Path.read_text()`, not
    # importlib.resources — those calls need a real file on disk, which
    # isn't guaranteed if pip/setuptools decides to install this as a
    # zipped egg. Explicit for safety even though wheels are the norm now.
    zip_safe=False,

    install_requires=[
        "httpx[http2]>=0.27.0",
        "PyYAML>=6.0.1",
        "rich>=13.7.1",
    ],
    extras_require={
        # Optional headless-rendering crawl pass (core/crawler.py) — see
        # README for what this unlocks and why it's opt-in.
        "render": ["playwright>=1.44.0"],
        "dev": ["pytest>=8.1.1", "pytest-asyncio>=0.23.6"],
    },

    # This is what makes `crossforge` available as a system command
    entry_points={
        "console_scripts": [
            "crossforge=main:main",
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
