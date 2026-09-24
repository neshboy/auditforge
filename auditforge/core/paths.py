"""Resolves where controls/profiles/frameworks live.

v0.1 assumes a source checkout or editable install (repo_root/auditforge,
repo_root/profiles, repo_root/frameworks) -- see docs/ARCHITECTURE.md
"Known limitations". A future release should fold profiles/ and
frameworks/ into package data so a plain `pip install auditforge` (not
editable) has them too.
"""

from __future__ import annotations

import os

import auditforge


def package_dir() -> str:
    return os.path.dirname(os.path.abspath(auditforge.__file__))


def repo_root() -> str:
    return os.path.dirname(package_dir())


def controls_base_dir() -> str:
    return package_dir()


def profiles_dir() -> str:
    return os.path.join(repo_root(), "profiles")


def frameworks_dir() -> str:
    return os.path.join(repo_root(), "frameworks")
