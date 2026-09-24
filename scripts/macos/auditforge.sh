#!/usr/bin/env bash
# One-click launcher for AuditForge on macOS.
# Usage:
#   sudo ./auditforge.sh                       # interactive menu
#   sudo ./auditforge.sh audit --profile audit_only
#   sudo ./auditforge.sh harden --dry-run
#
# NOTE: the macOS control set has not been validated on real Apple
# hardware in this project (see docs/TEST_MATRIX.md) -- run `audit` first
# and review results carefully before ever using `harden` here.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

if [ "$(id -u)" -ne 0 ]; then
    echo "WARNING: not running as root/sudo. Many probes (fdesetup, csrutil, systemsetup, per-user defaults domains) and ALL of harden/rollback require sudo." >&2
fi

if [ ! -x "${VENV_DIR}/bin/python3" ]; then
    echo "Setting up AuditForge's Python environment (first run only)..."
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is required and was not found on PATH. Install Xcode Command Line Tools (xcode-select --install) or Python from python.org, then re-run this script." >&2
        exit 1
    fi
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/python3" -m pip install -q --upgrade pip
    "${VENV_DIR}/bin/python3" -m pip install -q -e "${REPO_ROOT}"
fi

exec "${VENV_DIR}/bin/python3" -m auditforge.cli "$@"
