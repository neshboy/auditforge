#!/usr/bin/env bash
# One-click launcher for AuditForge on Linux.
# Usage:
#   sudo ./auditforge.sh                       # interactive menu
#   sudo ./auditforge.sh audit --profile audit_only
#   sudo ./auditforge.sh harden --dry-run
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
VENV_DIR="${REPO_ROOT}/.venv"

if [ "$(id -u)" -ne 0 ]; then
    echo "WARNING: not running as root. AUDIT mode will still work for most read-only checks, but many probes (sshd -T, systemctl, secedit-equivalents) and ALL of harden/rollback require root." >&2
fi

if [ ! -x "${VENV_DIR}/bin/python3" ]; then
    echo "Setting up AuditForge's Python environment (first run only)..."
    if ! command -v python3 >/dev/null 2>&1; then
        echo "python3 is required and was not found on PATH. Install it with your distro's package manager and re-run this script." >&2
        exit 1
    fi
    python3 -m venv "${VENV_DIR}"
    "${VENV_DIR}/bin/python3" -m pip install -q --upgrade pip
    "${VENV_DIR}/bin/python3" -m pip install -q -e "${REPO_ROOT}"
fi

exec "${VENV_DIR}/bin/python3" -m auditforge.cli "$@"
