#!/usr/bin/env sh
set -eu
cd "$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
command -v python3 >/dev/null 2>&1 || { echo 'Python 3 required' >&2; exit 1; }
python3 -c 'import sys; assert sys.version_info >= (3,10), "Python 3.10+ required"'
[ -f .env ] || { cp .env.example .env; echo 'Created .env; configure AI_* credentials'; }
mkdir -p output
printf 'Installed: standard Python library; no pip packages required.\nRun python3 agent.py\n'
