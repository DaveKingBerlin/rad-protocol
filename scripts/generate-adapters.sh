#!/usr/bin/env sh
set -eu
python3 "$(dirname "$0")/../tools/generate_adapters.py" "$@"
