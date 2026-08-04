#!/usr/bin/env bash
set -euo pipefail
mkdir -p data evidence reports logs
python3 -c 'from app.database import initialize_database; initialize_database(); print("Database initialized")'

