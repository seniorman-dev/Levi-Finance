


#!/usr/bin/env bash
# Exit on error
set -o errexit

# Set Python path to include the main directory
export PYTHONPATH=/opt/render/project/src

# Install dependencies
pip install -r requirements.txt

# Collect static files
python manage.py collectstatic --no-input

# Apply database migrations
python manage.py migrate