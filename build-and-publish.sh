#!/usr/bin/env bash
set -e

echo "🧹 Cleaning old builds..."
rm -rf dist/ build/ *.egg-info

echo "📦 Building package..."
python -m build

echo "🔍 Checking package with twine..."
python -m twine check dist/*

if [ -z "$TWINE_PASSWORD" ]; then
    read -sp "Enter your PyPI API token: " TWINE_PASSWORD
    echo
fi

echo "🚀 Uploading to PyPI..."
python -m twine upload -u __token__ -p "$TWINE_PASSWORD" dist/*

echo "✅ Done!"
