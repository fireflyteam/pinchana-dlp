#!/bin/bash
set -e

echo "=== Pinchana DLP Start Script ==="

if [ ! -f .env ]; then
    echo "No .env file found. Copying example.env to .env..."
    cp example.env .env
    echo "Please make sure to review the .env file and change default passwords in production."
fi

echo "[1/2] Building isolated worker image (pinchana-worker:latest)..."
docker build -t pinchana-worker:latest ./worker

echo "[2/2] Starting API and Redis via docker-compose..."
docker compose up --build -d

echo ""
echo "=== Success! ==="
echo "API is running on http://${API_BIND_HOST:-0.0.0.0}:${API_PORT:-8080}${API_ROOT_PATH:-}"
echo "Check logs with: docker compose logs -f"
