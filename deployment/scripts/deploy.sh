#!/bin/bash
# Deploy AiCC services to production
# Usage: bash /opt/web/deployment/scripts/deploy.sh [mcp|web|all]
# Default: all
#
# Run ON the droplet (64.23.155.158). Pulls latest code, rebuilds, restarts.
# This is the CANONICAL deploy script. Both services deploy through here.
#
# From a local machine:
#   ssh root@64.23.155.158 "bash /opt/web/deployment/scripts/deploy.sh mcp"

set -euo pipefail

SERVICE="${1:-all}"
COMPOSE="/opt/web/deployment/docker/docker-compose.prod.yml"

echo "=== AiCC Deploy: ${SERVICE} ==="
echo "Compose: ${COMPOSE}"
echo ""

case "${SERVICE}" in
  mcp)
    echo "Pulling MCP server..."
    cd /opt/mcp && git pull origin main
    echo ""
    echo "Rebuilding MCP container..."
    docker compose -f "${COMPOSE}" build --no-cache mcp
    echo ""
    echo "Restarting MCP..."
    docker compose -f "${COMPOSE}" up -d mcp
    sleep 3
    echo ""
    echo "Health check (MCP)..."
    if curl -sf http://127.0.0.1:8443/health > /dev/null 2>&1; then
        curl -s http://127.0.0.1:8443/health | python3 -m json.tool
    else
        echo "FAILED -- check logs: docker logs aicc-mcp --tail 50"
        exit 1
    fi
    ;;

  web)
    echo "Pulling website..."
    cd /opt/web && git pull origin main
    echo ""
    echo "Rebuilding web container..."
    docker compose -f "${COMPOSE}" build --no-cache web
    echo ""
    echo "Restarting web..."
    docker compose -f "${COMPOSE}" up -d web
    sleep 3
    echo ""
    echo "Health check (web)..."
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ 2>/dev/null || echo "000")
    if [ "${HTTP_CODE}" = "200" ]; then
        echo "Website: HTTP ${HTTP_CODE} OK"
    else
        echo "FAILED (HTTP ${HTTP_CODE}) -- check logs: docker logs aicc-web --tail 50"
        exit 1
    fi
    ;;

  all)
    echo "Pulling both repos..."
    cd /opt/mcp && git pull origin main
    cd /opt/web && git pull origin main
    echo ""
    echo "Rebuilding all containers..."
    docker compose -f "${COMPOSE}" build --no-cache
    echo ""
    echo "Restarting all..."
    docker compose -f "${COMPOSE}" up -d
    sleep 3
    echo ""
    echo "Health checks..."
    echo "--- MCP ---"
    if curl -sf http://127.0.0.1:8443/health > /dev/null 2>&1; then
        curl -s http://127.0.0.1:8443/health | python3 -m json.tool
    else
        echo "MCP FAILED -- check logs: docker logs aicc-mcp --tail 50"
    fi
    echo ""
    echo "--- Website ---"
    HTTP_CODE=$(curl -sf -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/ 2>/dev/null || echo "000")
    if [ "${HTTP_CODE}" = "200" ]; then
        echo "Website: HTTP ${HTTP_CODE} OK"
    else
        echo "Website FAILED (HTTP ${HTTP_CODE}) -- check logs: docker logs aicc-web --tail 50"
    fi
    ;;

  *)
    echo "Usage: deploy.sh [mcp|web|all]"
    echo ""
    echo "  mcp  -- Pull and rebuild MCP server only"
    echo "  web  -- Pull and rebuild website only"
    echo "  all  -- Pull and rebuild both (default)"
    exit 1
    ;;
esac

echo ""
echo "=== Deploy complete ==="
echo "Containers:"
docker ps --filter "name=aicc-" --format "  {{.Names}}: {{.Status}}"
