#!/bin/bash
#
# CloudLine — Quick Start / Stop
#
# Starts Docker containers + frontend without re-running setup.
# Use this after the initial setup.sh has been completed.
#
# Usage:
#   ./start.sh            — Start everything
#   ./start.sh --stop     — Stop all containers
#   ./start.sh --restart  — Restart everything
#   ./start.sh --rebuild  — Rebuild frontend + restart
#   ./start.sh --status   — Show container status
#

set -euo pipefail

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
COMPOSE_FILE="$ROOT_DIR/docker-compose.yml"

info()    { echo -e "${CYAN}→${NC} $1"; }
success() { echo -e "${GREEN}✔${NC} $1"; }
warn()    { echo -e "${YELLOW}⚠${NC} $1"; }
fail()    { echo -e "${RED}✘${NC} $1"; }

# ── Stop ──
do_stop() {
  info "Stopping containers..."
  docker compose -f "$COMPOSE_FILE" down
  success "All containers stopped"
}

# ── Status ──
do_status() {
  echo ""
  echo -e "${BOLD}Container Status:${NC}"
  docker compose -f "$COMPOSE_FILE" ps
  echo ""

  # Health checks
  for svc in "Backend:9710/health" "OPA:9720/health" "DynamoDB:9730"; do
    name="${svc%%:*}"
    url="http://localhost:${svc#*:}"
    if curl -sf "$url" >/dev/null 2>&1; then
      echo -e "  ${GREEN}●${NC} $name — running"
    else
      echo -e "  ${RED}●${NC} $name — not responding"
    fi
  done
  echo ""
}

# ── Start ──
do_start() {
  # Pre-flight checks
  if [[ ! -f "$ROOT_DIR/.env" ]]; then
    fail ".env not found — run ./setup.sh first"
    exit 1
  fi

  # Build frontend if dist/ is missing
  if [[ ! -d "$ROOT_DIR/frontend/dist" ]]; then
    info "Frontend not built — building now..."
    cd "$ROOT_DIR/frontend"
    if [[ ! -d "node_modules" ]]; then
      npm install --silent 2>&1 | tail -3
    fi
    npm run build 2>&1 | tail -5
    success "Frontend built"
  fi

  # Start containers
  info "Starting Docker containers..."
  docker compose -f "$COMPOSE_FILE" up -d 2>&1 | tail -5
  success "Containers started"

  # Wait for backend
  info "Waiting for backend..."
  for i in $(seq 1 20); do
    if curl -sf http://localhost:9710/health >/dev/null 2>&1; then
      success "Backend healthy"
      break
    fi
    if [[ $i -eq 20 ]]; then
      warn "Backend slow to start — check: docker compose logs backend"
    fi
    sleep 2
  done

  echo ""
  echo -e "${GREEN}${BOLD}CloudLine is running!${NC}"
  echo ""
  echo "  Dashboard:  http://localhost:9710"
  echo ""
}

# ── Parse args ──
case "${1:-}" in
  --stop|-s)
    do_stop
    ;;
  --restart|-r)
    do_stop
    echo ""
    do_start
    ;;
  --rebuild|-b)
    info "Rebuilding frontend..."
    cd "$ROOT_DIR/frontend"
    npm run build 2>&1 | tail -5
    success "Frontend rebuilt"
    do_stop
    echo ""
    do_start
    ;;
  --status)
    do_status
    ;;
  --help|-h)
    echo "Usage: ./start.sh [option]"
    echo ""
    echo "  (no args)     Start containers + serve app"
    echo "  --stop, -s    Stop all containers"
    echo "  --restart, -r Restart everything"
    echo "  --rebuild, -b Rebuild frontend + restart"
    echo "  --status      Show container health"
    echo "  --help, -h    Show this help"
    ;;
  *)
    do_start
    ;;
esac
