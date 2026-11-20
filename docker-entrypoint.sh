#!/bin/bash
#
# Docker Entrypoint
# =================
#
# This script serves as the Docker container entrypoint.
# It wraps run_all.sh. See README.md.
# GPL-3.0-only; see LICENSE.
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_banner() {
    echo ""
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║   ${GREEN}Cross-RFC Formal Analysis of DNSSEC${BLUE}                        ║${NC}"
    echo -e "${BLUE}║   DNSSECVerif: ACM CCS 2026, GPLv3                           ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}║   Companion artifact for:                                    ║${NC}"
    echo -e "${BLUE}║   \"Mind the Gap: Cross-RFC Formal Analysis Exposes           ║${NC}"
    echo -e "${BLUE}║    DNSSEC's Hidden Vulnerabilities\"                          ║${NC}"
    echo -e "${BLUE}║                                                              ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
}

print_tools() {
    echo "Environment:"
    echo "  - Tamarin: $(tamarin-prover --version 2>&1 | head -1)"
    echo "  - ProVerif: $(proverif -help 2>&1 | head -1 || echo 'available')"
    echo "  - Maude: $(maude --version 2>&1 | head -1 || echo 'available')"
    echo ""
}

# Handle special commands
case "${1:-}" in
    bash|sh)
        # Interactive shell
        exec /bin/bash
        ;;
    version|--version|-v)
        print_banner
        print_tools
        exit 0
        ;;
    help|--help|-h)
        print_banner
        exec /app/run_all.sh --help
        ;;
    interactive)
        # Start Tamarin in interactive mode for a specific model
        shift
        MODEL="${1:-models/authentication/dnssec_simple.spthy}"
        echo "Starting Tamarin interactive mode for: $MODEL"
        echo "Open http://localhost:3001 in your browser"
        exec tamarin-prover interactive "$MODEL" --interface=*4
        ;;
    *)
        # Run verification with provided arguments
        print_banner
        print_tools
        exec /app/run_all.sh "$@"
        ;;
esac
