#!/bin/bash
#
# Unified Verification Script
# ===========================
#
# Companion script for "Mind the Gap: Cross-RFC Formal Analysis
# Exposes DNSSEC's Hidden Vulnerabilities" (ACM CCS 2026)
# GPL-3.0-only. See README.md for usage and limitations.
#
# Usage:
#   ./run_all.sh                  # Select non-cache jobs (default: quick mode)
#   ./run_all.sh --full           # Run all models including long-running ones
#   ./run_all.sh --quick          # Exclude the long-running cache model
#   ./run_all.sh --group cache    # Run models in a specific group
#   ./run_all.sh --model nsec     # Run models matching pattern
#   ./run_all.sh --parallel 4     # Reserved option; main job loop is sequential
#   ./run_all.sh --json           # Output results as JSON
#   ./run_all.sh --help           # Show this help
#
# Examples:
#   ./run_all.sh --quick                    # Fast verification
#   ./run_all.sh --group denial             # Run denial-of-existence models
#   ./run_all.sh --model coexistence        # Run specific model
#   ./run_all.sh --full --timeout 7200      # Full run with timeout per model
#

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODELS_DIR="${SCRIPT_DIR}/models"
RESULTS_DIR="${SCRIPT_DIR}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

# Default settings
MODE="quick"
PARALLEL_JOBS=1
TIMEOUT_QUICK=0        # 0 = no timeout (run to completion)
TIMEOUT_FULL=0         # 0 = no timeout (run to completion)
OUTPUT_FORMAT="text"
FORCE_TOOL=""
SPECIFIC_MODEL=""
SPECIFIC_GROUP=""
PARSE_ONLY=false
VERBOSE=false
TRACK_MEMORY=true      # Track peak memory usage
PER_LEMMA=false        # Run and time each lemma separately

# Docker settings
USE_DOCKER=false
DOCKER_IMAGE="dnssecverif"
DOCKER_AVAILABLE=false
FORCE_DOCKER=false
FORCE_NO_DOCKER=false

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# =============================================================================
# Model Registry
# =============================================================================
# Format: "path|properties|tool|expected|time_est|group|description"
#   path: relative to models/
#   properties: property numbers or "validation"
#   tool: tamarin or proverif
#   expected: verified, falsified, mixed, or attack_exists
#   time_est: estimated time in seconds (0 = unknown/long)
#   group: cache, auth, denial, aggressive, attacks
#   description: short description

declare -a MODEL_REGISTRY=(
    # Bounded cache checks; P7 is in known_attacks/cd_bit_rucsec.pv.
    "cache/cache_bounded.spthy|1-6,8-9|tamarin|verified|7200|cache|Bounded cache checks; P8/P9 are reachability"

    # Authentication; P13 is in known_attacks/algorithm_downgrade.pv.
    "authentication/dnssec_simple.spthy|10-12,14|tamarin|verified|3|auth|DNSSEC auth - simple model"
    "authentication/dnssec_full.spthy|10-12,14|tamarin|verified|15|auth|DNSSEC auth - static KSK/ZSK model"

    # P16 is described in comments but has no executable secrecy lemma.
    # Its 'mixed' expected value is historical, not a P16 result.
    "denial_nsec/nsec.spthy|15,17|tamarin|mixed|30|denial|NSEC denial; P16 query absent"

    # Denial NSEC3 - Properties 18-20
    "denial_nsec3/nsec3.spthy|18-20|proverif|verified|1|denial|NSEC3 denial"

    # Cross-RFC Composition - Properties 21-23 (NEW VULNERABILITIES)
    "rrsig_underflow/rrsig_underflow_vulnerable.spthy|21|proverif|falsified|1|aggressive|Cross-Zone Wildcard Cache Poisoning (P21)"
    "rrsig_underflow/rrsig_underflow_secure.spthy|21|proverif|verified|1|aggressive|P21 mitigation: Labels >= signer-depth bound"
    "aggressive_caching/coexistence.spthy|22|tamarin|falsified|376|aggressive|NSEC/NSEC3 Coexistence Attack (P22)"
    "aggressive_caching/nta_vulnerable.pv|23|proverif|falsified|1|aggressive|NTA Cache Poisoning (P23)"
    "aggressive_caching/nta_secure.pv|23|proverif|verified|1|aggressive|P23 mitigation: validation-state tracking"

    # Known Attacks - Validation models
    "known_attacks/algorithm_downgrade.pv|13|proverif|attack_exists|1|attacks|Algorithm downgrade attack"
    "known_attacks/cd_bit_rucsec.pv|7|proverif|falsified|1|attacks|CD-bit cache poisoning"
)

# Quick mode models: all non-cache models.
# The cache model (P1-P6, P8-P9) is EXCLUDED; select --full or --group cache.
# These 11 jobs relate to 15 paper IDs (P7 and P10-P23), but P16 has no
# executable query. Registry time estimates are rough hints.
declare -a QUICK_MODELS=(
    "authentication/dnssec_simple.spthy"
    "authentication/dnssec_full.spthy"
    "denial_nsec/nsec.spthy"
    "denial_nsec3/nsec3.spthy"
    "rrsig_underflow/rrsig_underflow_vulnerable.spthy"
    "rrsig_underflow/rrsig_underflow_secure.spthy"
    "aggressive_caching/coexistence.spthy"
    "aggressive_caching/nta_vulnerable.pv"
    "aggressive_caching/nta_secure.pv"
    "known_attacks/algorithm_downgrade.pv"
    "known_attacks/cd_bit_rucsec.pv"
)

# =============================================================================
# Helper Functions
# =============================================================================

print_header() {
    echo ""
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo -e "${BOLD}${BLUE}  $1${NC}"
    echo -e "${BOLD}${BLUE}========================================${NC}"
    echo ""
}

print_subheader() {
    echo -e "${CYAN}--- $1 ---${NC}"
}

print_success() {
    echo -e "${GREEN}[PASS]${NC} $1"
}

print_failure() {
    echo -e "${RED}[FAIL]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Format memory in human-readable units (input: KB)
format_memory() {
    local kb="$1"
    if [[ -z "$kb" || "$kb" == "0" ]]; then
        echo "N/A"
        return
    fi

    local mb=$((kb / 1024))
    if [[ $mb -lt 1024 ]]; then
        echo "${mb}MB"
    else
        local gb_int=$((mb / 1024))
        local gb_frac=$(( (mb % 1024) * 10 / 1024 ))
        echo "${gb_int}.${gb_frac}GB"
    fi
}

# Extract peak memory from /usr/bin/time -v output (in KB)
extract_peak_memory() {
    local time_output="$1"
    # GNU time reports "Maximum resident set size (kbytes): NNNN"
    local mem_kb=$(grep -i "Maximum resident set size" "$time_output" 2>/dev/null | \
                   sed 's/.*: *//' | tr -d ' ')
    echo "${mem_kb:-0}"
}

# Extract lemma names from a SAPIC+/Tamarin model file
extract_lemma_names() {
    local model_file="$1"
    # Match lines like: lemma name: or lemma name [reuse]:
    grep -E "^lemma\s+\w+" "$model_file" 2>/dev/null | \
        sed -E 's/^lemma\s+(\w+).*/\1/' | \
        grep -v "^$"
}

# Run a single lemma and return timing/memory info
run_single_lemma() {
    local model_path="$1"
    local lemma_name="$2"
    local log_dir="$3"
    local use_docker="$4"

    local full_path="${MODELS_DIR}/${model_path}"
    local lemma_log="${log_dir}/${lemma_name}.log"
    local lemma_time="${log_dir}/${lemma_name}_time.txt"

    local start_time=$(date +%s)

    # Use /usr/bin/time -v for memory tracking if available
    local time_cmd=""
    if [[ "$TRACK_MEMORY" == true ]] && command -v /usr/bin/time &> /dev/null; then
        time_cmd="/usr/bin/time -v -o $lemma_time"
    fi

    if [[ "$use_docker" == true ]]; then
        local container_model_path="/app/models/${model_path}"
        local docker_opts="--rm --ulimit nofile=65536:65536 --entrypoint tamarin-prover"
        $time_cmd docker run $docker_opts \
            -v "${MODELS_DIR}:/app/models:ro" \
            "$DOCKER_IMAGE" \
            --prove="$lemma_name" --derivcheck-timeout=0 "$container_model_path" > "$lemma_log" 2>&1
    else
        $time_cmd tamarin-prover --prove="$lemma_name" --derivcheck-timeout=0 "$full_path" > "$lemma_log" 2>&1
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Extract memory
    local peak_mem_kb=0
    if [[ -f "$lemma_time" ]]; then
        peak_mem_kb=$(extract_peak_memory "$lemma_time")
    fi
    local peak_mem_fmt=$(format_memory "$peak_mem_kb")

    # Check result
    local status="unknown"
    if grep -q "verified" "$lemma_log" 2>/dev/null; then
        status="verified"
    elif grep -q "falsified" "$lemma_log" 2>/dev/null; then
        status="falsified"
    elif grep -q "analysis incomplete" "$lemma_log" 2>/dev/null; then
        status="incomplete"
    fi

    # Extract steps
    local steps=$(grep -oE "\([0-9]+ steps?\)" "$lemma_log" 2>/dev/null | head -1 | tr -d '()')

    echo "${lemma_name}|${status}|${duration}|${peak_mem_fmt}|${steps:-N/A}"
}

show_help() {
    cat << 'EOF'
Unified Verification Script

USAGE:
    ./run_all.sh [OPTIONS] [MODEL_PATTERN]

OPTIONS:
    --full              Run all models including long-running cache models
    --quick             Select the 11 non-cache jobs [default]
    --group GROUP       Run models in specific group (see GROUPS below)
    --model PATTERN     Run models matching pattern (e.g., "nsec", "auth")
    --parallel N        Reserved option; main job loop is sequential
    --timeout SECONDS   Set per-model timeout (default: 0 = no timeout)
    --parse-only        Tamarin parse/export only; .pv syntax is NOT checked
    --json              Output results as JSON
    --docker            Force using Docker for verification
    --no-docker         Force using local Tamarin/ProVerif (no Docker)
    --force-tamarin     Force Tamarin for all models
    --force-proverif    Force ProVerif for all models
    --verbose           Show detailed output
    --no-memory         Disable peak memory tracking
    --per-lemma         Run lemmas separately; normal timeout wrapper is unused
    --help              Show this help message

EXAMPLES:
    ./run_all.sh                        # Quick verification
    ./run_all.sh --full                 # Full verification
    ./run_all.sh --group cache          # Cache models
    ./run_all.sh --group auth           # Authentication models
    ./run_all.sh --group denial         # Denial-of-existence models
    ./run_all.sh --group aggressive     # New vulnerabilities P21-23
    ./run_all.sh --group attacks        # Known attack validation
    ./run_all.sh --model rrsig          # Headline P21 finding only
    ./run_all.sh --model coexistence    # Run specific model
    ./run_all.sh --per-lemma --group auth  # Per-lemma timing
    ./run_all.sh --parse-only           # Partial parse/export checks only

GROUPS:
    cache       Properties 1-6, 8-9: Bounded cache checks
    auth        Properties 10-12, 14: Data authentication & integrity
    denial      Properties 15, 17-20: Denial checks (P16 query missing)
    aggressive  Properties 21-23: Cross-RFC composition vulnerabilities
    attacks     Known attack validation (Properties 7, 13)

TOOL SELECTION:
    By default, the script auto-selects the appropriate tool:
    - Tamarin: Most models (default)
    - ProVerif: NTA, algorithm downgrade, CD-bit models (better scalability)

OUTPUT:
    Results are saved to results/run_YYYYMMDD_HHMMSS/
    - summary.txt: Human-readable summary
    - results.json: Machine-readable results (with --json)
    - *.log: Per-model verification logs
    - *_time.txt: Memory/timing stats from /usr/bin/time (if available)

MEMORY TRACKING:
    Peak memory usage is tracked using /usr/bin/time -v (GNU time).
    Results show "Peak Mem" column with values like "24MB" or "1.5GB".
    Use --no-memory to disable tracking. N/A shown for timeouts.

PER-LEMMA TIMING:
    Use --per-lemma to run each lemma separately with individual timing.
    Timing is per lemma, not automatically per paper property.
    Note: Only works with Tamarin (not ProVerif) and is slower overall
    since each lemma requires a separate verification run.

LIMITATIONS:
    Model summaries are not per-property proof results. Read every query and
    trace, especially for mixed safety/reachability or inconclusive results.
    See README.md for exporter, Docker, parsing, and timeout caveats.

EOF
    exit 0
}

check_dependencies() {
    local tamarin_available=false
    local proverif_local=false

    # Check for local Tamarin
    if command -v tamarin-prover &> /dev/null; then
        tamarin_available=true
    fi

    # Check for local ProVerif
    if command -v proverif &> /dev/null; then
        proverif_local=true
        PROVERIF_AVAILABLE=true
    else
        PROVERIF_AVAILABLE=false
    fi

    # Check for Docker
    if command -v docker &> /dev/null; then
        DOCKER_AVAILABLE=true
        # Check if Docker image exists
        if docker image inspect "$DOCKER_IMAGE" &> /dev/null; then
            DOCKER_IMAGE_EXISTS=true
        else
            DOCKER_IMAGE_EXISTS=false
        fi
    fi

    # Handle --docker flag (force Docker usage)
    if [[ "$FORCE_DOCKER" == true ]]; then
        if [[ "$DOCKER_AVAILABLE" != true ]]; then
            echo -e "${RED}Error: --docker specified but Docker is not available${NC}"
            echo "Install Docker: curl -fsSL https://get.docker.com | sh"
            exit 1
        fi
        USE_DOCKER=true
        PROVERIF_AVAILABLE=true
        print_info "Using Docker for verification (--docker flag)"

        # Build Docker image if it doesn't exist
        if [[ "$DOCKER_IMAGE_EXISTS" != true ]]; then
            print_info "Docker image '$DOCKER_IMAGE' not found. Building..."
            if ! docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"; then
                echo -e "${RED}Error: Failed to build Docker image${NC}"
                echo "Try running: docker build -t $DOCKER_IMAGE $SCRIPT_DIR"
                exit 1
            fi
            print_success "Docker image built successfully"
        fi
        return
    fi

    # Handle --no-docker flag (force local execution)
    if [[ "$FORCE_NO_DOCKER" == true ]]; then
        if [[ "$tamarin_available" != true ]]; then
            echo -e "${RED}Error: --no-docker specified but Tamarin is not installed${NC}"
            echo "Install Tamarin:"
            echo "  curl -L -o /tmp/tamarin.tar.gz \\"
            echo "    'https://github.com/tamarin-prover/tamarin-prover/releases/download/1.10.0/tamarin-prover-1.10.0-linux64-ubuntu.tar.gz'"
            echo "  tar -xzf /tmp/tamarin.tar.gz -C /tmp && sudo mv /tmp/tamarin-prover /usr/local/bin/"
            exit 1
        fi
        USE_DOCKER=false
        if [[ "$proverif_local" == false ]]; then
            print_warning "ProVerif not found. NSEC3 and CD-bit models will use Tamarin (may be slower)."
        fi
        return
    fi

    # Auto-detect: prefer local tools, fallback to Docker
    if [[ "$tamarin_available" == true ]]; then
        USE_DOCKER=false
        if [[ "$proverif_local" == false ]]; then
            print_warning "ProVerif not found. NSEC3 and CD-bit models will use Tamarin (may be slower)."
        fi
    elif [[ "$DOCKER_AVAILABLE" == true ]]; then
        USE_DOCKER=true
        PROVERIF_AVAILABLE=true  # Docker image has ProVerif
        print_info "Tamarin not found locally. Using Docker for verification."

        # Build Docker image if it doesn't exist
        if [[ "$DOCKER_IMAGE_EXISTS" != true ]]; then
            print_info "Docker image '$DOCKER_IMAGE' not found. Building..."
            if ! docker build -t "$DOCKER_IMAGE" "$SCRIPT_DIR"; then
                echo -e "${RED}Error: Failed to build Docker image${NC}"
                echo "Try running: docker build -t $DOCKER_IMAGE $SCRIPT_DIR"
                exit 1
            fi
            print_success "Docker image built successfully"
        fi
    else
        echo -e "${RED}Error: Neither Tamarin nor Docker is available${NC}"
        echo ""
        echo "Option 1 - Install Docker (recommended):"
        echo "  curl -fsSL https://get.docker.com | sh"
        echo "  docker build -t dnssecverif ."
        echo ""
        echo "Option 2 - Install Tamarin:"
        echo "  curl -L -o /tmp/tamarin.tar.gz \\"
        echo "    'https://github.com/tamarin-prover/tamarin-prover/releases/download/1.10.0/tamarin-prover-1.10.0-linux64-ubuntu.tar.gz'"
        echo "  tar -xzf /tmp/tamarin.tar.gz -C /tmp && sudo mv /tmp/tamarin-prover /usr/local/bin/"
        echo ""
        echo "Install Maude (required by Tamarin):"
        echo "  sudo apt-get install -y maude"
        exit 1
    fi
}

get_model_field() {
    local entry="$1"
    local field="$2"
    echo "$entry" | cut -d'|' -f"$field"
}

is_quick_model() {
    local model_path="$1"
    for quick in "${QUICK_MODELS[@]}"; do
        if [[ "$quick" == "$model_path" ]]; then
            return 0
        fi
    done
    return 1
}

select_tool() {
    local model_path="$1"
    local preferred_tool="$2"

    if [[ -n "$FORCE_TOOL" ]]; then
        echo "$FORCE_TOOL"
        return
    fi

    if [[ "$preferred_tool" == "proverif" ]] && [[ "$PROVERIF_AVAILABLE" == true ]]; then
        echo "proverif"
    else
        echo "tamarin"
    fi
}

run_tamarin() {
    local model_path="$1"
    local timeout="$2"
    local log_file="$3"
    local parse_only="$4"

    local full_path="${MODELS_DIR}/${model_path}"
    local time_file="${log_file%.log}_time.txt"

    if [[ ! -f "$full_path" ]]; then
        echo "ERROR: Model file not found: $full_path" > "$log_file"
        return 1
    fi

    # Use /usr/bin/time -v for memory tracking if available
    local time_cmd=""
    if [[ "$TRACK_MEMORY" == true ]] && command -v /usr/bin/time &> /dev/null; then
        time_cmd="/usr/bin/time -v -o $time_file"
    fi

    # Build timeout wrapper (skip if timeout=0)
    local timeout_cmd=""
    if [[ "$timeout" -gt 0 ]]; then
        timeout_cmd="timeout $timeout"
    fi

    if [[ "$parse_only" == true ]]; then
        $timeout_cmd $time_cmd tamarin-prover --parse-only "$full_path" > "$log_file" 2>&1
    else
        # --derivcheck-timeout=0 disables derivation check timeout for complex SAPIC+ models
        $timeout_cmd $time_cmd tamarin-prover --prove --derivcheck-timeout=0 "$full_path" > "$log_file" 2>&1
    fi
}

run_proverif() {
    local model_path="$1"
    local timeout="$2"
    local log_file="$3"
    local parse_only="$4"

    local full_path="${MODELS_DIR}/${model_path}"

    if [[ ! -f "$full_path" ]]; then
        echo "ERROR: Model file not found: $full_path" > "$log_file"
        return 1
    fi

    local pv_file
    if [[ "$full_path" == *.pv ]]; then
        # Already a ProVerif file, use directly
        pv_file="$full_path"
    else
        # Convert SAPIC+ to ProVerif format
        pv_file="${full_path%.spthy}.pv"
        if ! sapic "$full_path" --proverif > "$pv_file" 2>> "$log_file"; then
            echo "ERROR: SAPIC+ to ProVerif conversion failed" >> "$log_file"
            # Fall back to Tamarin
            print_warning "ProVerif conversion failed, falling back to Tamarin for $model_path"
            run_tamarin "$model_path" "$timeout" "$log_file" "$parse_only"
            return $?
        fi
    fi

    if [[ "$parse_only" == true ]]; then
        echo "Parse-only mode: ProVerif file at $pv_file" >> "$log_file"
        return 0
    fi

    # Build timeout wrapper (skip if timeout=0)
    if [[ "$timeout" -gt 0 ]]; then
        timeout "$timeout" proverif "$pv_file" >> "$log_file" 2>&1
    else
        proverif "$pv_file" >> "$log_file" 2>&1
    fi
}

run_tamarin_docker() {
    local model_path="$1"
    local timeout="$2"
    local log_file="$3"
    local parse_only="$4"

    # Model path is relative to models/ dir
    local container_model_path="/app/models/${model_path}"
    local time_file="${log_file%.log}_time.txt"

    # Common docker options: ulimits for file descriptors
    local docker_opts="--rm --ulimit nofile=65536:65536 --entrypoint tamarin-prover"

    # Use /usr/bin/time -v for memory tracking if available
    local time_cmd=""
    if [[ "$TRACK_MEMORY" == true ]] && command -v /usr/bin/time &> /dev/null; then
        time_cmd="/usr/bin/time -v -o $time_file"
    fi

    # Build timeout wrapper (skip if timeout=0)
    local timeout_cmd=""
    if [[ "$timeout" -gt 0 ]]; then
        timeout_cmd="timeout $timeout"
    fi

    if [[ "$parse_only" == true ]]; then
        $timeout_cmd $time_cmd docker run $docker_opts \
            -v "${MODELS_DIR}:/app/models:ro" \
            "$DOCKER_IMAGE" \
            --parse-only "$container_model_path" > "$log_file" 2>&1
    else
        $timeout_cmd $time_cmd docker run $docker_opts \
            -v "${MODELS_DIR}:/app/models:ro" \
            "$DOCKER_IMAGE" \
            --prove --derivcheck-timeout=0 "$container_model_path" > "$log_file" 2>&1
    fi
}

run_proverif_docker() {
    local model_path="$1"
    local timeout="$2"
    local log_file="$3"
    local parse_only="$4"

    # In Docker mode, use Tamarin for all models since ProVerif conversion
    # requires SAPIC+ toolchain setup which is complex in containerized environment.
    # Tamarin handles all SAPIC+ models natively.
    run_tamarin_docker "$model_path" "$timeout" "$log_file" "$parse_only"
}

parse_tamarin_results() {
    local log_file="$1"

    local verified=0
    local falsified=0
    local analyzing=0

    if grep -q "verified" "$log_file"; then
        verified=$(grep -c "verified" "$log_file" || echo 0)
    fi
    if grep -q "falsified" "$log_file"; then
        falsified=$(grep -c "falsified" "$log_file" || echo 0)
    fi
    if grep -q "analysis incomplete" "$log_file"; then
        analyzing=$(grep -c "analysis incomplete" "$log_file" || echo 0)
    fi

    echo "${verified}:${falsified}:${analyzing}"
}

# Extract and save per-lemma results from Tamarin log
extract_lemma_results() {
    local log_file="$1"
    local lemma_file="$2"

    # Extract processing time
    local proc_time=$(grep "processing time:" "$log_file" 2>/dev/null | sed 's/.*processing time: //' | tr -d ' ')

    # Extract individual lemma results (format: "lemma_name (type): status (N steps)")
    {
        echo "Processing time: ${proc_time:-N/A}"
        echo "-------------------------------------------------------------------"
        printf "%-40s %-12s %-10s %s\n" "Lemma" "Status" "Time" "Peak Mem"
        echo "-------------------------------------------------------------------"
        grep -E "^\s+\S+\s+\((all-traces|exists-trace)\):" "$log_file" 2>/dev/null | \
        while read -r line; do
            # Parse: "  lemma_name (type): status (N steps)"
            local lemma=$(echo "$line" | sed 's/^\s*//' | cut -d' ' -f1)
            local status=$(echo "$line" | grep -oE "(verified|falsified|analysis incomplete)" | head -1)
            local steps=$(echo "$line" | grep -oE "\([0-9]+ steps?\)" | tr -d '()')
            printf "%-40s %-12s %-10s %s\n" "$lemma" "${status:-unknown}" "N/A" "N/A"
        done
        echo "-------------------------------------------------------------------"
        echo "(Per-lemma timing requires --per-lemma flag)"
    } > "$lemma_file"
}

# Run each lemma separately with individual timing
run_model_per_lemma() {
    local model_path="$1"
    local run_dir="$2"
    local model_name="$3"

    local full_path="${MODELS_DIR}/${model_path}"
    local lemma_dir="${run_dir}/${model_name}_lemmas"
    local lemma_results="${run_dir}/${model_name}_lemmas.txt"

    mkdir -p "$lemma_dir"

    # Extract all lemma names from the model
    local lemmas=()
    mapfile -t lemmas < <(extract_lemma_names "$full_path")

    if [[ ${#lemmas[@]} -eq 0 ]]; then
        echo "No lemmas found in model" > "$lemma_results"
        return 1
    fi

    local total_time=0
    local verified_count=0
    local falsified_count=0

    {
        echo "Per-Lemma Timing Results"
        echo "-------------------------------------------------------------------"
        printf "%-40s %-12s %8s %10s %s\n" "Lemma" "Status" "Time(s)" "Peak Mem" "Steps"
        echo "-------------------------------------------------------------------"

        for lemma in "${lemmas[@]}"; do
            if [[ "$VERBOSE" == true ]]; then
                echo -ne "\r  Proving: $lemma...                    " >&2
            fi

            # Run single lemma
            local result=$(run_single_lemma "$model_path" "$lemma" "$lemma_dir" "$USE_DOCKER")
            IFS='|' read -r l_name l_status l_time l_mem l_steps <<< "$result"

            printf "%-40s %-12s %8s %10s %s\n" "$l_name" "$l_status" "${l_time}s" "$l_mem" "$l_steps"

            total_time=$((total_time + l_time))
            if [[ "$l_status" == "verified" ]]; then
                verified_count=$((verified_count + 1))
            elif [[ "$l_status" == "falsified" ]]; then
                falsified_count=$((falsified_count + 1))
            fi
        done

        echo "-------------------------------------------------------------------"
        echo "Total: ${#lemmas[@]} lemmas, ${verified_count} verified, ${falsified_count} falsified"
        echo "Total time: ${total_time}s"
    } > "$lemma_results"

    # Return counts for summary
    echo "${verified_count}:${falsified_count}:0:${total_time}"
}

parse_proverif_results() {
    local log_file="$1"

    local verified=0
    local falsified=0

    if grep -q "RESULT.*true" "$log_file"; then
        verified=$(grep -c "RESULT.*true" "$log_file" || echo 0)
    fi
    if grep -q "RESULT.*false" "$log_file"; then
        falsified=$(grep -c "RESULT.*false" "$log_file" || echo 0)
    fi

    echo "${verified}:${falsified}:0"
}

run_model() {
    local entry="$1"
    local run_dir="$2"

    local model_path=$(get_model_field "$entry" 1)
    local properties=$(get_model_field "$entry" 2)
    local preferred_tool=$(get_model_field "$entry" 3)
    local expected=$(get_model_field "$entry" 4)
    local time_est=$(get_model_field "$entry" 5)
    local group=$(get_model_field "$entry" 6)
    local description=$(get_model_field "$entry" 7)

    local tool=$(select_tool "$model_path" "$preferred_tool")
    local model_name=$(basename "$model_path" .spthy)
    local log_file="${run_dir}/${model_name}.log"

    local timeout_val
    if [[ "$MODE" == "quick" ]]; then
        timeout_val=$TIMEOUT_QUICK
    else
        timeout_val=$TIMEOUT_FULL
    fi

    local start_time=$(date +%s)
    local status="unknown"
    local exit_code=0

    if [[ "$VERBOSE" == true ]]; then
        print_info "Running $model_name with $tool (timeout: ${timeout_val}s)"
    fi

    # Per-lemma mode: run each lemma separately with timing
    if [[ "$PER_LEMMA" == true && "$tool" == "tamarin" && "$PARSE_ONLY" != true ]]; then
        local per_lemma_results=$(run_model_per_lemma "$model_path" "$run_dir" "$model_name")
        IFS=':' read -r verified falsified incomplete duration <<< "$per_lemma_results"

        # Determine status
        if [[ $falsified -gt 0 && "$expected" == "falsified" ]]; then
            status="expected_fail"
        elif [[ $falsified -gt 0 && "$expected" == "mixed" ]]; then
            status="expected_mixed"
        elif [[ $falsified -gt 0 && "$expected" == "attack_exists" ]]; then
            status="attack_found"
        elif [[ $falsified -gt 0 ]]; then
            status="unexpected_fail"
        elif [[ $verified -gt 0 ]]; then
            status="verified"
        fi

        local actual_tool="tamarin"
        local peak_mem_fmt="(per-lemma)"
        echo "${model_name}|${properties}|${actual_tool}|${status}|${duration}|${verified}|${falsified}|${group}|${description}|${peak_mem_fmt}"
        return
    fi

    if [[ "$USE_DOCKER" == true ]]; then
        # Use Docker-based execution
        if [[ "$tool" == "tamarin" ]]; then
            if run_tamarin_docker "$model_path" "$timeout_val" "$log_file" "$PARSE_ONLY"; then
                exit_code=0
            else
                exit_code=$?
            fi
        else
            if run_proverif_docker "$model_path" "$timeout_val" "$log_file" "$PARSE_ONLY"; then
                exit_code=0
            else
                exit_code=$?
            fi
        fi
    else
        # Use local execution
        if [[ "$tool" == "tamarin" ]]; then
            if run_tamarin "$model_path" "$timeout_val" "$log_file" "$PARSE_ONLY"; then
                exit_code=0
            else
                exit_code=$?
            fi
        else
            if run_proverif "$model_path" "$timeout_val" "$log_file" "$PARSE_ONLY"; then
                exit_code=0
            else
                exit_code=$?
            fi
        fi
    fi

    local end_time=$(date +%s)
    local duration=$((end_time - start_time))

    # Extract peak memory usage
    local time_file="${log_file%.log}_time.txt"
    local peak_mem_kb=0
    if [[ -f "$time_file" ]]; then
        peak_mem_kb=$(extract_peak_memory "$time_file")
    fi
    local peak_mem_fmt=$(format_memory "$peak_mem_kb")

    # Parse results
    # In Docker mode, always use Tamarin parser since all models run with Tamarin
    local results
    local actual_tool="$tool"
    if [[ "$USE_DOCKER" == true ]]; then
        actual_tool="tamarin"
    fi

    if [[ "$actual_tool" == "tamarin" ]]; then
        results=$(parse_tamarin_results "$log_file")
        # Extract per-lemma results to separate file
        local lemma_file="${run_dir}/${model_name}_lemmas.txt"
        extract_lemma_results "$log_file" "$lemma_file"
    else
        results=$(parse_proverif_results "$log_file")
    fi

    local verified=$(echo "$results" | cut -d':' -f1)
    local falsified=$(echo "$results" | cut -d':' -f2)
    local incomplete=$(echo "$results" | cut -d':' -f3)

    # Determine status
    if [[ $exit_code -eq 124 ]]; then
        status="timeout"
    elif [[ $exit_code -ne 0 ]]; then
        status="error"
    elif [[ "$PARSE_ONLY" == true ]]; then
        if grep -q "ERROR\|error\|Error" "$log_file"; then
            status="parse_error"
        else
            status="parsed"
        fi
    elif [[ $incomplete -gt 0 ]]; then
        status="incomplete"
    elif [[ $falsified -gt 0 && "$expected" == "falsified" ]]; then
        status="expected_fail"
    elif [[ $falsified -gt 0 && "$expected" == "mixed" ]]; then
        status="expected_mixed"
    elif [[ $falsified -gt 0 && "$expected" == "attack_exists" ]]; then
        status="attack_found"
    elif [[ $falsified -gt 0 ]]; then
        status="unexpected_fail"
    elif [[ $verified -gt 0 ]]; then
        status="verified"
    else
        status="unknown"
    fi

    # Output result line (use actual_tool to show what really ran)
    echo "${model_name}|${properties}|${actual_tool}|${status}|${duration}|${verified}|${falsified}|${group}|${description}|${peak_mem_fmt}"
}

# =============================================================================
# Main Functions
# =============================================================================

filter_models() {
    local filtered=()

    for entry in "${MODEL_REGISTRY[@]}"; do
        local model_path=$(get_model_field "$entry" 1)
        local group=$(get_model_field "$entry" 6)
        local include=false

        # Apply group filter first - if a specific group is requested,
        # include all models from that group regardless of quick/full mode
        if [[ -n "$SPECIFIC_GROUP" ]]; then
            if [[ "$group" == "$SPECIFIC_GROUP" ]]; then
                include=true
            fi
        # Apply mode filter only when no specific group is requested
        elif [[ "$MODE" == "quick" ]]; then
            if is_quick_model "$model_path"; then
                include=true
            fi
        else
            include=true
        fi

        # Apply model pattern filter
        if [[ -n "$SPECIFIC_MODEL" ]] && [[ "$model_path" != *"$SPECIFIC_MODEL"* ]]; then
            include=false
        fi

        if [[ "$include" == true ]]; then
            filtered+=("$entry")
        fi
    done

    # Output each entry on a separate line to preserve entries with spaces
    # Only print if there are entries (printf with empty array prints empty line)
    if [[ ${#filtered[@]} -gt 0 ]]; then
        printf '%s\n' "${filtered[@]}"
    fi
}

print_composition_report() {
    local results_file="$1"

    print_header "CROSS-RFC VERIFICATION REPORT"

    # Parse results by group
    declare -A group_verified
    declare -A group_falsified
    declare -A group_expected

    while IFS='|' read -r name props tool status duration verified falsified group desc; do
        # Skip lines with empty group
        [[ -z "$group" ]] && continue

        group_verified[$group]=$((${group_verified[$group]:-0} + verified))
        group_falsified[$group]=$((${group_falsified[$group]:-0} + falsified))

        # Track if all results match expectations
        if [[ "$status" == "verified" || "$status" == "expected_fail" || "$status" == "expected_mixed" || "$status" == "attack_found" ]]; then
            group_expected[$group]=$((${group_expected[$group]:-0} + 1))
        fi
    done < "$results_file"

    # Print group summaries
    echo -e "${BOLD}Group: Bounded Cache Checks (Properties 1-6, 8-9)${NC}"
    if [[ "${group_verified[cache]:-0}" -gt 0 ]]; then
        print_info "Some cache lemmas were counted as verified; inspect each formula and log"
    else
        print_warning "Cache models not run or incomplete"
    fi
    echo ""

    echo -e "${BOLD}Group: Data Authentication (Properties 10-12, 14)${NC}"
    if [[ "${group_verified[auth]:-0}" -gt 0 ]]; then
        print_info "Some authentication lemmas were counted as verified; P13 is separate"
    else
        print_warning "Auth models not run or incomplete"
    fi
    echo ""

    echo -e "${BOLD}Group: Denial of Existence (Properties 15-20)${NC}"
    if [[ "${group_verified[denial]:-0}" -gt 0 ]]; then
        print_info "Some denial lemmas were counted as verified; this is not a group proof"
        print_warning "P16 has no executable secrecy lemma in the imported NSEC model"
    else
        print_warning "Denial models not run or incomplete"
    fi
    echo ""

    echo -e "${BOLD}Group: Cross-RFC Composition (Properties 21-23)${NC}"
    if [[ "${group_falsified[aggressive]:-0}" -gt 0 ]]; then
        print_warning "At least one falsified query was counted in this group"
        print_info "Inspect its formula and trace; this does not establish all of P21-P23"
        print_info "Safety and reachability checks have different result interpretations"
    else
        print_warning "Composition models not run or incomplete"
    fi
    echo ""

    echo -e "${BOLD}Group: Known Attacks (Properties 7, 13)${NC}"
    if [[ "${group_falsified[attacks]:-0}" -gt 0 || "${group_verified[attacks]:-0}" -gt 0 ]]; then
        print_info "Known-attack query results were counted; inspect their formulas and traces"
        print_info "A group total alone does not establish both P7 and P13"
    else
        print_warning "Attack models not run or incomplete"
    fi
    echo ""

    # Print cross-RFC claim
    echo -e "${BOLD}${CYAN}INTERPRETATION LIMITS:${NC}"
    echo "This aggregate report is not a per-property proof or composition theorem."
    echo "The paper reports violations of P7, P13, P16, and P21-P23."
    echo "P16 has no executable query here; see MODEL_INDEX.md."
    echo "Read all per-query results; inconclusive output is not proof of an attack."
    echo ""
}

print_summary_table() {
    local results_file="$1"

    print_header "VERIFICATION SUMMARY"

    printf "%-35s %-6s %-8s %-12s %7s %10s\n" "Model" "Props" "Tool" "Status" "Time(s)" "Peak Mem"
    printf "%-35s %-6s %-8s %-12s %7s %10s\n" "$(printf '%0.s-' {1..35})" "------" "--------" "------------" "-------" "----------"

    while IFS='|' read -r name props tool status duration verified falsified group desc peak_mem; do
        local status_colored
        case "$status" in
            verified)         status_colored="${GREEN}verified${NC}" ;;
            expected_fail)    status_colored="${YELLOW}exp. fail${NC}" ;;
            expected_mixed)   status_colored="${YELLOW}mixed${NC}" ;;
            attack_found)     status_colored="${GREEN}attack ok${NC}" ;;
            unexpected_fail)  status_colored="${RED}UNEXPECTED${NC}" ;;
            timeout)          status_colored="${RED}timeout${NC}" ;;
            error)            status_colored="${RED}error${NC}" ;;
            parsed)           status_colored="${GREEN}parsed${NC}" ;;
            parse_error)      status_colored="${RED}parse err${NC}" ;;
            *)                status_colored="$status" ;;
        esac

        printf "%-35s %-6s %-8s ${status_colored}%*s %7s %10s\n" \
            "$name" "$props" "$tool" "" "$((12 - ${#status}))" "$duration" "${peak_mem:-N/A}"
    done < "$results_file"

    echo ""
}

print_lemma_details() {
    local run_dir="$1"

    print_header "PER-LEMMA VERIFICATION DETAILS"

    # Find all lemma result files
    for lemma_file in "${run_dir}"/*_lemmas.txt; do
        if [[ -f "$lemma_file" ]]; then
            local model_name=$(basename "$lemma_file" _lemmas.txt)
            echo -e "${BOLD}Model: ${model_name}${NC}"
            cat "$lemma_file"
            echo ""
        fi
    done
}

output_json() {
    local results_file="$1"
    local output_file="$2"

    echo "{" > "$output_file"
    echo '  "timestamp": "'$(date -Iseconds)'",' >> "$output_file"
    echo '  "mode": "'$MODE'",' >> "$output_file"
    echo '  "results": [' >> "$output_file"

    local first=true
    while IFS='|' read -r name props tool status duration verified falsified group desc peak_mem; do
        if [[ "$first" != true ]]; then
            echo "," >> "$output_file"
        fi
        first=false

        echo -n "    {" >> "$output_file"
        echo -n '"model": "'$name'", ' >> "$output_file"
        echo -n '"properties": "'$props'", ' >> "$output_file"
        echo -n '"tool": "'$tool'", ' >> "$output_file"
        echo -n '"status": "'$status'", ' >> "$output_file"
        echo -n '"duration_seconds": '$duration', ' >> "$output_file"
        echo -n '"verified_count": '$verified', ' >> "$output_file"
        echo -n '"falsified_count": '$falsified', ' >> "$output_file"
        echo -n '"group": "'$group'", ' >> "$output_file"
        echo -n '"description": "'$desc'", ' >> "$output_file"
        echo -n '"peak_memory": "'${peak_mem:-N/A}'"' >> "$output_file"
        echo -n "}" >> "$output_file"
    done < "$results_file"

    echo "" >> "$output_file"
    echo "  ]" >> "$output_file"
    echo "}" >> "$output_file"
}

main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --full)
                MODE="full"
                shift
                ;;
            --quick)
                MODE="quick"
                shift
                ;;
            --group)
                SPECIFIC_GROUP="$2"
                shift 2
                ;;
            --model)
                SPECIFIC_MODEL="$2"
                shift 2
                ;;
            --parallel)
                PARALLEL_JOBS="$2"
                shift 2
                ;;
            --timeout)
                TIMEOUT_QUICK="$2"
                TIMEOUT_FULL="$2"
                shift 2
                ;;
            --parse-only)
                PARSE_ONLY=true
                shift
                ;;
            --json)
                OUTPUT_FORMAT="json"
                shift
                ;;
            --docker)
                USE_DOCKER=true
                FORCE_DOCKER=true
                shift
                ;;
            --no-docker)
                USE_DOCKER=false
                FORCE_NO_DOCKER=true
                shift
                ;;
            --force-tamarin)
                FORCE_TOOL="tamarin"
                shift
                ;;
            --force-proverif)
                FORCE_TOOL="proverif"
                shift
                ;;
            --verbose|-v)
                VERBOSE=true
                shift
                ;;
            --no-memory)
                TRACK_MEMORY=false
                shift
                ;;
            --per-lemma)
                PER_LEMMA=true
                shift
                ;;
            --help|-h)
                show_help
                ;;
            *)
                # Treat as model pattern
                SPECIFIC_MODEL="$1"
                shift
                ;;
        esac
    done

    print_header "Cross-RFC Formal Analysis: Unified Verification"

    # Check dependencies
    check_dependencies

    # Create results directory
    local run_dir="${RESULTS_DIR}/run_${TIMESTAMP}"
    mkdir -p "$run_dir"

    print_info "Mode: $MODE"
    if [[ "$USE_DOCKER" == true ]]; then
        print_info "Execution: Docker ($DOCKER_IMAGE)"
    else
        print_info "Execution: Local (tamarin-prover)"
    fi
    print_info "Results directory: $run_dir"
    if [[ -n "$SPECIFIC_GROUP" ]]; then
        print_info "Group filter: $SPECIFIC_GROUP"
    fi
    if [[ -n "$SPECIFIC_MODEL" ]]; then
        print_info "Model filter: $SPECIFIC_MODEL"
    fi
    if [[ "$PARSE_ONLY" == true ]]; then
        print_info "Parse-only mode (no proofs)"
    fi
    echo ""

    # Get filtered models (using mapfile to handle entries with spaces)
    local models_to_run=()
    mapfile -t models_to_run < <(filter_models)

    if [[ ${#models_to_run[@]} -eq 0 ]]; then
        print_warning "No models match the specified criteria"
        exit 0
    fi

    print_info "Running ${#models_to_run[@]} model(s)..."
    echo ""

    # Run models
    local results_file="${run_dir}/results.txt"
    : > "$results_file"

    local completed=0
    local total=${#models_to_run[@]}

    for entry in "${models_to_run[@]}"; do
        local model_name=$(get_model_field "$entry" 1 | xargs basename | sed 's/.spthy//')
        echo -ne "\r[${completed}/${total}] Running: ${model_name}...                    "

        local result=$(run_model "$entry" "$run_dir")
        echo "$result" >> "$results_file"

        completed=$((completed + 1))
    done

    echo -e "\r[${total}/${total}] Complete!                                        "
    echo ""

    # Output results
    print_summary_table "$results_file"
    print_lemma_details "$run_dir"
    print_composition_report "$results_file"

    # Save summary
    {
        echo "Verification Run"
        echo "============================"
        echo "Timestamp: $(date)"
        echo "Mode: $MODE"
        echo ""
        print_summary_table "$results_file"
        print_lemma_details "$run_dir"
    } > "${run_dir}/summary.txt" 2>/dev/null || true

    # JSON output if requested
    if [[ "$OUTPUT_FORMAT" == "json" ]]; then
        local json_file="${run_dir}/results.json"
        output_json "$results_file" "$json_file"
        print_info "JSON results saved to: $json_file"
    fi

    print_info "Full logs available in: $run_dir"

    # Exit code based on unexpected failures
    if grep -q "unexpected_fail\|error" "$results_file"; then
        exit 1
    fi
    exit 0
}

# =============================================================================
# Entry Point
# =============================================================================

main "$@"
