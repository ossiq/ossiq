#!/bin/bash
set -e

# =============================================================================
# OSS IQ CLI - Docker Entrypoint
# =============================================================================
# Handles environment validation and command execution
# =============================================================================

# Colors for output (disable if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'
    YELLOW='\033[1;33m'
    GREEN='\033[0;32m'
    NC='\033[0m' # No Color
else
    RED=''
    YELLOW=''
    GREEN=''
    NC=''
fi

# -----------------------------------------------------------------------------
# Helper Functions
# -----------------------------------------------------------------------------

print_error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

print_warning() {
    echo -e "${YELLOW}WARNING:${NC} $1" >&2
}

print_info() {
    echo -e "${GREEN}INFO:${NC} $1"
}

show_usage() {
    cat << 'EOF'
OSS IQ CLI - Docker Usage

REQUIRED ENVIRONMENT VARIABLES:
  OSSIQ_GITHUB_TOKEN    GitHub Personal Access Token (required for API access)
                        Generate at: https://github.com/settings/tokens

OPTIONAL ENVIRONMENT VARIABLES:
  OSSIQ_VERBOSE         Enable verbose output (true/false)
  OSSIQ_PRESENTATION    Output format: console, html (default: console)
  OSSIQ_OUTPUT          Output file path (for html/json exports)

USAGE EXAMPLES:

  # Scan a local project (mount it to /project)
  docker run --rm \
    -e OSSIQ_GITHUB_TOKEN=$OSSIQ_GITHUB_TOKEN \
    -v /path/to/project:/project:ro \
    ossiq/ossiq-cli scan /project

  # Generate HTML report
  docker run --rm \
    -e OSSIQ_GITHUB_TOKEN=$OSSIQ_GITHUB_TOKEN \
    -v /path/to/project:/project:ro \
    -v /path/to/output:/output \
    ossiq/ossiq-cli scan -p html -o /output/report.html /project

  # Export to JSON
  docker run --rm \
    -e OSSIQ_GITHUB_TOKEN=$OSSIQ_GITHUB_TOKEN \
    -v /path/to/project:/project:ro \
    -v /path/to/output:/output \
    ossiq/ossiq-cli export -f json -o /output/data.json /project

  # Show help
  docker run --rm ossiq/ossiq-cli --help
  docker run --rm ossiq/ossiq-cli scan --help

For more information: https://github.com/ossiq/ossiq

EOF
}

# -----------------------------------------------------------------------------
# Environment Validation
# -----------------------------------------------------------------------------

validate_environment() {
    local has_errors=0

    # Check for GitHub token (required for most operations)
    if [ -z "${OSSIQ_GITHUB_TOKEN:-}" ]; then
        # Only error if we're running a command that needs the token
        # (not --help, --version, etc.)
        if [[ "${1:-}" == "scan" || "${1:-}" == "export" ]]; then
            print_error "OSSIQ_GITHUB_TOKEN is required but not set."
            print_info "Set it with: -e OSSIQ_GITHUB_TOKEN=your_token"
            print_info "Generate a token at: https://github.com/settings/tokens"
            has_errors=1
        fi
    fi

    # Validate token format if provided (basic sanity check)
    if [ -n "${OSSIQ_GITHUB_TOKEN:-}" ]; then
        # GitHub tokens are typically 40+ characters (classic) or start with ghp_/gho_/ghs_
        if [[ ${#OSSIQ_GITHUB_TOKEN} -lt 20 ]]; then
            print_warning "OSSIQ_GITHUB_TOKEN appears to be invalid (too short)."
        fi
    fi

    return $has_errors
}

# -----------------------------------------------------------------------------
# Main Execution
# -----------------------------------------------------------------------------

main() {
    # Show usage if explicitly requested
    if [[ "${1:-}" == "help" || "${1:-}" == "--usage" ]]; then
        show_usage
        exit 0
    fi

    # Validate environment for commands that need it
    if ! validate_environment "$@"; then
        echo ""
        exit 1
    fi

    # Log startup in verbose mode
    if [ "${OSSIQ_VERBOSE:-false}" = "true" ]; then
        print_info "Starting OSS IQ CLI"
        print_info "Working directory: $(pwd)"
        print_info "Command: ossiq-cli $*"
    fi

    # Execute the CLI command
    # Pass all arguments directly to ossiq-cli
    exec ossiq-cli "$@"
}

# Run main with all script arguments
main "$@"
