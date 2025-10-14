#!/bin/bash

# Enhanced startup script for caido-hunt scanner
# Version: 2.1
# Features: Health checks, error handling, logging, dependency validation

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="$SCRIPT_DIR/caido-env"
LOG_DIR="$SCRIPT_DIR/logs"
CONFIG_FILE="$SCRIPT_DIR/config.json"
PYTHON_MIN_VERSION="3.8"
GECKODRIVER_PATH="$SCRIPT_DIR/geckodriver"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $(date '+%Y-%m-%d %H:%M:%S') - $1"
}

# Error handling
cleanup() {
    local exit_code=$?
    if [ $exit_code -ne 0 ]; then
        log_error "Script failed with exit code $exit_code"
    fi
    exit $exit_code
}

trap cleanup EXIT

# Create necessary directories
create_directories() {
    log_info "Creating necessary directories..."
    mkdir -p "$LOG_DIR"
    mkdir -p "$SCRIPT_DIR/caido_results"
    mkdir -p "$SCRIPT_DIR/wordlists"
}

# Check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check Python version
check_python_version() {
    log_info "Checking Python version..."

    if ! command_exists python3; then
        log_error "Python 3 is not installed"
        return 1
    fi

    local python_version
    python_version=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')

    local required_version="$PYTHON_MIN_VERSION"

    if [ "$(printf '%s\n' "$required_version" "$python_version" | sort -V | head -n1)" != "$required_version" ]; then
        log_error "Python $python_version is installed, but $required_version or higher is required"
        return 1
    fi

    log_success "Python $python_version is installed"
    return 0
}

# Check virtual environment
check_virtual_env() {
    log_info "Checking virtual environment..."

    if [ ! -d "$VENV_DIR" ]; then
        log_warn "Virtual environment not found. Creating..."
        python3 -m venv "$VENV_DIR"
        log_success "Virtual environment created"
    fi

    if [ ! -f "$VENV_DIR/bin/activate" ]; then
        log_error "Virtual environment activation script not found"
        return 1
    fi

    log_success "Virtual environment is ready"
    return 0
}

# Check and install dependencies
check_dependencies() {
    log_info "Checking Python dependencies..."

    # Activate virtual environment
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    # Check if requirements.txt exists
    if [ ! -f "$SCRIPT_DIR/requirements.txt" ]; then
        log_error "requirements.txt not found"
        return 1
    fi

    # Install/update dependencies
    log_info "Installing/updating dependencies..."
    pip install --upgrade pip
    pip install -r "$SCRIPT_DIR/requirements.txt"

    # Verify critical dependencies
    local critical_deps=("requests" "bs4" "selenium" "tldextract")
    local dep_names=("requests" "beautifulsoup4" "selenium" "tldextract")

    for i in "${!critical_deps[@]}"; do
        dep="${critical_deps[$i]}"
        dep_name="${dep_names[$i]}"
        if ! python3 -c "import $dep" 2>/dev/null; then
            log_error "Critical dependency '$dep_name' is not installed correctly"
            return 1
        fi
    done

    log_success "All dependencies are installed"
    return 0
}

# Check Geckodriver
check_geckodriver() {
    log_info "Checking Geckodriver..."

    if [ ! -f "$GECKODRIVER_PATH" ]; then
        log_error "Geckodriver not found at $GECKODRIVER_PATH"
        log_info "Please download Geckodriver from: https://github.com/mozilla/geckodriver/releases"
        return 1
    fi

    if [ ! -x "$GECKODRIVER_PATH" ]; then
        log_warn "Making Geckodriver executable..."
        chmod +x "$GECKODRIVER_PATH"
    fi

    # Check Geckodriver version
    local gecko_version
    if gecko_version=$("$GECKODRIVER_PATH" --version 2>/dev/null | head -n1); then
        log_success "Geckodriver is ready: $gecko_version"
    else
        log_error "Geckodriver is not working properly"
        return 1
    fi

    return 0
}

# Check Firefox installation
check_firefox() {
    log_info "Checking Firefox installation..."

    if command_exists firefox; then
        local firefox_version
        firefox_version=$(firefox --version 2>/dev/null || echo "Unknown")
        log_success "Firefox is installed: $firefox_version"
        return 0
    else
        log_warn "Firefox not found. Screenshots may not work."
        log_info "Install Firefox: sudo apt-get install firefox (Ubuntu/Debian)"
        return 0  # Not critical for basic functionality
    fi
}

# Check system dependencies
check_system_dependencies() {
    log_info "Checking system dependencies..."

    local deps_missing=0

    # Check for common tools
    local tools=("curl" "wget" "unzip")

    for tool in "${tools[@]}"; do
        if ! command_exists "$tool"; then
            log_warn "$tool is not installed"
            deps_missing=1
        fi
    done

    if [ $deps_missing -eq 1 ]; then
        log_warn "Some optional system dependencies are missing"
        log_info "Install missing tools with: sudo apt-get install curl wget unzip"
    else
        log_success "All system dependencies are available"
    fi

    return 0
}

# Validate configuration
validate_config() {
    log_info "Validating configuration..."

    # Check if config file exists, create template if not
    if [ ! -f "$CONFIG_FILE" ]; then
        log_warn "Configuration file not found. Creating template..."
        # shellcheck source=/dev/null
        source "$VENV_DIR/bin/activate"
        python3 -c "
from config import get_config
config = get_config()
config.export_template('$CONFIG_FILE')
" 2>/dev/null || log_warn "Could not create config template"
    fi

    log_success "Configuration validated"
    return 0
}

# Health check
health_check() {
    log_info "Performing health check..."

    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    # Test basic imports
    python3 -c "
import sys
import requests
import bs4
import selenium
import tldextract
print('All imports successful')
" || {
        log_error "Health check failed - import errors"
        return 1
    }

    log_success "Health check passed"
    return 0
}

# Display help
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Enhanced startup script for caido-hunt scanner"
    echo ""
    echo "OPTIONS:"
    echo "  -h, --help                Show this help message"
    echo "  -c, --check-only          Run checks only, don't start scanner"
    echo "  -v, --verbose             Enable verbose output"
    echo "  -u, --target URL          Target URL to scan"
    echo "  --proxy PROXY_URL         Proxy URL (default: http://127.0.0.1:8080)"
    echo "  --no-proxy                Run without proxy"
    echo "  --gui                     Enable web GUI"
    echo "  --headless                Use headless browser"
    echo "  --depth N                 Crawl depth (default: 3)"
    echo "  --workers N               Number of workers (default: 4)"
    echo "  --config FILE             Configuration file path"
    echo ""
    echo "Examples:"
    echo "  $0 -u https://example.com --gui"
    echo "  $0 --target https://test.com --depth 5 --workers 8"
    echo "  $0 --check-only"
    echo ""
}

# Parse command line arguments
parse_arguments() {
    CHECK_ONLY=0
    VERBOSE=0
    TARGET_URL=""
    PROXY_URL="http://127.0.0.1:8080"
    USE_PROXY=1
    ENABLE_GUI=0
    USE_HEADLESS=1
    CRAWL_DEPTH=3
    WORKER_COUNT=4

    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                show_help
                exit 0
                ;;
            -c|--check-only)
                CHECK_ONLY=1
                shift
                ;;
            -v|--verbose)
                VERBOSE=1
                shift
                ;;
            -u|--target)
                TARGET_URL="$2"
                shift 2
                ;;
            --proxy)
                PROXY_URL="$2"
                shift 2
                ;;
            --no-proxy)
                USE_PROXY=0
                shift
                ;;
            --gui)
                ENABLE_GUI=1
                shift
                ;;
            --headless)
                USE_HEADLESS=1
                shift
                ;;
            --depth)
                CRAWL_DEPTH="$2"
                shift 2
                ;;
            --workers)
                WORKER_COUNT="$2"
                shift 2
                ;;
            --config)
                CONFIG_FILE="$2"
                shift 2
                ;;
            *)
                log_error "Unknown argument: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Run all checks
run_checks() {
    log_info "Running comprehensive system checks..."

    local checks=(
        "create_directories"
        "check_python_version"
        "check_virtual_env"
        "check_dependencies"
        "check_geckodriver"
        "check_firefox"
        "check_system_dependencies"
        "validate_config"
        "health_check"
    )

    local failed_checks=0

    for check in "${checks[@]}"; do
        if ! $check; then
            log_error "Check failed: $check"
            failed_checks=$((failed_checks + 1))
        fi
    done

    if [ $failed_checks -gt 0 ]; then
        log_error "$failed_checks checks failed"
        return 1
    fi

    log_success "All checks passed successfully"
    return 0
}

# Start the scanner
start_scanner() {
    log_info "Starting caido-hunt scanner..."

    # Activate virtual environment
    # shellcheck source=/dev/null
    source "$VENV_DIR/bin/activate"

    # Build command arguments
    local cmd_args=()

    if [ -n "$TARGET_URL" ]; then
        cmd_args+=("--target" "$TARGET_URL")
    fi

    if [ $USE_PROXY -eq 1 ]; then
        cmd_args+=("--proxy" "$PROXY_URL")
    else
        cmd_args+=("--no-proxy")
    fi

    if [ $ENABLE_GUI -eq 1 ]; then
        cmd_args+=("--gui")
    fi

    if [ $USE_HEADLESS -eq 1 ]; then
        cmd_args+=("--headless")
    fi

    cmd_args+=("--depth" "$CRAWL_DEPTH")
    cmd_args+=("--workers" "$WORKER_COUNT")

    # Set environment variables
    export CAIDO_GECKODRIVER_PATH="$GECKODRIVER_PATH"
    export CAIDO_RESULTS_DIR="$SCRIPT_DIR/caido_results"
    export CAIDO_LOG_LEVEL="INFO"

    # Start the scanner
    log_info "Executing: python3 hunt.py ${cmd_args[*]}"

    if [ $VERBOSE -eq 1 ]; then
        python3 hunt.py "${cmd_args[@]}"
    else
        python3 hunt.py "${cmd_args[@]}" 2>&1 | tee "$LOG_DIR/scanner.log"
    fi
}

# Main function
main() {
    log_info "Starting caido-hunt startup sequence..."

    # Change to script directory
    cd "$SCRIPT_DIR" || {
        log_error "Failed to change to script directory: $SCRIPT_DIR"
        exit 1
    }

    # Parse arguments
    parse_arguments "$@"

    # Run checks
    if ! run_checks; then
        log_error "System checks failed. Please fix the issues and try again."
        exit 1
    fi

    # Exit if check-only mode
    if [ $CHECK_ONLY -eq 1 ]; then
        log_success "Check-only mode completed successfully"
        exit 0
    fi

    # Validate target URL if provided
    if [ -n "$TARGET_URL" ]; then
        log_info "Target URL: $TARGET_URL"
    else
        log_warn "No target URL specified. Scanner will prompt for target."
    fi

    # Start scanner
    start_scanner

    log_success "caido-hunt startup completed"
}

# Execute main function with all arguments
main "$@"
