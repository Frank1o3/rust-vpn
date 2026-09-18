#!/usr/bin/env bash
#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# RVPN Build / Install Tool
#
# Usage:
#   ./build.sh server
#   ./build.sh client
#   ./build.sh tray
#   ./build.sh all
#
# Server/client:
#   cargo build --release --bin ...
#   install binary
#   optionally install + enable systemd service
#
# Tray:
#   cargo build --release --bin rvpn-tray
#   install to ~/.local/bin
#   no system service
# ============================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

USER_BIN="${HOME}/.local/bin"
SYSTEM_BIN="/usr/local/bin"

SERVER_BIN="rvpn-server"
CLIENT_BIN="rvpn-client"
TRAY_BIN="rvpn-tray"

SERVER_SERVICE="rvpn-server.service"
CLIENT_SERVICE="rvpn-client.service"

# Common places where a repository might keep service files.
SERVICE_DIRS=(
    "${SCRIPT_DIR}/systemd"
    "${SCRIPT_DIR}/services"
    "${SCRIPT_DIR}/service"
    "${SCRIPT_DIR}"
)

# ------------------------------------------------------------
# Colors
# ------------------------------------------------------------

if [[ -t 1 ]]; then
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    CYAN='\033[36m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    CYAN=''
    RESET=''
fi

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

info() {
    printf '%b[INFO]%b %s\n' "$BLUE" "$RESET" "$*"
}

success() {
    printf '%b[OK]%b %s\n' "$GREEN" "$RESET" "$*"
}

warn() {
    printf '%b[WARN]%b %s\n' "$YELLOW" "$RESET" "$*"
}

error() {
    printf '%b[ERROR]%b %s\n' "$RED" "$RESET" "$*" >&2
}

die() {
    error "$*"
    exit 1
}

ask_yes_no() {
    local prompt="$1"
    local answer

    while true; do
        read -r -p "$prompt [y/N] " answer

        case "${answer,,}" in
            y|yes)
                return 0
                ;;
            n|no|"")
                return 1
                ;;
            *)
                echo "Please answer y or n."
                ;;
        esac
    done
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

find_service_file() {
    local service_name="$1"
    local directory

    for directory in "${SERVICE_DIRS[@]}"; do
        if [[ -f "${directory}/${service_name}" ]]; then
            printf '%s\n' "${directory}/${service_name}"
            return 0
        fi
    done

    return 1
}

require_command() {
    command_exists "$1" || die "Required command not found: $1"
}

# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

check_dependencies() {
    require_command cargo
    require_command install
    require_command sudo
    require_command systemctl
}

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

build_binary() {
    local binary="$1"

    info "Building ${binary}..."

    cargo build \
        --release \
        --bin "$binary"

    local artifact="${SCRIPT_DIR}/target/release/${binary}"

    [[ -f "$artifact" ]] || die \
        "Cargo reported success, but ${artifact} was not found."

    success "Built ${artifact}"
}

# ------------------------------------------------------------
# Install binary
# ------------------------------------------------------------

install_user_binary() {
    local binary="$1"

    local source="${SCRIPT_DIR}/target/release/${binary}"
    local destination="${USER_BIN}/${binary}"

    mkdir -p "$USER_BIN"

    info "Installing ${binary} to ${USER_BIN}..."

    install -Dm755 "$source" "$destination"

    success "Installed ${destination}"
}

install_system_binary() {
    local binary="$1"

    local source="${SCRIPT_DIR}/target/release/${binary}"
    local destination="${SYSTEM_BIN}/${binary}"

    info "Installing ${binary} to ${SYSTEM_BIN}..."

    sudo install -Dm755 "$source" "$destination"

    success "Installed ${destination}"
}

# ------------------------------------------------------------
# Service installation
# ------------------------------------------------------------

install_system_service() {
    local service_name="$1"
    local binary_name="$2"

    local source

    if ! source="$(find_service_file "$service_name")"; then
        warn "Could not find ${service_name} in the repository."
        warn "Checked:"
        for directory in "${SERVICE_DIRS[@]}"; do
            printf '  %s\n' "${directory}/${service_name}"
        done

        return 1
    fi

    info "Found service file:"
    printf '  %s\n' "$source"

    info "Installing ${service_name}..."

    sudo install -Dm644 \
        "$source" \
        "/etc/systemd/system/${service_name}"

    sudo systemctl daemon-reload

    success "Installed /etc/systemd/system/${service_name}"

    if ask_yes_no "Enable ${service_name} at boot?"; then
        sudo systemctl enable "$service_name"
        success "${service_name} enabled"
    else
        info "${service_name} was not enabled"
    fi

    if ask_yes_no "Start ${service_name} now?"; then
        sudo systemctl start "$service_name"
        success "${service_name} started"
    else
        info "${service_name} was not started"
    fi

    echo
    info "Current status:"
    sudo systemctl --no-pager --full status "$service_name" || true

    return 0
}

# ------------------------------------------------------------
# Server
# ------------------------------------------------------------

build_server() {
    echo
    printf '%b=== RVPN SERVER ===%b\n' "$CYAN" "$RESET"
    echo

    build_binary "$SERVER_BIN"

    #
    # System daemons belong in /usr/local/bin rather than
    # ~/.local/bin. This makes them accessible to systemd
    # regardless of the user's home-directory permissions.
    #
    install_system_binary "$SERVER_BIN"

    echo

    if ask_yes_no "Install the RVPN server systemd service?"; then
        if ! install_system_service \
            "$SERVER_SERVICE" \
            "$SERVER_BIN"
        then
            warn "Server binary was installed, but the service was not installed."
        fi
    else
        info "Skipping server service installation."
    fi

    echo
    success "Server build complete."
}

# ------------------------------------------------------------
# Client
# ------------------------------------------------------------

build_client() {
    echo
    printf '%b=== RVPN CLIENT ===%b\n' "$CYAN" "$RESET"
    echo

    build_binary "$CLIENT_BIN"

    #
    # The client daemon can require NET_ADMIN / NET_RAW and
    # therefore belongs in the system installation path.
    #
    install_system_binary "$CLIENT_BIN"

    echo

    local service_installed=0

    if ask_yes_no "Install the RVPN client systemd service?"; then
        if install_system_service \
            "$CLIENT_SERVICE" \
            "$CLIENT_BIN"
        then
            service_installed=1
        else
            warn "Client binary was installed, but the service was not installed."
        fi
    else
        info "Skipping client service installation."
    fi

    #
    # Build the tray when the client setup was accepted.
    #
    if [[ "$service_installed" -eq 1 ]]; then
        echo

        if ask_yes_no "Build and install RVPN Tray too?"; then
            build_tray
        else
            info "Skipping tray build."
        fi
    fi

    echo
    success "Client build complete."
}

# ------------------------------------------------------------
# Tray
# ------------------------------------------------------------

build_tray() {
    echo
    printf '%b=== RVPN TRAY ===%b\n' "$CYAN" "$RESET"
    echo

    build_binary "$TRAY_BIN"

    install_user_binary "$TRAY_BIN"

    echo
    success "Tray installed to:"
    printf '  %s\n' "${USER_BIN}/${TRAY_BIN}"

    echo
    info "The tray does not need a root/systemd service."
    info "You can start it manually with:"
    printf '  %s\n' "$TRAY_BIN"

    echo
    info "For Hyprland autostart, add:"
    printf '  exec-once = %s\n' "${USER_BIN}/${TRAY_BIN}"

    echo
}

# ------------------------------------------------------------
# All
# ------------------------------------------------------------

build_all() {
    build_server
    build_client

    echo

    if [[ ! -x "${USER_BIN}/${TRAY_BIN}" ]]; then
        if ask_yes_no "Build and install RVPN Tray?"; then
            build_tray
        fi
    fi

    echo
    success "RVPN build/install process complete."
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

usage() {
    cat <<EOF
RVPN build tool

Usage:
    ./build.sh server
    ./build.sh client
    ./build.sh tray
    ./build.sh all

Commands:
    server    Build rvpn-server and optionally install/enable its service.
    client    Build rvpn-client and optionally install/enable its service.
    tray      Build rvpn-tray and install it to ~/.local/bin.
    all       Build server, client, and optionally tray.
EOF
}

check_dependencies

case "${1:-}" in
    server)
        build_server
        ;;

    client)
        build_client
        ;;

    tray)
        build_tray
        ;;

    all)
        build_all
        ;;

    help|-h|--help)
        usage
        ;;

    *)
        usage
        exit 1
        ;;
esac