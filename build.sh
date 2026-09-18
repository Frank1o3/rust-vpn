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
# Server:
#   Build rvpn-server, install it system-wide, and optionally
#   install/enable rvpn-server.service.
#
# Client:
#   Build rvpn-client, install it system-wide, install its
#   capabilities, and optionally install/enable the per-user
#   rvpn-client@<user>.service instance.
#
# Tray:
#   Build rvpn-tray, install it to ~/.local/bin, and optionally
#   install/enable the per-user rvpn-tray.service.
# ============================================================

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [[ "$EUID" -eq 0 ]]; then
    echo "Do not run build.sh as root."
    echo "Run it as your normal user; it will use sudo when needed."
    exit 1
fi

# ------------------------------------------------------------
# Configuration
# ------------------------------------------------------------

USER_BIN="${HOME}/.local/bin"
USER_SERVICE_DIR="${HOME}/.config/systemd/user"
SYSTEM_BIN="/usr/local/bin"
SYSTEM_SERVICE_DIR="/etc/systemd/system"

SERVER_BIN="rvpn-server"
CLIENT_BIN="rvpn-client"
TRAY_BIN="rvpn-tray"

SERVER_SERVICE="rvpn-server.service"
CLIENT_TEMPLATE="rvpn-client@.service"
TRAY_SERVICE="rvpn-tray.service"

# The account whose user context should own the client service.
# When build.sh is run normally this is simply $USER. If it is
# ever invoked through sudo, preserve the original user.
INSTALL_USER="${SUDO_USER:-${USER}}"

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

require_command() {
    command_exists "$1" || die "Required command not found: $1"
}

# ------------------------------------------------------------
# Dependency checks
# ------------------------------------------------------------

check_dependencies() {
    require_command cargo
    require_command install
    require_command rm
    require_command systemctl
    require_command id
}

# ------------------------------------------------------------
# Service file lookup
# ------------------------------------------------------------

find_service_file() {
    local service_name="$1"
    local path="${SCRIPT_DIR}/services/${service_name}"

    [[ -f "$path" ]] || die "Service file not found: $path"

    printf '%s\n' "$path"
}

# ------------------------------------------------------------
# Build
# ------------------------------------------------------------

build_binary() {
    local binary="$1"

    info "Building ${binary}..."

    cargo build         --release         --bin "$binary"

    local artifact="${SCRIPT_DIR}/target/release/${binary}"

    [[ -f "$artifact" ]] || die         "Cargo reported success, but ${artifact} was not found."

    success "Built ${artifact}"
}

# ------------------------------------------------------------
# Binary installation
# ------------------------------------------------------------

install_system_binary() {
    local binary="$1"
    local source="${SCRIPT_DIR}/target/release/${binary}"
    local destination="${SYSTEM_BIN}/${binary}"

    info "Installing ${binary} to ${destination}..."

    sudo install -Dm755 "$source" "$destination"

    success "Installed ${destination}"
}

install_user_binary() {
    local binary="$1"
    local source="${SCRIPT_DIR}/target/release/${binary}"
    local destination="${USER_BIN}/${binary}"

    mkdir -p "$USER_BIN"

    info "Installing ${binary} to ${destination}..."

    install -Dm755 "$source" "$destination"

    success "Installed ${destination}"
}

# ------------------------------------------------------------
# Client capabilities
# ------------------------------------------------------------

grant_client_capabilities() {
    require_command setcap

    local binary="${SYSTEM_BIN}/${CLIENT_BIN}"

    info "Granting CAP_NET_ADMIN and CAP_NET_RAW to ${binary}..."

    sudo setcap 'cap_net_admin,cap_net_raw=+eip' "$binary"

    success "Client capabilities installed"

    if command_exists getcap; then
        getcap "$binary" || true
    fi
}

# ------------------------------------------------------------
# System service installation
# ------------------------------------------------------------

install_system_service() {
    local service_name="$1"

    local source
    source="$(find_service_file "$service_name")"

    info "Installing ${service_name}..."

    sudo install -Dm644         "$source"         "${SYSTEM_SERVICE_DIR}/${service_name}"

    sudo systemctl daemon-reload

    success "Installed ${SYSTEM_SERVICE_DIR}/${service_name}"
}

# ------------------------------------------------------------
# Server service
# ------------------------------------------------------------

ensure_server_user() {
    if id rvpn >/dev/null 2>&1; then
        return
    fi

    info "Creating dedicated rvpn system user..."

    local nologin_shell
    nologin_shell="$(command -v nologin || true)"
    [[ -n "$nologin_shell" ]] || die "Could not find the nologin shell executable."

    sudo useradd \
        --system \
        --create-home \
        --home-dir /var/lib/rvpn \
        --shell "$nologin_shell" \
        rvpn

    success "Created rvpn system user"
}

install_server_service() {
    ensure_server_user
    install_system_service "$SERVER_SERVICE"

    echo

    if ask_yes_no "Enable ${SERVER_SERVICE} at boot?"; then
        sudo systemctl enable "$SERVER_SERVICE"
        success "${SERVER_SERVICE} enabled"
    else
        info "${SERVER_SERVICE} was not enabled"
    fi

    echo

    if ask_yes_no "Start ${SERVER_SERVICE} now?"; then
        sudo systemctl start "$SERVER_SERVICE"
        success "${SERVER_SERVICE} started"
    else
        info "${SERVER_SERVICE} was not started"
    fi
}

# ------------------------------------------------------------
# Client service
# ------------------------------------------------------------

install_client_service() {
    local instance="rvpn-client@${INSTALL_USER}.service"

    if ! id "$INSTALL_USER" >/dev/null 2>&1; then
        die "Unable to resolve install user: ${INSTALL_USER}"
    fi

    install_system_service "$CLIENT_TEMPLATE"

    #
    # Remove the old non-templated service if an older RVPN
    # installation left one behind.
    #
    if sudo systemctl list-unit-files --all |         grep -q '^rvpn-client\.service'; then

        warn "Found legacy rvpn-client.service; disabling it."

        sudo systemctl disable --now rvpn-client.service 2>/dev/null || true
    fi

    sudo rm -f "${SYSTEM_SERVICE_DIR}/rvpn-client.service"
    sudo systemctl daemon-reload

    echo
    info "Client service instance: ${instance}"

    if ask_yes_no "Enable ${instance} at boot?"; then
        sudo systemctl enable "${instance}"
        success "${instance} enabled"
    else
        info "${instance} was not enabled"
    fi

    echo

    if ask_yes_no "Start ${instance} now?"; then
        sudo systemctl start "${instance}"
        success "${instance} started"
    else
        info "${instance} was not started"
    fi

    echo
    info "Client service status:"
    sudo systemctl --no-pager --full status "${instance}" || true
}

# ------------------------------------------------------------
# Tray service
# ------------------------------------------------------------

install_tray_service() {
    local source
    source="$(find_service_file "$TRAY_SERVICE")"

    mkdir -p "$USER_SERVICE_DIR"

    info "Installing ${TRAY_SERVICE} to ${USER_SERVICE_DIR}..."

    install -Dm644         "$source"         "${USER_SERVICE_DIR}/${TRAY_SERVICE}"

    systemctl --user daemon-reload

    success "Installed ${USER_SERVICE_DIR}/${TRAY_SERVICE}"

    echo

    if ask_yes_no "Enable ${TRAY_SERVICE} for your user session?"; then
        systemctl --user enable "$TRAY_SERVICE"
        success "${TRAY_SERVICE} enabled"
    else
        info "${TRAY_SERVICE} was not enabled"
    fi

    echo

    if ask_yes_no "Start ${TRAY_SERVICE} now?"; then
        systemctl --user start "$TRAY_SERVICE"
        success "${TRAY_SERVICE} started"
    else
        info "${TRAY_SERVICE} was not started"
    fi
}

# ------------------------------------------------------------
# Server
# ------------------------------------------------------------

build_server() {
    echo
    printf '%b=== RVPN SERVER ===%b\n' "$CYAN" "$RESET"
    echo

    build_binary "$SERVER_BIN"
    install_system_binary "$SERVER_BIN"

    echo

    if ask_yes_no "Install the RVPN server systemd service?"; then
        install_server_service
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
    install_system_binary "$CLIENT_BIN"
    grant_client_capabilities

    echo

    if ask_yes_no "Install the RVPN client systemd service?"; then
        install_client_service
    else
        info "Skipping client service installation."
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

    if ask_yes_no "Install the RVPN tray user service?"; then
        install_tray_service
    else
        info "Skipping tray service installation."
    fi

    echo
    success "Tray build complete."
}

# ------------------------------------------------------------
# All
# ------------------------------------------------------------

build_all() {
    build_server
    build_client
    build_tray

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
    server    Build rvpn-server and optionally install/enable
              rvpn-server.service.

    client    Build rvpn-client, grant CAP_NET_ADMIN and
              CAP_NET_RAW, and optionally install/enable
              rvpn-client@<user>.service.

    tray      Build rvpn-tray, install it to ~/.local/bin,
              and optionally install/enable rvpn-tray.service
              as a user service.

    all       Build and install server, client, and tray.
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
