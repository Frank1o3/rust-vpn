#!/usr/bin/env bash

set -Eeuo pipefail

# ============================================================
# RVPN Uninstall Tool
#
# Usage:
#   ./uninstall.sh server
#   ./uninstall.sh client
#   ./uninstall.sh tray
#   ./uninstall.sh all
#
# Server:
#   Stop/disable rvpn-server.service, remove its unit and binary.
#
# Client:
#   Stop/disable every rvpn-client@<user>.service instance,
#   remove rvpn-client@.service (and any legacy rvpn-client.service),
#   then remove the client binary.
#
# Tray:
#   Stop/disable the current user's rvpn-tray.service, remove the
#   user unit, and remove ~/.local/bin/rvpn-tray.
# ============================================================

if [[ "$EUID" -eq 0 ]]; then
    echo "Do not run uninstall.sh as root."
    echo "Run it as your normal user; it will use sudo when needed."
    exit 1
fi

SYSTEM_BIN="/usr/local/bin"
USER_BIN="${HOME}/.local/bin"
SYSTEM_SERVICE_DIR="/etc/systemd/system"
USER_SERVICE_DIR="${HOME}/.config/systemd/user"

SERVER_SERVICE="rvpn-server.service"
CLIENT_TEMPLATE="rvpn-client@.service"
CLIENT_LEGACY_SERVICE="rvpn-client.service"
TRAY_SERVICE="rvpn-tray.service"

SERVER_BINARY="rvpn-server"
CLIENT_BINARY="rvpn-client"
TRAY_BINARY="rvpn-tray"

SYSTEM_SERVICE_PATHS=(
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
    "/lib/systemd/system"
)

# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------

require_sudo() {
    sudo -v
}

find_system_service_file() {
    local service="$1"
    local directory

    for directory in "${SYSTEM_SERVICE_PATHS[@]}"; do
        if [[ -f "${directory}/${service}" ]]; then
            printf '%s\n' "${directory}/${service}"
            return 0
        fi
    done

    return 1
}

remove_system_service_file() {
    local service="$1"
    local service_file

    if service_file="$(find_system_service_file "$service")"; then
        echo "Removing service file: ${service_file}"
        sudo rm -f "${service_file}"
    else
        echo "Service file not found: ${service}"
    fi
}

list_client_instances() {
    {
        sudo systemctl list-unit-files --no-legend 2>/dev/null |
            awk '$1 ~ /^rvpn-client@.*\\.service$/ {print $1}' || true

        sudo systemctl list-units --all --no-legend 2>/dev/null |
            awk '$1 ~ /^rvpn-client@.*\\.service$/ {print $1}' || true
    } | sort -u
}

# ------------------------------------------------------------
# Server
# ------------------------------------------------------------

uninstall_server() {
    echo
    echo "==> Uninstalling ${SERVER_BINARY}"

    require_sudo

    echo "Stopping ${SERVER_SERVICE}..."
    sudo systemctl stop "${SERVER_SERVICE}" 2>/dev/null || true

    echo "Disabling ${SERVER_SERVICE}..."
    sudo systemctl disable "${SERVER_SERVICE}" 2>/dev/null || true

    remove_system_service_file "${SERVER_SERVICE}"

    sudo systemctl daemon-reload

    local binary="${SYSTEM_BIN}/${SERVER_BINARY}"

    if [[ -f "${binary}" ]]; then
        echo "Removing binary: ${binary}"
        sudo rm -f "${binary}"
    else
        echo "Binary not found: ${binary}"
    fi

    echo "Finished uninstalling ${SERVER_BINARY}."
}

# ------------------------------------------------------------
# Client
# ------------------------------------------------------------

uninstall_client() {
    echo
    echo "==> Uninstalling ${CLIENT_BINARY}"

    require_sudo

    #
    # Stop and disable every instantiated client service. The
    # template is system-wide, so removing it while another user
    # still has an active instance would leave a broken service.
    #
    local instances
    instances="$(list_client_instances || true)"

    if [[ -n "${instances}" ]]; then
        while IFS= read -r instance; do
            [[ -n "${instance}" ]] || continue

            echo "Stopping ${instance}..."
            sudo systemctl stop "${instance}" 2>/dev/null || true

            echo "Disabling ${instance}..."
            sudo systemctl disable "${instance}" 2>/dev/null || true
        done <<< "${instances}"
    else
        echo "No instantiated RVPN client services found."
    fi

    #
    # Clean up the old non-templated service from older RVPN
    # installations as part of the migration.
    #
    echo "Checking for legacy ${CLIENT_LEGACY_SERVICE}..."

    sudo systemctl stop "${CLIENT_LEGACY_SERVICE}" 2>/dev/null || true
    sudo systemctl disable "${CLIENT_LEGACY_SERVICE}" 2>/dev/null || true

    remove_system_service_file "${CLIENT_TEMPLATE}"
    remove_system_service_file "${CLIENT_LEGACY_SERVICE}"

    sudo systemctl daemon-reload

    local binary="${SYSTEM_BIN}/${CLIENT_BINARY}"

    if [[ -f "${binary}" ]]; then
        echo "Removing binary: ${binary}"
        sudo rm -f "${binary}"
    else
        echo "Binary not found: ${binary}"
    fi

    echo "Finished uninstalling ${CLIENT_BINARY}."
}

# ------------------------------------------------------------
# Tray
# ------------------------------------------------------------

uninstall_tray() {
    echo
    echo "==> Uninstalling ${TRAY_BINARY}"

    echo "Stopping ${TRAY_SERVICE}..."

    systemctl --user stop "${TRAY_SERVICE}" 2>/dev/null || true

    echo "Disabling ${TRAY_SERVICE}..."

    systemctl --user disable "${TRAY_SERVICE}" 2>/dev/null || true

    local service_file="${USER_SERVICE_DIR}/${TRAY_SERVICE}"

    if [[ -f "${service_file}" ]]; then
        echo "Removing service file: ${service_file}"
        rm -f "${service_file}"
    else
        echo "Tray service file not found: ${service_file}"
    fi

    systemctl --user daemon-reload 2>/dev/null || true

    local binary="${USER_BIN}/${TRAY_BINARY}"

    if [[ -f "${binary}" ]]; then
        echo "Removing binary: ${binary}"
        rm -f "${binary}"
    else
        echo "Tray binary not found: ${binary}"
    fi

    echo "Finished uninstalling ${TRAY_BINARY}."
}

# ------------------------------------------------------------
# All
# ------------------------------------------------------------

uninstall_all() {
    uninstall_tray
    uninstall_client
    uninstall_server
}

# ------------------------------------------------------------
# Main
# ------------------------------------------------------------

usage() {
    cat <<EOF
RVPN uninstall tool

Usage:
    ./uninstall.sh server
    ./uninstall.sh client
    ./uninstall.sh tray
    ./uninstall.sh all

Commands:
    server    Remove rvpn-server.service and rvpn-server.
    client    Remove all rvpn-client@<user>.service instances,
              the client service template, and rvpn-client.
    tray      Remove the current user's rvpn-tray.service and
              ~/.local/bin/rvpn-tray.
    all       Remove server, client, and tray.
EOF
}

case "${1:-}" in
    server)
        uninstall_server
        ;;

    client)
        uninstall_client
        ;;

    tray)
        uninstall_tray
        ;;

    all)
        uninstall_all
        ;;

    help|-h|--help)
        usage
        exit 0
        ;;

    "")
        echo "RVPN Uninstaller"
        echo
        echo "What do you want to uninstall?"
        echo
        echo "  1) Server"
        echo "  2) Client"
        echo "  3) Tray"
        echo "  4) Everything"
        echo
        read -r -p "Selection: " selection

        case "${selection}" in
            1) uninstall_server ;;
            2) uninstall_client ;;
            3) uninstall_tray ;;
            4) uninstall_all ;;
            *)
                echo "Invalid selection."
                exit 1
                ;;
        esac
        ;;

    *)
        usage
        exit 1
        ;;
esac

echo
echo "RVPN uninstall complete."
