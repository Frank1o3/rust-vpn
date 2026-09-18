#!/usr/bin/env bash

set -u

SERVER_SERVICE="rvpn-server.service"
CLIENT_SERVICE="rvpn-client.service"

SERVER_BINARY="rvpn-server"
CLIENT_BINARY="rvpn-client"
TRAY_BINARY="rvpn-tray"

USER_BIN="$HOME/.local/bin"

SERVICE_PATHS=(
    "/etc/systemd/system"
    "/usr/lib/systemd/system"
    "/lib/systemd/system"
)

BINARY_PATHS=(
    "/usr/local/bin"
    "/usr/bin"
)

usage() {
    echo "Usage: $0 {server|client|tray|all}"
    echo
    echo "  server  Uninstall RVPN server and its systemd service"
    echo "  client  Uninstall RVPN client and its systemd service"
    echo "  tray    Uninstall RVPN tray application"
    echo "  all     Uninstall server, client, and tray"
    exit 1
}

require_sudo() {
    if ! sudo -v; then
        echo "Failed to obtain sudo privileges."
        exit 1
    fi
}

find_service_file() {
    local service="$1"

    for dir in "${SERVICE_PATHS[@]}"; do
        if [[ -f "$dir/$service" ]]; then
            echo "$dir/$service"
            return 0
        fi
    done

    return 1
}

find_binary() {
    local binary="$1"

    for dir in "${BINARY_PATHS[@]}"; do
        if [[ -f "$dir/$binary" ]]; then
            echo "$dir/$binary"
            return 0
        fi
    done

    return 1
}

uninstall_service() {
    local service="$1"
    local binary="$2"

    echo
    echo "==> Uninstalling $binary"

    require_sudo

    # Stop and disable the service if it exists.
    if sudo systemctl list-unit-files --all | grep -q "^${service}"; then
        echo "Stopping $service..."
        sudo systemctl stop "$service" 2>/dev/null || true

        echo "Disabling $service..."
        sudo systemctl disable "$service" 2>/dev/null || true
    else
        echo "Service $service is not installed."
    fi

    # Locate and remove the service file.
    local service_file
    if service_file="$(find_service_file "$service")"; then
        echo "Removing service file: $service_file"
        sudo rm -f "$service_file"
    else
        echo "Service file not found."
    fi

    # Reload systemd after removing the unit.
    sudo systemctl daemon-reload

    # Locate and remove the binary.
    local binary_path
    if binary_path="$(find_binary "$binary")"; then
        echo "Removing binary: $binary_path"
        sudo rm -f "$binary_path"
    else
        echo "Binary $binary not found in system paths."
    fi

    echo "Finished uninstalling $binary."
}

uninstall_tray() {
    echo
    echo "==> Uninstalling $TRAY_BINARY"

    local tray_path="$USER_BIN/$TRAY_BINARY"

    if [[ -f "$tray_path" ]]; then
        echo "Removing tray binary: $tray_path"
        rm -f "$tray_path"
    else
        echo "Tray binary not found: $tray_path"
    fi

    echo "Finished uninstalling $TRAY_BINARY."
}

uninstall_all() {
    uninstall_service "$SERVER_SERVICE" "$SERVER_BINARY"
    uninstall_service "$CLIENT_SERVICE" "$CLIENT_BINARY"
    uninstall_tray
}

if [[ $# -ge 1 ]]; then
    choice="$1"
else
    echo "RVPN Uninstaller"
    echo
    echo "What do you want to uninstall?"
    echo
    echo "  1) Server"
    echo "  2) Client"
    echo "  3) Tray"
    echo "  4) Everything"
    echo
    read -rp "Selection: " selection

    case "$selection" in
        1) choice="server" ;;
        2) choice="client" ;;
        3) choice="tray" ;;
        4) choice="all" ;;
        *)
            echo "Invalid selection."
            exit 1
            ;;
    esac
fi

case "$choice" in
    server)
        uninstall_service "$SERVER_SERVICE" "$SERVER_BINARY"
        ;;
    client)
        uninstall_service "$CLIENT_SERVICE" "$CLIENT_BINARY"
        ;;
    tray)
        uninstall_tray
        ;;
    all)
        uninstall_all
        ;;
    *)
        usage
        ;;
esac

echo
echo "RVPN uninstall complete."