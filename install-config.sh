#!/usr/bin/env bash
set -Eeuo pipefail

# Securely install an RVPN server or client TOML config.
# Usage (run through sudo):
#   sudo bash ./install-config.sh server path/to/server.toml
#   sudo bash ./install-config.sh client path/to/client.toml
# Client mode uses SUDO_USER so it does not accidentally write into /root.

readonly SERVER_DIR='/var/lib/rvpn/.config/rvpn'
readonly SERVER_PATH='/var/lib/rvpn/.config/rvpn/server.toml'
readonly RVPN_GROUP='rvpn'

usage() {
    cat <<'USAGE'
RVPN config installer

Usage:
  sudo bash ./install-config.sh server <source-file>
  sudo bash ./install-config.sh client <source-file>

Server target: /var/lib/rvpn/.config/rvpn/server.toml
Client target: <invoking user's home>/.config/rvpn/client.toml
Both files are installed with mode 0600 and group rvpn.
USAGE
}

die() {
    echo "install-config.sh: error: $*" >&2
    exit 1
}

if [[ "$EUID" -ne 0 ]]; then
    die 'run this helper through sudo.'
fi

if [[ "$#" -eq 1 ]]; then
    case "$1" in
        -h|--help|help) usage; exit 0 ;;
    esac
fi

[[ "$#" -eq 2 ]] || { usage >&2; exit 2; }
mode="$1"
source_path="$2"
[[ -f "$source_path" ]] || die "source is not a regular file: $source_path"

case "$mode" in
    server)
        getent passwd rvpn >/dev/null || die 'the rvpn service account is missing; install the server service first with ./build.sh server.'
        getent group "$RVPN_GROUP" >/dev/null || die 'the rvpn group is missing; install the server service first with ./build.sh server.'
        destination_dir="$SERVER_DIR"
        destination_path="$SERVER_PATH"
        destination_owner='rvpn'
        ;;
    client)
        [[ -v SUDO_USER ]] || die 'run client mode through sudo from the user who should own the config.'
        [[ -n "$SUDO_USER" && "$SUDO_USER" != 'root' ]] || die 'SUDO_USER does not identify a regular user.'
        if ! getent group "$RVPN_GROUP" >/dev/null 2>&1; then
            groupadd --system "$RVPN_GROUP" || die "could not create group $RVPN_GROUP."
        fi
        destination_owner="$SUDO_USER"
        passwd_entry="$(getent passwd "$destination_owner" || true)"
        [[ -n "$passwd_entry" ]] || die "could not find user $destination_owner."
        client_home="$(printf '%s\n' "$passwd_entry" | cut -d: -f6)"
        [[ -n "$client_home" && -d "$client_home" ]] || die "could not find a valid home directory for $destination_owner."
        destination_dir="$client_home/.config/rvpn"
        destination_path="$destination_dir/client.toml"
        ;;
    *)
        usage >&2
        die "unknown target '$mode'; expected server or client."
        ;;
esac

# RVPN rejects group/world permission bits, so use 0600. The server config
# belongs to the unprivileged rvpn service account so the service can read it.
if [[ -d "$destination_path" && ! -L "$destination_path" ]]; then
    die "destination exists as a directory: $destination_path"
fi
install -d -o "$destination_owner" -g "$RVPN_GROUP" -m 0700 -- "$destination_dir"

# Stage beside the destination, then rename to replace an existing config
# atomically rather than leaving a partially copied file if interrupted.
temp_path="$(mktemp --tmpdir="$destination_dir" .rvpn-config.tmp.XXXXXX)"
cleanup() {
    if [[ -n "$temp_path" && -e "$temp_path" ]]; then
        rm -f -- "$temp_path"
    fi
}
trap cleanup EXIT

install -o "$destination_owner" -g "$RVPN_GROUP" -m 0600 -- "$source_path" "$temp_path"
chown -- "$destination_owner:$RVPN_GROUP" "$temp_path"
chmod 0600 -- "$temp_path"
mv -fT -- "$temp_path" "$destination_path"
temp_path=''
trap - EXIT

echo "Installed: $destination_path"
echo "Owner/group: $destination_owner:$RVPN_GROUP"
echo 'Permissions: 0600'
