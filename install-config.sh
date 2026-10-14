#!/usr/bin/env bash
set -Eeuo pipefail

# Securely install an RVPN server or client TOML config.
# Usage (run as root through sudo):
#   sudo bash ./install-config.sh server path/to/server.toml
#   sudo bash ./install-config.sh client path/to/client.toml
# Client mode uses SUDO_USER so it does not accidentally write into /root.

readonly SERVER_DIR='/var/lib/rvpn/.config/rvpn'
readonly SERVER_PATH="${SERVER_DIR}/server.toml"
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
    printf 'install-config.sh: error: %s\n' "$*" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || die 'run this helper through sudo.'

if [[ "${1:-}" == '-h' || "${1:-}" == '--help' || "${1:-}" == 'help' ]]; then
    usage
    exit 0
fi

[[ "$#" -eq 2 ]] || { usage >&2; exit 2; }
mode="$1"
source_path="$2"
[[ -f "$source_path" ]] || die "source is not a regular file: $source_path"

case "$mode" in
    server)
        getent passwd rvpn >/dev/null || die "the rvpn service account is missing; install the server service first with ./build.sh server."
        getent group "$RVPN_GROUP" >/dev/null || die "the rvpn group is missing; install the server service first with ./build.sh server."
        destination_dir="$SERVER_DIR"
        destination_path="$SERVER_PATH"
        destination_owner='rvpn'
        ;;
    client)
        [[ -n "${SUDO_USER:-}" && "$SUDO_USER" != 'root' ]] || die 'run client mode through sudo from the user who should own the config.'
        getent group "$RVPN_GROUP" >/dev/null 2>&1 || groupadd --system "$RVPN_GROUP" || die "could not create group $RVPN_GROUP."
        destination_owner="$SUDO_USER"
        client_home="$(getent passwd "$destination_owner" | cut -d: -f6)"
        [[ -n "$client_home" && -d "$client_home" ]] || die "could not find a valid home directory for $destination_owner."
        destination_dir="${client_home}/.config/rvpn"
        destination_path="${destination_dir}/client.toml"
        ;;
    *)
        usage >&2
        die "unknown target '$mode'; expected server or client."
        ;;
esac

# RVPN rejects configs with any group/world permission bits, so use 0600.
# The server must own its config to read it as the unprivileged rvpn service.
if [[ -d "$destination_path" && ! -L "$destination_path" ]]; then
    die "destination exists as a directory: $destination_path"
fi
install -d -o "$destination_owner" -g "$RVPN_GROUP" -m 0700 -- "$destination_dir"
temp_path="$(mktemp --tmpdir="$destination_dir" '.rvpn-config.tmp.XXXXXX')"
cleanup() {
    if [[ -n "${temp_path:-}" && -e "$temp_path" ]]; then
        rm -f -- "$temp_path"
    fi
}
trap cleanup EXIT

install -o "$destination_owner" -g "$RVPN_GROUP" -m 0600 -- "$source_path" "$temp_path"
chown -- "${destination_owner}:${RVPN_GROUP}" "$temp_path"
chmod 0600 -- "$temp_path"
mv -fT -- "$temp_path" "$destination_path"
temp_path=''
trap - EXIT

printf 'Installed: %s\nOwner/group: %s:%s\nPermissions: 0600\n' \
    "$destination_path" "$destination_owner" "$RVPN_GROUP"
