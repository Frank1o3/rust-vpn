package org.rvpn.client

import android.content.Context

/**
 * Android client configuration data model and SharedPreferences persistence.
 */
data class RvpnConfig(
    val server: String = "",
    /** "psk", "pinned-key", or "certificate". */
    val authMode: String = "psk",
    val preSharedKey: String = "",
    /** Used by pinned-key and certificate modes: this device's own Ed25519 seed. */
    val localIdentitySeed: String = "",
    /** Used by pinned-key mode: the server's exact Ed25519 public key. */
    val peerPublicKey: String = "",
    /** Used by certificate mode: this device's cert, issued by the trusted CA. */
    val localCertificate: String = "",
    /** Used by certificate mode: the CA's public key. */
    val caPublicKey: String = "",
    val tunnelAddress: String = "10.42.0.2",
    val tunnelPrefixLength: Int = 24,
    val ipv6Enabled: Boolean = false,
    val tunnelAddressV6: String = "",
    val tunnelPrefixLengthV6: Int = 64,
    /** Comma- or newline-separated DNS servers, e.g. "1.1.1.1, 1.0.0.1". */
    val dnsServers: String = "1.1.1.1",
    val mtu: Int = 1400,
    val rekeyPacketLimit: Long = 1048576L,
    val retryIntervalMs: Long = 500L,
    val retryLimit: Int = 5,
    val excludedApps: Set<String> = emptySet(),
    /** Independent per-protocol default-route toggles. */
    val useDefaultRouteV4: Boolean = true,
    val useDefaultRouteV6: Boolean = true,
    /** Comma- or newline-separated CIDR prefixes, applied only when the
     *  matching default-route toggle above is off. */
    val splitTunnelRoutesV4: String = "",
    val splitTunnelRoutesV6: String = "",
    /** Verbatim text last pasted into the Config screen, so it can be
     *  re-displayed for editing without needing to re-derive it. */
    val rawClientToml: String = ""
) {
    companion object {
        private const val PREFS_NAME = "rvpn_prefs"
        private const val KEY_SERVER = "server"
        private const val KEY_AUTH_MODE = "auth_mode"
        private const val KEY_PSK = "psk"
        private const val KEY_LOCAL_IDENTITY_SEED = "local_identity_seed"
        private const val KEY_PEER_PUBLIC_KEY = "peer_public_key"
        private const val KEY_LOCAL_CERTIFICATE = "local_certificate"
        private const val KEY_CA_PUBLIC_KEY = "ca_public_key"
        private const val KEY_TUNNEL_ADDR = "tunnel_addr"
        private const val KEY_TUNNEL_PREFIX = "tunnel_prefix"
        private const val KEY_IPV6_ENABLED = "ipv6_enabled"
        private const val KEY_TUNNEL_ADDR_V6 = "tunnel_addr_v6"
        private const val KEY_TUNNEL_PREFIX_V6 = "tunnel_prefix_v6"
        private const val KEY_DNS = "dns_servers"
        private const val KEY_MTU = "mtu"
        private const val KEY_REKEY_LIMIT = "rekey_limit"
        private const val KEY_RETRY_INTERVAL = "retry_interval_ms"
        private const val KEY_RETRY_LIMIT = "retry_limit"
        private const val KEY_EXCLUDED_APPS = "excluded_apps"
        private const val KEY_USE_DEFAULT_ROUTE_V4 = "use_default_route_v4"
        private const val KEY_USE_DEFAULT_ROUTE_V6 = "use_default_route_v6"
        private const val KEY_SPLIT_ROUTES_V4 = "split_tunnel_routes_v4"
        private const val KEY_SPLIT_ROUTES_V6 = "split_tunnel_routes_v6"
        private const val KEY_RAW_CLIENT_TOML = "raw_client_toml"

        fun load(context: Context): RvpnConfig {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return RvpnConfig(
                server = prefs.getString(KEY_SERVER, "") ?: "",
                authMode = prefs.getString(KEY_AUTH_MODE, "psk") ?: "psk",
                preSharedKey = prefs.getString(KEY_PSK, "") ?: "",
                localIdentitySeed = prefs.getString(KEY_LOCAL_IDENTITY_SEED, "") ?: "",
                peerPublicKey = prefs.getString(KEY_PEER_PUBLIC_KEY, "") ?: "",
                localCertificate = prefs.getString(KEY_LOCAL_CERTIFICATE, "") ?: "",
                caPublicKey = prefs.getString(KEY_CA_PUBLIC_KEY, "") ?: "",
                tunnelAddress = prefs.getString(KEY_TUNNEL_ADDR, "10.42.0.2") ?: "10.42.0.2",
                tunnelPrefixLength = prefs.getInt(KEY_TUNNEL_PREFIX, 24),
                ipv6Enabled = prefs.getBoolean(KEY_IPV6_ENABLED, false),
                tunnelAddressV6 = prefs.getString(KEY_TUNNEL_ADDR_V6, "") ?: "",
                tunnelPrefixLengthV6 = prefs.getInt(KEY_TUNNEL_PREFIX_V6, 64),
                dnsServers = prefs.getString(KEY_DNS, "1.1.1.1") ?: "1.1.1.1",
                mtu = prefs.getInt(KEY_MTU, 1400),
                rekeyPacketLimit = prefs.getLong(KEY_REKEY_LIMIT, 1048576L),
                retryIntervalMs = prefs.getLong(KEY_RETRY_INTERVAL, 500L),
                retryLimit = prefs.getInt(KEY_RETRY_LIMIT, 5),
                excludedApps = prefs.getStringSet(KEY_EXCLUDED_APPS, emptySet()) ?: emptySet(),
                useDefaultRouteV4 = prefs.getBoolean(KEY_USE_DEFAULT_ROUTE_V4, true),
                useDefaultRouteV6 = prefs.getBoolean(KEY_USE_DEFAULT_ROUTE_V6, true),
                splitTunnelRoutesV4 = prefs.getString(KEY_SPLIT_ROUTES_V4, "") ?: "",
                splitTunnelRoutesV6 = prefs.getString(KEY_SPLIT_ROUTES_V6, "") ?: "",
                rawClientToml = prefs.getString(KEY_RAW_CLIENT_TOML, "") ?: ""
            )
        }

        fun save(context: Context, config: RvpnConfig) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_SERVER, config.server)
                .putString(KEY_AUTH_MODE, config.authMode)
                .putString(KEY_PSK, config.preSharedKey)
                .putString(KEY_LOCAL_IDENTITY_SEED, config.localIdentitySeed)
                .putString(KEY_PEER_PUBLIC_KEY, config.peerPublicKey)
                .putString(KEY_LOCAL_CERTIFICATE, config.localCertificate)
                .putString(KEY_CA_PUBLIC_KEY, config.caPublicKey)
                .putString(KEY_TUNNEL_ADDR, config.tunnelAddress)
                .putInt(KEY_TUNNEL_PREFIX, config.tunnelPrefixLength)
                .putBoolean(KEY_IPV6_ENABLED, config.ipv6Enabled)
                .putString(KEY_TUNNEL_ADDR_V6, config.tunnelAddressV6)
                .putInt(KEY_TUNNEL_PREFIX_V6, config.tunnelPrefixLengthV6)
                .putString(KEY_DNS, config.dnsServers)
                .putInt(KEY_MTU, config.mtu)
                .putLong(KEY_REKEY_LIMIT, config.rekeyPacketLimit)
                .putLong(KEY_RETRY_INTERVAL, config.retryIntervalMs)
                .putInt(KEY_RETRY_LIMIT, config.retryLimit)
                .putStringSet(KEY_EXCLUDED_APPS, config.excludedApps)
                .putBoolean(KEY_USE_DEFAULT_ROUTE_V4, config.useDefaultRouteV4)
                .putBoolean(KEY_USE_DEFAULT_ROUTE_V6, config.useDefaultRouteV6)
                .putString(KEY_SPLIT_ROUTES_V4, config.splitTunnelRoutesV4)
                .putString(KEY_SPLIT_ROUTES_V6, config.splitTunnelRoutesV6)
                .putString(KEY_RAW_CLIENT_TOML, config.rawClientToml)
                .apply()
        }
    }
}
