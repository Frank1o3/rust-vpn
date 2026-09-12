package org.rvpn.client

import android.content.Context
import java.security.SecureRandom

/**
 * Android client configuration data model and SharedPreferences persistence.
 */
data class RvpnConfig(
    val server: String = "10.0.0.1:9000",
    val preSharedKey: String = "",
    val tunnelAddress: String = "10.42.0.2",
    val tunnelPrefixLength: Int = 24,
    val tunnelAddressV6: String = "",
    val tunnelPrefixLengthV6: Int = 64,
    val dnsServer: String = "1.1.1.1",
    val mtu: Int = 1400,
    val rekeyPacketLimit: Long = 1048576L,
    val retryIntervalMs: Long = 500L,
    val retryLimit: Int = 5,
    val excludedApps: Set<String> = emptySet(),
    /** When false, only [splitTunnelRoutes] are routed through the tunnel. */
    val useDefaultRoute: Boolean = true,
    /** Comma- or newline-separated CIDR prefixes, e.g. "10.0.0.0/8,192.168.1.0/24". */
    val splitTunnelRoutes: String = ""
) {
    companion object {
        private const val PREFS_NAME = "rvpn_prefs"
        private const val KEY_SERVER = "server"
        private const val KEY_PSK = "psk"
        private const val KEY_TUNNEL_ADDR = "tunnel_addr"
        private const val KEY_TUNNEL_PREFIX = "tunnel_prefix"
        private const val KEY_TUNNEL_ADDR_V6 = "tunnel_addr_v6"
        private const val KEY_TUNNEL_PREFIX_V6 = "tunnel_prefix_v6"
        private const val KEY_DNS = "dns"
        private const val KEY_MTU = "mtu"
        private const val KEY_REKEY_LIMIT = "rekey_limit"
        private const val KEY_RETRY_INTERVAL = "retry_interval_ms"
        private const val KEY_RETRY_LIMIT = "retry_limit"
        private const val KEY_EXCLUDED_APPS = "excluded_apps"
        private const val KEY_USE_DEFAULT_ROUTE = "use_default_route"
        private const val KEY_SPLIT_ROUTES = "split_tunnel_routes"

        fun load(context: Context): RvpnConfig {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            return RvpnConfig(
                server = prefs.getString(KEY_SERVER, "10.0.0.1:9000") ?: "10.0.0.1:9000",
                preSharedKey = prefs.getString(KEY_PSK, "") ?: "",
                tunnelAddress = prefs.getString(KEY_TUNNEL_ADDR, "10.42.0.2") ?: "10.42.0.2",
                tunnelPrefixLength = prefs.getInt(KEY_TUNNEL_PREFIX, 24),
                tunnelAddressV6 = prefs.getString(KEY_TUNNEL_ADDR_V6, "") ?: "",
                tunnelPrefixLengthV6 = prefs.getInt(KEY_TUNNEL_PREFIX_V6, 64),
                dnsServer = prefs.getString(KEY_DNS, "1.1.1.1") ?: "1.1.1.1",
                mtu = prefs.getInt(KEY_MTU, 1400),
                rekeyPacketLimit = prefs.getLong(KEY_REKEY_LIMIT, 1048576L),
                retryIntervalMs = prefs.getLong(KEY_RETRY_INTERVAL, 500L),
                retryLimit = prefs.getInt(KEY_RETRY_LIMIT, 5),
                excludedApps = prefs.getStringSet(KEY_EXCLUDED_APPS, emptySet()) ?: emptySet(),
                useDefaultRoute = prefs.getBoolean(KEY_USE_DEFAULT_ROUTE, true),
                splitTunnelRoutes = prefs.getString(KEY_SPLIT_ROUTES, "") ?: ""
            )
        }

        fun save(context: Context, config: RvpnConfig) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_SERVER, config.server)
                .putString(KEY_PSK, config.preSharedKey)
                .putString(KEY_TUNNEL_ADDR, config.tunnelAddress)
                .putInt(KEY_TUNNEL_PREFIX, config.tunnelPrefixLength)
                .putString(KEY_TUNNEL_ADDR_V6, config.tunnelAddressV6)
                .putInt(KEY_TUNNEL_PREFIX_V6, config.tunnelPrefixLengthV6)
                .putString(KEY_DNS, config.dnsServer)
                .putInt(KEY_MTU, config.mtu)
                .putLong(KEY_REKEY_LIMIT, config.rekeyPacketLimit)
                .putLong(KEY_RETRY_INTERVAL, config.retryIntervalMs)
                .putInt(KEY_RETRY_LIMIT, config.retryLimit)
                .putStringSet(KEY_EXCLUDED_APPS, config.excludedApps)
                .putBoolean(KEY_USE_DEFAULT_ROUTE, config.useDefaultRoute)
                .putString(KEY_SPLIT_ROUTES, config.splitTunnelRoutes)
                .apply()
        }

        /**
         * Generates a cryptographically secure 256-bit (32-byte) hex-encoded pre-shared key.
         */
        fun generateRandomPsk(): String {
            val random = SecureRandom()
            val bytes = ByteArray(32)
            random.nextBytes(bytes)
            return bytes.joinToString("") { "%02x".format(it) }
        }
    }
}