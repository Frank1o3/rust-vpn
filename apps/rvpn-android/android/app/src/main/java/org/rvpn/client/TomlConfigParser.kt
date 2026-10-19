package org.rvpn.client

import com.akuleshov7.ktoml.Toml
import com.akuleshov7.ktoml.TomlInputConfig
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable

/**
 * Sections of an RVPN client.toml, as documented in docs/configuration.md.
 * Every field is optional so a partial or legacy config still decodes; we
 * layer whatever is present over the caller's existing [RvpnConfig].
 */
@Serializable
private data class TomlInterfaceSection(
    val name: String? = null,
    @SerialName("tap_name") val tapName: String? = null,
    val mtu: Long? = null,
    val mode: String? = null,
    val address: String? = null,
    val addresses: List<String> = emptyList(),
    @SerialName("dns_servers") val dnsServers: String? = null,
)

@Serializable
private data class TomlRoutingSection(
    @SerialName("default_route") val defaultRoute: Boolean? = null,
    val gateway: String? = null,
    @SerialName("default_route_v6") val defaultRouteV6: Boolean? = null,
    @SerialName("gateway_v6") val gatewayV6: String? = null,
    val routes: List<String> = emptyList(),
)

@Serializable
private data class TomlAuthSection(
    val mode: String? = null,
    @SerialName("pre_shared_key") val preSharedKey: String? = null,
    @SerialName("local_identity_seed") val localIdentitySeed: String? = null,
    @SerialName("peer_public_key") val peerPublicKey: String? = null,
    @SerialName("local_certificate") val localCertificate: String? = null,
    @SerialName("ca_public_key") val caPublicKey: String? = null,
)

@Serializable
private data class TomlHandshakeSection(
    @SerialName("retry_interval_ms") val retryIntervalMs: Long? = null,
    @SerialName("retry_limit") val retryLimit: Long? = null,
)

@Serializable
private data class TomlRekeySection(
    @SerialName("packet_limit") val packetLimit: Long? = null,
)

@Serializable
private data class RvpnClientToml(
    val server: String? = null,
    @SerialName("dns_replace") val dnsReplace: Boolean? = null,
    @SerialName("obfuscation_key") val obfuscationKey: String? = null,
    @SerialName("pre_shared_key") val preSharedKey: String? = null,
    @SerialName("interface") val iface: TomlInterfaceSection = TomlInterfaceSection(),
    val routing: TomlRoutingSection = TomlRoutingSection(),
    val auth: TomlAuthSection = TomlAuthSection(),
    val handshake: TomlHandshakeSection = TomlHandshakeSection(),
    val rekey: TomlRekeySection = TomlRekeySection(),
)

/**
 * Parses RVPN `client.toml` text using ktoml (a real TOML implementation)
 * instead of a hand-rolled line parser, and layers the result over a base
 * [RvpnConfig].
 */
object TomlConfigParser {

    // ignoreUnknownNames: tolerate sections/keys this app doesn't model yet
    // (e.g. [liveness]) instead of failing the whole parse.
    private val toml = Toml(inputConfig = TomlInputConfig(ignoreUnknownNames = true))

    /** Parses client.toml and layers values over base configuration. */
    fun toRvpnConfig(text: String, base: RvpnConfig): RvpnConfig {
        val parsed: RvpnClientToml = toml.decodeFromString(RvpnClientToml.serializer(), text)

        val iface = parsed.iface
        val addresses = iface.addresses

        val v4Address =
            iface.address?.takeIf { !it.contains(":") }
                ?: addresses.firstOrNull { !it.contains(":") }

        val v6Address =
            iface.address?.takeIf { it.contains(":") }
                ?: addresses.firstOrNull { it.contains(":") }

        val (v4Ip, v4Prefix) =
            splitCidr(v4Address)
                ?: (base.tunnelAddress to base.tunnelPrefixLength)

        val (v6Ip, v6Prefix) =
            splitCidr(v6Address)
                ?: ("" to base.tunnelPrefixLengthV6)

        val routes = parsed.routing.routes

        val routesV4 = routes.filter { !it.contains(":") }.joinToString(", ")
        val routesV6 = routes.filter { it.contains(":") }.joinToString(", ")

        return base.copy(
            server = parsed.server ?: base.server,
            dnsReplace = parsed.dnsReplace ?: base.dnsReplace,

            obfuscationKey = parsed.obfuscationKey ?: base.obfuscationKey,

            authMode = parsed.auth.mode ?: base.authMode,

            preSharedKey =
                parsed.auth.preSharedKey
                    ?: parsed.preSharedKey
                    ?: base.preSharedKey,

            localIdentitySeed = parsed.auth.localIdentitySeed ?: base.localIdentitySeed,
            peerPublicKey = parsed.auth.peerPublicKey ?: base.peerPublicKey,
            localCertificate = parsed.auth.localCertificate ?: base.localCertificate,
            caPublicKey = parsed.auth.caPublicKey ?: base.caPublicKey,

            tunnelAddress = v4Ip,
            tunnelPrefixLength = v4Prefix,

            ipv6Enabled = v6Address != null,
            tunnelAddressV6 = v6Ip,
            tunnelPrefixLengthV6 = v6Prefix,

            dnsServers = iface.dnsServers ?: base.dnsServers,

            mtu = iface.mtu?.toInt() ?: base.mtu,

            rekeyPacketLimit = parsed.rekey.packetLimit ?: base.rekeyPacketLimit,

            retryIntervalMs = parsed.handshake.retryIntervalMs ?: base.retryIntervalMs,
            retryLimit = parsed.handshake.retryLimit?.toInt() ?: base.retryLimit,

            useDefaultRouteV4 = parsed.routing.defaultRoute ?: base.useDefaultRouteV4,
            useDefaultRouteV6 = parsed.routing.defaultRouteV6 ?: base.useDefaultRouteV6,

            splitTunnelRoutesV4 = routesV4,
            splitTunnelRoutesV6 = routesV6,

            rawClientToml = text,
        )
    }

    /** Renders a structured form config as readable, indented client TOML. */
    fun fromRvpnConfig(config: RvpnConfig): String = buildString {
        fun quoted(value: String) = buildString {
            append('"')
            value.forEach { character ->
                when (character) {
                    '\\' -> append("\\\\")
                    '"' -> append("\\\"")
                    '\b' -> append("\\b")
                    '\t' -> append("\\t")
                    '\n' -> append("\\n")
                    '\u000C' -> append("\\f")
                    '\r' -> append("\\r")
                    else -> if (character.code < 0x20) {
                        append("\\u%04x".format(character.code))
                    } else {
                        append(character)
                    }
                }
            }
            append('"')
        }
        append("server = ").append(quoted(config.server)).append("\n")
        append("dns_replace = ").append(config.dnsReplace).append("\n")
        if (config.obfuscationKey.isNotBlank()) append("obfuscation_key = ").append(quoted(config.obfuscationKey)).append("\n")
        append("\n[interface]\n")
        append("    address = ").append(quoted("${config.tunnelAddress}/${config.tunnelPrefixLength}")).append("\n")
        append("    mode = \"tun\"\n")
        append("    mtu = ").append(config.mtu).append("\n")
        if (config.ipv6Enabled && config.tunnelAddressV6.isNotBlank()) {
            append("    addresses = [").append(quoted("${config.tunnelAddressV6}/${config.tunnelPrefixLengthV6}")).append("]\n")
        }
        if (config.dnsServers.isNotBlank()) append("    dns_servers = ").append(quoted(config.dnsServers)).append("\n")
        append("\n[routing]\n")
        append("    default_route = ").append(config.useDefaultRouteV4).append("\n")
        append("    default_route_v6 = ").append(config.useDefaultRouteV6).append("\n")
        val routes = (config.splitTunnelRoutesV4.split(',', '\n') + config.splitTunnelRoutesV6.split(',', '\n'))
            .map(String::trim).filter(String::isNotEmpty)
        if (routes.isNotEmpty()) append("    routes = [").append(routes.joinToString(", ") { quoted(it) }).append("]\n")
        append("\n[auth]\n")
        append("    mode = ").append(quoted(config.authMode)).append("\n")
        when (config.authMode) {
            "psk" -> append("    pre_shared_key = ").append(quoted(config.preSharedKey)).append("\n")
            "pinned-key" -> {
                append("    local_identity_seed = ").append(quoted(config.localIdentitySeed)).append("\n")
                append("    peer_public_key = ").append(quoted(config.peerPublicKey)).append("\n")
            }
            "certificate" -> {
                append("    local_identity_seed = ").append(quoted(config.localIdentitySeed)).append("\n")
                append("    local_certificate = ").append(quoted(config.localCertificate)).append("\n")
                append("    ca_public_key = ").append(quoted(config.caPublicKey)).append("\n")
            }
        }
        append("\n[handshake]\n")
        append("    retry_interval_ms = ").append(config.retryIntervalMs).append("\n")
        append("    retry_limit = ").append(config.retryLimit).append("\n")
        append("\n[rekey]\n")
        append("    packet_limit = ").append(config.rekeyPacketLimit).append("\n")
    }

    private fun splitCidr(value: String?): Pair<String, Int>? {
        if (value.isNullOrBlank()) return null
        val parts = value.split("/", limit = 2)
        val ip = parts[0]
        val prefix = parts.getOrNull(1)?.toIntOrNull() ?: if (ip.contains(":")) 64 else 24
        return ip to prefix
    }

    /** Updates the top-level server value without reformatting imported TOML. */
    fun replaceServer(text: String, server: String): String {
        val replacement = "server = \"${server.replace("\\", "\\\\").replace("\"", "\\\"")}\""
        val lines = text.lines().toMutableList()
        var inSection = false
        var index = -1
        for (lineIndex in lines.indices) {
            val trimmed = lines[lineIndex].trimStart()
            if (trimmed.startsWith("[")) inSection = true
            if (!inSection && trimmed.substringBefore('=').trim() == "server") {
                index = lineIndex
                break
            }
        }
        if (index >= 0) {
            lines[index] = replacement
        } else {
            lines.add(0, replacement)
        }
        return lines.joinToString("\n")
    }
}
