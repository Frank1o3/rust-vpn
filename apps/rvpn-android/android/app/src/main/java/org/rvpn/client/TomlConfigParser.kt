
package org.rvpn.client

/**
 * Minimal TOML reader for RVPN client.toml files.
 *
 * Supports:
 * - Flat key/value pairs
 * - [section] headers
 * - Quoted strings
 * - Quoted-string arrays
 * - Booleans
 * - Integers
 */
object TomlConfigParser {

    private val sectionRegex = Regex("""^\[([A-Za-z0-9_.]+)]$""")
    private val kvRegex = Regex("""^([A-Za-z0-9_]+)\s*=\s*(.+)$""")

    /** Parses text into a map of section name to key/value pairs. */
    fun parse(text: String): Map<String, Map<String, Any>> {
        val sections = LinkedHashMap<String, LinkedHashMap<String, Any>>()
        var current = LinkedHashMap<String, Any>()
        sections[""] = current

        for (rawLine in text.lines()) {
            val line = stripComment(rawLine).trim()
            if (line.isEmpty()) continue

            val sectionMatch = sectionRegex.find(line)
            if (sectionMatch != null) {
                val name = sectionMatch.groupValues[1]
                current = sections.getOrPut(name) { LinkedHashMap() }
                continue
            }

            val kv = kvRegex.find(line) ?: continue
            val key = kv.groupValues[1]
            current[key] = parseValue(kv.groupValues[2].trim())
        }

        return sections
    }

    /** Parses client.toml and layers values over base configuration. */
    fun toRvpnConfig(text: String, base: RvpnConfig): RvpnConfig {
        val sections = parse(text)

        val root = sections[""] ?: emptyMap()
        val iface = sections["interface"] ?: emptyMap()
        val routing = sections["routing"] ?: emptyMap()
        val auth = sections["auth"] ?: emptyMap()
        val handshake = sections["handshake"] ?: emptyMap()
        val rekey = sections["rekey"] ?: emptyMap()

        val addresses = stringList(iface, "addresses")

        val v4Address =
            stringValue(iface, "address")?.takeIf { !it.contains(":") }
                ?: addresses.firstOrNull { !it.contains(":") }

        val v6Address =
            stringValue(iface, "address")?.takeIf { it.contains(":") }
                ?: addresses.firstOrNull { it.contains(":") }

        val (v4Ip, v4Prefix) =
            splitCidr(v4Address)
                ?: (base.tunnelAddress to base.tunnelPrefixLength)

        val (v6Ip, v6Prefix) =
            splitCidr(v6Address)
                ?: ("" to base.tunnelPrefixLengthV6)

        val routes = stringList(routing, "routes")

        val routesV4 = routes
            .filter { !it.contains(":") }
            .joinToString(", ")

        val routesV6 = routes
            .filter { it.contains(":") }
            .joinToString(", ")

        return base.copy(
            server = stringValue(root, "server") ?: base.server,

            // FIX: Load the obfuscation key from client.toml.
            obfuscationKey =
                stringValue(root, "obfuscation_key")
                    ?: base.obfuscationKey,

            authMode = stringValue(auth, "mode") ?: base.authMode,

            preSharedKey =
                stringValue(auth, "pre_shared_key")
                    ?: stringValue(root, "pre_shared_key")
                    ?: base.preSharedKey,

            localIdentitySeed =
                stringValue(auth, "local_identity_seed")
                    ?: base.localIdentitySeed,

            peerPublicKey =
                stringValue(auth, "peer_public_key")
                    ?: base.peerPublicKey,

            localCertificate =
                stringValue(auth, "local_certificate")
                    ?: base.localCertificate,

            caPublicKey =
                stringValue(auth, "ca_public_key")
                    ?: base.caPublicKey,

            tunnelAddress = v4Ip,
            tunnelPrefixLength = v4Prefix,

            ipv6Enabled = v6Address != null,
            tunnelAddressV6 = v6Ip,
            tunnelPrefixLengthV6 = v6Prefix,

            dnsServers =
                stringValue(root, "dns_servers")
                    ?: stringValue(iface, "dns_servers")
                    ?: base.dnsServers,

            mtu = longValue(iface, "mtu")?.toInt() ?: base.mtu,

            rekeyPacketLimit =
                longValue(rekey, "packet_limit")
                    ?: base.rekeyPacketLimit,

            retryIntervalMs =
                longValue(handshake, "retry_interval_ms")
                    ?: base.retryIntervalMs,

            retryLimit =
                longValue(handshake, "retry_limit")?.toInt()
                    ?: base.retryLimit,

            useDefaultRouteV4 =
                boolValue(routing, "default_route")
                    ?: base.useDefaultRouteV4,

            useDefaultRouteV6 =
                boolValue(routing, "default_route_v6")
                    ?: base.useDefaultRouteV6,

            splitTunnelRoutesV4 = routesV4,
            splitTunnelRoutesV6 = routesV6,

            rawClientToml = text
        )
    }

    private fun splitCidr(value: String?): Pair<String, Int>? {
        if (value.isNullOrBlank()) return null

        val parts = value.split("/", limit = 2)
        val ip = parts[0]

        val prefix = parts.getOrNull(1)?.toIntOrNull()
            ?: if (ipLooksV6(ip)) 64 else 24

        return ip to prefix
    }

    private fun ipLooksV6(value: String): Boolean =
        value.contains(":")

    private fun stringValue(
        map: Map<String, Any>,
        key: String
    ): String? = map[key] as? String

    private fun boolValue(
        map: Map<String, Any>,
        key: String
    ): Boolean? = map[key] as? Boolean

    private fun longValue(
        map: Map<String, Any>,
        key: String
    ): Long? = when (val value = map[key]) {
        is Long -> value
        is Int -> value.toLong()
        else -> null
    }

    private fun stringList(
        map: Map<String, Any>,
        key: String
    ): List<String> = (map[key] as? List<*>)
        ?.filterIsInstance<String>()
        ?: emptyList()

    private fun stripComment(line: String): String {
        var inQuotes = false

        for (i in line.indices) {
            val c = line[i]

            if (c == '"') {
                inQuotes = !inQuotes
            }

            if (c == '#' && !inQuotes) {
                return line.substring(0, i)
            }
        }

        return line
    }

    private fun parseValue(raw: String): Any {
        val value = raw.trim()

        return when {
            value == "true" -> true
            value == "false" -> false

            value.startsWith("\"") &&
                value.endsWith("\"") &&
                value.length >= 2 ->
                value.substring(1, value.length - 1)

            value.startsWith("[") &&
                value.endsWith("]") ->
                value.substring(1, value.length - 1)
                    .split(",")
                    .map { it.trim().trim('"') }
                    .filter { it.isNotEmpty() }

            value.toLongOrNull() != null ->
                value.toLong()

            else ->
                value.trim('"')
        }
    }
}