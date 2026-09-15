package org.rvpn.client

/**
 * A minimal TOML reader tailored to the shape of RVPN's client.toml files:
 * flat `key = value` pairs, `[section]` headers (one level deep), quoted
 * strings, quoted-string arrays, booleans, and integers. This is not a
 * general-purpose TOML parser -- it only needs to understand what
 * `scripts/generate_rvpn_setup.py` and the Rust `rvpn-config` crate emit.
 */
object TomlConfigParser {

    private val sectionRegex = Regex("""^\[([A-Za-z0-9_.]+)]$""")
    private val kvRegex = Regex("""^([A-Za-z0-9_]+)\s*=\s*(.+)$""")

    /** Parses `text` into a map of section name ("" for the root) to its key/value pairs. */
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

    /** Parses pasted client.toml `text`, layering parsed values over `base`. */
    @Suppress("UNCHECKED_CAST")
    fun toRvpnConfig(text: String, base: RvpnConfig): RvpnConfig {
        val sections = parse(text)
        val root = sections[""] ?: emptyMap()
        val iface = sections["interface"] ?: emptyMap()
        val routing = sections["routing"] ?: emptyMap()
        val auth = sections["auth"] ?: emptyMap()
        val handshake = sections["handshake"] ?: emptyMap()
        val rekey = sections["rekey"] ?: emptyMap()

        val addresses = list(iface, "addresses")
        val v4Address = (str(iface, "address")?.takeIf { !it.contains(":") })
            ?: addresses.firstOrNull { !it.contains(":") }
        val v6Address = (str(iface, "address")?.takeIf { it.contains(":") })
            ?: addresses.firstOrNull { it.contains(":") }

        val (v4Ip, v4Prefix) = splitCidr(v4Address) ?: (base.tunnelAddress to base.tunnelPrefixLength)
        val (v6Ip, v6Prefix) = splitCidr(v6Address) ?: ("" to base.tunnelPrefixLengthV6)

        val routes = list(routing, "routes")
        val routesV4 = routes.filter { !it.contains(":") }.joinToString(", ")
        val routesV6 = routes.filter { it.contains(":") }.joinToString(", ")

        return base.copy(
            server = str(root, "server") ?: base.server,
            authMode = str(auth, "mode") ?: base.authMode,
            preSharedKey = str(auth, "pre_shared_key") ?: str(root, "pre_shared_key") ?: "",
            localIdentitySeed = str(auth, "local_identity_seed") ?: "",
            peerPublicKey = str(auth, "peer_public_key") ?: "",
            localCertificate = str(auth, "local_certificate") ?: "",
            caPublicKey = str(auth, "ca_public_key") ?: "",
            tunnelAddress = v4Ip,
            tunnelPrefixLength = v4Prefix,
            ipv6Enabled = v6Address != null,
            tunnelAddressV6 = v6Ip,
            tunnelPrefixLengthV6 = v6Prefix,
            dnsServers = str(root, "dns_servers") ?: str(iface, "dns_servers") ?: base.dnsServers,
            mtu = long(iface, "mtu")?.toInt() ?: base.mtu,
            rekeyPacketLimit = long(rekey, "packet_limit") ?: base.rekeyPacketLimit,
            retryIntervalMs = long(handshake, "retry_interval_ms") ?: base.retryIntervalMs,
            retryLimit = long(handshake, "retry_limit")?.toInt() ?: base.retryLimit,
            useDefaultRouteV4 = bool(routing, "default_route") ?: base.useDefaultRouteV4,
            useDefaultRouteV6 = bool(routing, "default_route_v6") ?: base.useDefaultRouteV6,
            splitTunnelRoutesV4 = routesV4,
            splitTunnelRoutesV6 = routesV6,
            rawClientToml = text
        )
    }

    private fun splitCidr(value: String?): Pair<String, Int>? {
        if (value.isNullOrBlank()) return null
        val (ip, prefix) = value.split("/", limit = 2).let {
            it[0] to (it.getOrNull(1)?.toIntOrNull() ?: if (ip_looks_v6(it[0])) 64 else 24)
        }
        return ip to prefix
    }

    private fun ip_looks_v6(value: String) = value.contains(":")

    private fun str(map: Map<String, Any>, key: String): String? = map[key] as? String
    private fun bool(map: Map<String, Any>, key: String): Boolean? = map[key] as? Boolean
    private fun long(map: Map<String, Any>, key: String): Long? = map[key] as? Long
    @Suppress("UNCHECKED_CAST")
    private fun list(map: Map<String, Any>, key: String): List<String> =
        (map[key] as? List<String>) ?: emptyList()

    private fun stripComment(line: String): String {
        var inQuotes = false
        for (i in line.indices) {
            val c = line[i]
            if (c == '"') inQuotes = !inQuotes
            if (c == '#' && !inQuotes) return line.substring(0, i)
        }
        return line
    }

    private fun parseValue(raw: String): Any {
        val v = raw.trim()
        return when {
            v == "true" -> true
            v == "false" -> false
            v.startsWith("\"") && v.endsWith("\"") && v.length >= 2 ->
                v.substring(1, v.length - 1)
            v.startsWith("[") && v.endsWith("]") ->
                v.substring(1, v.length - 1)
                    .split(",")
                    .map { it.trim().trim('"') }
                    .filter { it.isNotEmpty() }
            v.toLongOrNull() != null -> v.toLong()
            else -> v.trim('"')
        }
    }
}
