package org.rvpn.client

import android.net.VpnService

/**
 * Tunnel statistics snapshot returned from native Rust.
 */
data class NativeTunnelStats(
    val bytesTx: Long,
    val bytesRx: Long,
    val packetsTx: Long,
    val packetsRx: Long,
    val uptimeMs: Long
)

/**
 * JNI bindings to the native Rust `librvpn_android.so` library.
 */
object RvpnNative {

    init {
        try {
            System.loadLibrary("rvpn_android")
        } catch (e: UnsatisfiedLinkError) {
            System.err.println("Failed to load native library librvpn_android: $e")
        }
    }

    /**
     * Initializes the tracing logger in native code.
     */
    external fun initLogger()

    /**
     * Returns true if the background tunnel event loop is running.
     */
    external fun isTunnelRunning(): Boolean

    /**
     * Returns true only after the Rust handshake has completed.
     */
    external fun isTunnelConnected(): Boolean

    /**
     * Returns the most recent native tunnel error, or an empty string.
     */
    external fun getTunnelError(): String

    /**
     * Signals the background tunnel event loop to gracefully shut down.
     * Returns true if a running tunnel was signaled.
     */
    external fun stopTunnel(): Boolean

    /**
     * Queries active tunnel transmission statistics.
     */
    external fun getTunnelStats(): LongArray?

    /**
     * Helper to get structured statistics.
     */
    fun getStats(): NativeTunnelStats? {
        val raw = getTunnelStats() ?: return null
        if (raw.size < 5) return null
        return NativeTunnelStats(
            bytesTx = raw[0],
            bytesRx = raw[1],
            packetsTx = raw[2],
            packetsRx = raw[3],
            uptimeMs = raw[4]
        )
    }

    /**
     * Starts the RVPN tunnel on a background Tokio runtime thread.
     *
     * @param vpnService The running Android [VpnService] instance (used to call protect(fd)).
     * @param server The server address in host:port format (e.g. "10.0.0.1:9000").
     * @param authMode One of "psk", "pinned-key", or "certificate".
     * @param pskHex 64-hex-char PSK; used when authMode == "psk", otherwise ignored (pass "").
     * @param localIdentitySeedHex 64-hex-char Ed25519 seed; used by "pinned-key" and
     *   "certificate" modes, otherwise ignored (pass "").
     * @param peerPublicKeyHex 64-hex-char Ed25519 public key of the server; used only
     *   by "pinned-key" mode, otherwise ignored (pass "").
     * @param localCertificateHex 224-hex-char certificate; used only by "certificate"
     *   mode, otherwise ignored (pass "").
     * @param caPublicKeyHex 64-hex-char CA public key; used only by "certificate"
     *   mode, otherwise ignored (pass "").
     * @param tunFd The raw file descriptor of the virtual TUN device from [VpnService.Builder.establish].
     * @param mtu Configured MTU.
     * @param rekeyPacketLimit Number of packets before rekeying (0 to disable).
     * @param retryIntervalMs Handshake retransmission interval in ms.
     * @param retryLimit Maximum handshake attempts.
     * @return Empty string on success, or an error message if startup failed.
     */
    external fun startTunnel(
        vpnService: VpnService,
        server: String,
        authMode: String,
        pskHex: String,
        localIdentitySeedHex: String,
        peerPublicKeyHex: String,
        localCertificateHex: String,
        caPublicKeyHex: String,
        obfuscationKeyHex: String,
        tunFd: Int,
        mtu: Int,
        rekeyPacketLimit: Long,
        retryIntervalMs: Long,
        retryLimit: Int
    ): String
}