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
     * @param pskHex The 32-byte pre-shared key encoded as a 64-character hexadecimal string.
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
        pskHex: String,
        tunFd: Int,
        mtu: Int,
        rekeyPacketLimit: Long,
        retryIntervalMs: Long,
        retryLimit: Int
    ): String
}
