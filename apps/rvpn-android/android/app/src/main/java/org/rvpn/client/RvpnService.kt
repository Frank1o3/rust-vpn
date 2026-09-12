package org.rvpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class RvpnService : VpnService() {

    companion object {
        const val TAG = "RvpnService"
        const val ACTION_CONNECT = "org.rvpn.client.CONNECT"
        const val ACTION_DISCONNECT = "org.rvpn.client.DISCONNECT"
        const val ACTION_STATUS_BROADCAST = "org.rvpn.client.STATUS"
        const val EXTRA_IS_CONNECTED = "is_connected"
        const val EXTRA_STATUS_MESSAGE = "status_message"
        const val EXTRA_BYTES_TX = "bytes_tx"
        const val EXTRA_BYTES_RX = "bytes_rx"
        const val EXTRA_PACKETS_TX = "packets_tx"
        const val EXTRA_PACKETS_RX = "packets_rx"
        const val EXTRA_UPTIME_MS = "uptime_ms"

        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID = "rvpn_status_channel"

        var isConnected: Boolean = false
            private set
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private val serviceScope = CoroutineScope(Dispatchers.Default + Job())
    private var monitorJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action ?: ACTION_CONNECT
        when (action) {
            ACTION_CONNECT -> {
                val config = RvpnConfig.load(this)
                startVpn(config)
            }

            ACTION_DISCONNECT -> {
                stopVpn()
            }
        }
        return START_NOT_STICKY
    }

    private fun startVpn(config: RvpnConfig) {
        if (isConnected || RvpnNative.isTunnelRunning()) {
            Log.w(TAG, "VPN is already running")
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification("Connecting to ${config.server}..."))

        try {
            Log.i(TAG, "Configuring Android VPN interface...")
            val builder = Builder()
                .setSession("RVPN")
                .setMtu(config.mtu)
                .addAddress(config.tunnelAddress, config.tunnelPrefixLength)

            if (config.tunnelAddressV6.isNotEmpty()) {
                builder.addAddress(config.tunnelAddressV6, config.tunnelPrefixLengthV6)
            }

            if (config.useDefaultRoute) {
                builder.addRoute("0.0.0.0", 0)
                if (config.tunnelAddressV6.isNotEmpty()) {
                    builder.addRoute("::", 0)
                }
            } else {
                val routes = config.splitTunnelRoutes
                    .split(",", "\n")
                    .map { it.trim() }
                    .filter { it.isNotEmpty() }
                if (routes.isEmpty()) {
                    Log.w(
                        TAG,
                        "Split tunneling is on but no routes were configured; only the VPN subnet will be reachable"
                    )
                }
                for (route in routes) {
                    val parts = route.split("/")
                    val prefix = parts.getOrNull(1)?.toIntOrNull()
                    if (parts.size == 2 && prefix != null) {
                        try {
                            builder.addRoute(parts[0], prefix)
                        } catch (e: Exception) {
                            Log.w(TAG, "Skipping invalid split-tunnel route '$route': ${e.message}")
                        }
                    } else {
                        Log.w(TAG, "Skipping malformed split-tunnel route '$route' (expected CIDR like 10.0.0.0/8)")
                    }
                }
            }

            // Primary DNS
            if (config.dnsServer.isNotEmpty()) {
                builder.addDnsServer(config.dnsServer)
            }

            // Split tunneling: exclude apps from VPN tunnel
            for (pkg in config.excludedApps) {
                try {
                    builder.addDisallowedApplication(pkg)
                } catch (e: Exception) {
                    Log.w(TAG, "Could not exclude app $pkg: ${e.message}")
                }
            }

            val pfd = builder.establish()
            if (pfd == null) {
                Log.e(TAG, "VpnService.Builder.establish() returned null; user or OS denied TUN creation")
                broadcastStatus(false, "Failed to establish VPN interface")
                stopSelf()
                return
            }

            vpnInterface = pfd
            val tunFd = pfd.detachFd()

            Log.i(TAG, "Established TUN device with fd $tunFd. Launching native Rust tunnel...")
            val error = RvpnNative.startTunnel(
                vpnService = this,
                server = config.server,
                pskHex = config.preSharedKey,
                tunFd = tunFd,
                mtu = config.mtu,
                rekeyPacketLimit = config.rekeyPacketLimit,
                retryIntervalMs = config.retryIntervalMs,
                retryLimit = config.retryLimit
            )

            if (error.isNotEmpty()) {
                Log.e(TAG, "Native tunnel failed to start: $error")
                broadcastStatus(false, "Error: $error")
                closeInterface()
                stopSelf()
                return
            }

            isConnected = true
            broadcastStatus(true, "Connected to ${config.server}")
            updateNotification("Connected to ${config.server}")

            // Start monitoring tunnel lifecycle and broadcasting live stats
            monitorJob?.cancel()
            monitorJob = serviceScope.launch {
                delay(500)
                while (isActive && RvpnNative.isTunnelRunning()) {
                    val stats = RvpnNative.getStats()
                    if (stats != null) {
                        broadcastStatus(
                            connected = true,
                            message = "Connected to ${config.server}",
                            stats = stats
                        )
                        updateNotification(
                            "Connected: ↓ ${formatBytes(stats.bytesRx)} | ↑ ${formatBytes(stats.bytesTx)}"
                        )
                    }
                    delay(1000)
                }
                if (isConnected) {
                    Log.i(TAG, "Tunnel stopped; cleaning up service")
                    stopVpn()
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Exception establishing VPN: ${e.message}", e)
            broadcastStatus(false, "Exception: ${e.message}")
            closeInterface()
            stopSelf()
        }
    }

    private fun stopVpn() {
        Log.i(TAG, "Stopping RVPN service...")
        monitorJob?.cancel()
        monitorJob = null

        if (RvpnNative.isTunnelRunning()) {
            RvpnNative.stopTunnel()
        }

        closeInterface()
        isConnected = false
        broadcastStatus(false, "Disconnected")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun closeInterface() {
        try {
            vpnInterface?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error closing ParcelFileDescriptor: ${e.message}")
        }
        vpnInterface = null
    }

    private fun broadcastStatus(
        connected: Boolean,
        message: String,
        stats: NativeTunnelStats? = null
    ) {
        val intent = Intent(ACTION_STATUS_BROADCAST).apply {
            putExtra(EXTRA_IS_CONNECTED, connected)
            putExtra(EXTRA_STATUS_MESSAGE, message)
            if (stats != null) {
                putExtra(EXTRA_BYTES_TX, stats.bytesTx)
                putExtra(EXTRA_BYTES_RX, stats.bytesRx)
                putExtra(EXTRA_PACKETS_TX, stats.packetsTx)
                putExtra(EXTRA_PACKETS_RX, stats.packetsRx)
                putExtra(EXTRA_UPTIME_MS, stats.uptimeMs)
            }
            setPackage(packageName)
        }
        sendBroadcast(intent)
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "RVPN Connection Status",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Shows the active RVPN tunnel status and data transfer"
                setShowBadge(false)
            }
            val manager = getSystemService(NotificationManager::class.java)
            manager.createNotificationChannel(channel)
        }
    }

    private fun buildNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val disconnectIntent = PendingIntent.getService(
            this,
            1,
            Intent(this, RvpnService::class.java).apply { action = ACTION_DISCONNECT },
            PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("RVPN")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_vpn)
            .setContentIntent(pendingIntent)
            .addAction(0, "Disconnect", disconnectIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val manager = getSystemService(NotificationManager::class.java)
        manager.notify(NOTIFICATION_ID, buildNotification(status))
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> "%.2f MB".format(bytes / (1024.0 * 1024.0))
            else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
