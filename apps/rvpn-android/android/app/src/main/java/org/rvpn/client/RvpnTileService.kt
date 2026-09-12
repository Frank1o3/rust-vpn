package org.rvpn.client

import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.RequiresApi

/**
 * Quick Settings tile enabling one-tap VPN toggling from the Android notification shade.
 */
@RequiresApi(Build.VERSION_CODES.N)
class RvpnTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTileState()
    }

    override fun onClick() {
        super.onClick()
        if (RvpnService.isConnected || RvpnNative.isTunnelRunning()) {
            val intent = Intent(this, RvpnService::class.java).apply {
                action = RvpnService.ACTION_DISCONNECT
            }
            startService(intent)
            updateTileState(false)
        } else {
            // Check if VPN permission has been granted
            val prepareIntent = VpnService.prepare(this)
            if (prepareIntent != null) {
                // Must open activity to request user consent
                val activityIntent = Intent(this, MainActivity::class.java).apply {
                    flags = Intent.FLAG_ACTIVITY_NEW_TASK
                }
                startActivityAndCollapse(activityIntent)
            } else {
                val intent = Intent(this, RvpnService::class.java).apply {
                    action = RvpnService.ACTION_CONNECT
                }
                startForegroundService(intent)
                updateTileState(true)
            }
        }
    }

    private fun updateTileState(forcedConnected: Boolean? = null) {
        val tile = qsTile ?: return
        val connected = forcedConnected ?: (RvpnService.isConnected || RvpnNative.isTunnelRunning())

        tile.state = if (connected) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        tile.label = if (connected) "RVPN (On)" else "RVPN (Off)"
        tile.updateTile()
    }
}
