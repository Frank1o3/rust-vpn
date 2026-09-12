package org.rvpn.client

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity

class MainActivity : AppCompatActivity() {

    private lateinit var statusText: TextView
    private lateinit var statsRxText: TextView
    private lateinit var statsTxText: TextView
    private lateinit var statsPacketsText: TextView
    private lateinit var statsUptimeText: TextView
    private lateinit var serverInput: EditText
    private lateinit var pskInput: EditText
    private lateinit var tunnelIpInput: EditText
    private lateinit var tunnelIpv6Input: EditText
    private lateinit var dnsInput: EditText
    private lateinit var connectButton: Button
    private lateinit var generatePskButton: Button
    private lateinit var routeAllTrafficSwitch: com.google.android.material.switchmaterial.SwitchMaterial
    private lateinit var splitRoutesInput: EditText
    private lateinit var retryIntervalInput: EditText
    private lateinit var retryLimitInput: EditText
    private lateinit var rekeyLimitInput: EditText

    private val vpnPrepareLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            startVpnService()
        } else {
            Toast.makeText(this, "VPN permission denied", Toast.LENGTH_SHORT).show()
            updateUiState(false, "Permission Denied")
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == RvpnService.ACTION_STATUS_BROADCAST) {
                val isConnected = intent.getBooleanExtra(RvpnService.EXTRA_IS_CONNECTED, false)
                val message = intent.getStringExtra(RvpnService.EXTRA_STATUS_MESSAGE) ?: ""
                val bytesTx = intent.getLongExtra(RvpnService.EXTRA_BYTES_TX, 0L)
                val bytesRx = intent.getLongExtra(RvpnService.EXTRA_BYTES_RX, 0L)
                val packetsTx = intent.getLongExtra(RvpnService.EXTRA_PACKETS_TX, 0L)
                val packetsRx = intent.getLongExtra(RvpnService.EXTRA_PACKETS_RX, 0L)
                val uptimeMs = intent.getLongExtra(RvpnService.EXTRA_UPTIME_MS, 0L)

                updateUiState(isConnected, message)
                updateStats(bytesTx, bytesRx, packetsTx, packetsRx, uptimeMs)
            }
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        statusText = findViewById(R.id.statusText)
        statsRxText = findViewById(R.id.statsRxText)
        statsTxText = findViewById(R.id.statsTxText)
        statsPacketsText = findViewById(R.id.statsPacketsText)
        statsUptimeText = findViewById(R.id.statsUptimeText)
        serverInput = findViewById(R.id.serverInput)
        pskInput = findViewById(R.id.pskInput)
        tunnelIpInput = findViewById(R.id.tunnelIpInput)
        tunnelIpv6Input = findViewById(R.id.tunnelIpv6Input)
        dnsInput = findViewById(R.id.dnsInput)
        connectButton = findViewById(R.id.connectButton)
        generatePskButton = findViewById(R.id.generatePskButton)
        routeAllTrafficSwitch = findViewById(R.id.routeAllTrafficSwitch)
        splitRoutesInput = findViewById(R.id.splitRoutesInput)
        retryIntervalInput = findViewById(R.id.retryIntervalInput)
        retryLimitInput = findViewById(R.id.retryLimitInput)
        rekeyLimitInput = findViewById(R.id.rekeyLimitInput)

        routeAllTrafficSwitch.setOnCheckedChangeListener { _, isChecked ->
            splitRoutesInput.visibility = if (isChecked) android.view.View.GONE else android.view.View.VISIBLE
        }

        loadSavedConfig()

        connectButton.setOnClickListener {
            if (RvpnService.isConnected || RvpnNative.isTunnelRunning()) {
                disconnectVpn()
            } else {
                saveAndConnectVpn()
            }
        }

        generatePskButton.setOnClickListener {
            val randomKey = RvpnConfig.generateRandomPsk()
            pskInput.setText(randomKey)
            Toast.makeText(this, "Generated secure 256-bit PSK", Toast.LENGTH_SHORT).show()
        }

        updateUiState(RvpnService.isConnected, if (RvpnService.isConnected) "Connected" else "Disconnected")
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(RvpnService.ACTION_STATUS_BROADCAST)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(statusReceiver, filter, RECEIVER_NOT_EXPORTED)
        } else {
            registerReceiver(statusReceiver, filter)
        }
        updateUiState(RvpnService.isConnected, if (RvpnService.isConnected) "Connected" else "Disconnected")
    }

    override fun onStop() {
        super.onStop()
        unregisterReceiver(statusReceiver)
    }

    private fun loadSavedConfig() {
        val config = RvpnConfig.load(this)
        serverInput.setText(config.server)
        pskInput.setText(config.preSharedKey)
        tunnelIpInput.setText(config.tunnelAddress)
        tunnelIpv6Input.setText(config.tunnelAddressV6)
        dnsInput.setText(config.dnsServer)
        routeAllTrafficSwitch.isChecked = config.useDefaultRoute
        splitRoutesInput.setText(config.splitTunnelRoutes)
        splitRoutesInput.visibility = if (config.useDefaultRoute) android.view.View.GONE else android.view.View.VISIBLE
        retryIntervalInput.setText(config.retryIntervalMs.toString())
        retryLimitInput.setText(config.retryLimit.toString())
        rekeyLimitInput.setText(config.rekeyPacketLimit.toString())
    }

    private fun saveAndConnectVpn() {
        val server = serverInput.text.toString().trim()
        val psk = pskInput.text.toString().trim()
        val tunnelIp = tunnelIpInput.text.toString().trim()
        val tunnelIpv6 = tunnelIpv6Input.text.toString().trim()
        val dns = dnsInput.text.toString().trim()

        if (server.isEmpty()) {
            serverInput.error = "Server address required"
            return
        }
        if (psk.length != 64) {
            pskInput.error = "PSK must be 64 hexadecimal characters"
            return
        }

        val config = RvpnConfig(
            server = server,
            preSharedKey = psk,
            tunnelAddress = if (tunnelIp.isNotEmpty()) tunnelIp else "10.42.0.2",
            tunnelAddressV6 = tunnelIpv6,
            dnsServer = if (dns.isNotEmpty()) dns else "1.1.1.1",
            useDefaultRoute = routeAllTrafficSwitch.isChecked,
            splitTunnelRoutes = splitRoutesInput.text.toString().trim(),
            retryIntervalMs = retryIntervalInput.text.toString().toLongOrNull() ?: 500L,
            retryLimit = retryLimitInput.text.toString().toIntOrNull() ?: 5,
            rekeyPacketLimit = rekeyLimitInput.text.toString().toLongOrNull() ?: 1048576L
        )
        RvpnConfig.save(this, config)

        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPrepareLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        updateUiState(false, "Connecting...")
        val intent = Intent(this, RvpnService::class.java).apply {
            action = RvpnService.ACTION_CONNECT
        }
        startService(intent)
    }

    private fun disconnectVpn() {
        updateUiState(false, "Disconnecting...")
        val intent = Intent(this, RvpnService::class.java).apply {
            action = RvpnService.ACTION_DISCONNECT
        }
        startService(intent)
    }

    private fun updateUiState(connected: Boolean, message: String) {
        statusText.text = message
        connectButton.text = if (connected) "Disconnect" else "Connect"
        serverInput.isEnabled = !connected
        pskInput.isEnabled = !connected
        tunnelIpInput.isEnabled = !connected
        tunnelIpv6Input.isEnabled = !connected
        dnsInput.isEnabled = !connected
        generatePskButton.isEnabled = !connected
    }

    private fun updateStats(bytesTx: Long, bytesRx: Long, packetsTx: Long, packetsRx: Long, uptimeMs: Long) {
        statsRxText.text = formatBytes(bytesRx)
        statsTxText.text = formatBytes(bytesTx)
        statsPacketsText.text = "$packetsRx ↓ / $packetsTx ↑"
        statsUptimeText.text = formatUptime(uptimeMs)
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
            bytes < 1024 * 1024 * 1024 -> "%.2f MB".format(bytes / (1024.0 * 1024.0))
            else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
        }
    }

    private fun formatUptime(uptimeMs: Long): String {
        val totalSecs = uptimeMs / 1000
        val hours = totalSecs / 3600
        val minutes = (totalSecs % 3600) / 60
        val seconds = totalSecs % 60
        return "%02d:%02d:%02d".format(hours, minutes, seconds)
    }
}
