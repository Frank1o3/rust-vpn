package org.rvpn.client

import android.Manifest
import android.app.Activity
import android.content.BroadcastReceiver
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : AppCompatActivity() {

    // Main section
    private lateinit var statusText: TextView
    private lateinit var statsRxText: TextView
    private lateinit var statsTxText: TextView
    private lateinit var statsPacketsText: TextView
    private lateinit var statsUptimeText: TextView
    private lateinit var connectButton: Button

    // Config section: scan a QR code or paste a client.toml, WireGuard-import style.
    private lateinit var configInput: EditText
    private lateinit var saveConfigButton: Button
    private lateinit var scanQrButton: Button
    private lateinit var pasteClipboardButton: Button
    private lateinit var configStatusText: TextView

    private lateinit var sections: Map<Int, View>

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

    // ZXing's ScanContract shows the camera preview and asks for the CAMERA
    // permission itself, right when the user taps "Load from QR code" — not
    // upfront. `contents` is null when the user backs out.
    private val qrScanLauncher = registerForActivityResult(ScanContract()) { result ->
        val contents = result.contents
        if (contents.isNullOrBlank()) {
            configStatusText.text = "QR scan cancelled."
        } else {
            importConfigText(contents, "QR code")
        }
    }

    // Android 13+ requires an explicit runtime grant before a foreground
    // service's notification is shown. Requested once, right after launch,
    // since RvpnService posts its status notification the moment Connect is
    // tapped — asking at that point would be too late for the first connect.
    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { granted ->
        if (!granted) {
            Toast.makeText(
                this,
                "Notifications are off; connection status won't appear in the shade",
                Toast.LENGTH_LONG
            ).show()
        }
    }

    private val statusReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == RvpnService.ACTION_STATUS_BROADCAST) {
                val isConnected = intent.getBooleanExtra(RvpnService.EXTRA_IS_CONNECTED, false)
                val message = intent.getStringExtra(RvpnService.EXTRA_STATUS_MESSAGE) ?: ""
                updateUiState(isConnected, message)
                updateStats(
                    intent.getLongExtra(RvpnService.EXTRA_BYTES_TX, 0L),
                    intent.getLongExtra(RvpnService.EXTRA_BYTES_RX, 0L),
                    intent.getLongExtra(RvpnService.EXTRA_PACKETS_TX, 0L),
                    intent.getLongExtra(RvpnService.EXTRA_PACKETS_RX, 0L),
                    intent.getLongExtra(RvpnService.EXTRA_UPTIME_MS, 0L)
                )
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
        connectButton = findViewById(R.id.connectButton)

        configInput = findViewById(R.id.configInput)
        saveConfigButton = findViewById(R.id.saveConfigButton)
        scanQrButton = findViewById(R.id.scanQrButton)
        pasteClipboardButton = findViewById(R.id.pasteClipboardButton)
        configStatusText = findViewById(R.id.configStatusText)
        saveConfigButton.setOnClickListener { saveConfigSection() }
        scanQrButton.setOnClickListener { launchQrScanner() }
        pasteClipboardButton.setOnClickListener { pasteFromClipboard() }

        sections = mapOf(
            R.id.nav_main to findViewById(R.id.sectionMain),
            R.id.nav_config to findViewById(R.id.sectionConfig)
        )
        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.bottomNav)
            .setOnItemSelectedListener { item ->
                showSection(item.itemId)
                true
            }

        connectButton.setOnClickListener {
            if (RvpnService.isConnected || RvpnNative.isTunnelRunning()) {
                disconnectVpn()
            } else {
                connectWithSavedConfig()
            }
        }

        requestNotificationPermissionIfNeeded()

        loadSavedConfig()
        val hasConfig = RvpnConfig.load(this).server.isNotBlank()
        showSection(if (hasConfig) R.id.nav_main else R.id.nav_config)
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

    /**
     * Asks for POST_NOTIFICATIONS up front on Android 13+ so the app never
     * silently fails to show the "Connected" status notification. Skipped
     * entirely below API 33, where the permission doesn't exist.
     */
    private fun requestNotificationPermissionIfNeeded() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun showSection(id: Int) {
        sections.forEach { (sectionId, view) -> view.visibility = if (sectionId == id) View.VISIBLE else View.GONE }
    }

    private fun loadSavedConfig() {
        configInput.setText(RvpnConfig.load(this).rawClientToml)
    }

    private fun launchQrScanner() {
        val options = ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("Scan the RVPN client QR code")
            setBeepEnabled(false)
            setOrientationLocked(false)
        }
        qrScanLauncher.launch(options)
    }

    private fun pasteFromClipboard() {
        val clipboard = getSystemService(ClipboardManager::class.java)
        val text = clipboard?.primaryClip
            ?.takeIf { it.itemCount > 0 }
            ?.getItemAt(0)
            ?.coerceToText(this)
            ?.toString()
        if (text.isNullOrBlank()) {
            configStatusText.text = "The clipboard is empty."
        } else {
            importConfigText(text, "clipboard")
        }
    }

    /** Fills the config box with [text] and saves it right away. */
    private fun importConfigText(text: String, source: String) {
        configInput.setText(text.trim())
        configStatusText.text = "Loaded config from $source."
        saveConfigSection()
    }

    /** Parses whatever is currently in the config box and persists it. */
    private fun saveConfigSection() {
        val text = configInput.text.toString()
        if (text.isBlank()) {
            configStatusText.text = "Scan a QR code or paste your client.toml above first."
            return
        }
        try {
            val base = RvpnConfig.load(this)
            val updated = TomlConfigParser.toRvpnConfig(text, base)
            if (updated.server.isBlank()) {
                configStatusText.text = "Could not find `server = \"host:port\"` in this config."
                return
            }
            RvpnConfig.save(this, updated)
            configStatusText.text = "Configuration saved for ${updated.server}."
            Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            configStatusText.text = "Could not parse config: ${e.message}"
        }
    }

    private fun connectWithSavedConfig() {
        val config = RvpnConfig.load(this)
        if (config.server.isBlank()) {
            showSection(R.id.nav_config)
            Toast.makeText(this, "Scan a QR code or paste a client.toml first", Toast.LENGTH_SHORT).show()
            return
        }
        val authValid = when (config.authMode) {
            "psk" -> config.preSharedKey.length == 64
            "pinned-key" -> config.localIdentitySeed.length == 64 && config.peerPublicKey.length == 64
            "certificate" -> config.localIdentitySeed.length == 64 &&
                    config.localCertificate.length == 224 && config.caPublicKey.length == 64
            else -> false
        }
        if (!authValid) {
            showSection(R.id.nav_config)
            Toast.makeText(
                this,
                "The saved config is missing valid authentication fields",
                Toast.LENGTH_SHORT
            ).show()
            return
        }
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            vpnPrepareLauncher.launch(prepareIntent)
        } else {
            startVpnService()
        }
    }

    private fun startVpnService() {
        updateUiState(false, "Connecting...")
        val intent = Intent(this, RvpnService::class.java).apply { action = RvpnService.ACTION_CONNECT }
        startService(intent)
    }

    private fun disconnectVpn() {
        updateUiState(false, "Disconnecting...")
        val intent = Intent(this, RvpnService::class.java).apply { action = RvpnService.ACTION_DISCONNECT }
        startService(intent)
    }

    private fun updateUiState(connected: Boolean, message: String) {
        statusText.text = message
        connectButton.text = if (connected) "Disconnect" else "Connect"
    }

    private fun updateStats(bytesTx: Long, bytesRx: Long, packetsTx: Long, packetsRx: Long, uptimeMs: Long) {
        statsRxText.text = formatBytes(bytesRx)
        statsTxText.text = formatBytes(bytesTx)
        statsPacketsText.text = "$packetsRx ↓ / $packetsTx ↑"
        statsUptimeText.text = formatUptime(uptimeMs)
    }

    private fun formatBytes(bytes: Long): String = when {
        bytes < 1024 -> "$bytes B"
        bytes < 1024 * 1024 -> "%.1f KB".format(bytes / 1024.0)
        bytes < 1024 * 1024 * 1024 -> "%.2f MB".format(bytes / (1024.0 * 1024.0))
        else -> "%.2f GB".format(bytes / (1024.0 * 1024.0 * 1024.0))
    }

    private fun formatUptime(uptimeMs: Long): String {
        val totalSecs = uptimeMs / 1000
        return "%02d:%02d:%02d".format(totalSecs / 3600, (totalSecs % 3600) / 60, totalSecs % 60)
    }
}