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
    private lateinit var diagnosticsText: TextView
    private lateinit var statsRxText: TextView
    private lateinit var statsTxText: TextView
    private lateinit var statsPacketsText: TextView
    private lateinit var statsUptimeText: TextView
    private lateinit var connectButton: Button

    // Config section: scan a QR code or paste a client.toml, WireGuard-import style.
    private lateinit var configInput: EditText
    private lateinit var saveConfigButton: Button
    private lateinit var saveFormButton: Button
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
        diagnosticsText = findViewById(R.id.diagnosticsText)
        statsRxText = findViewById(R.id.statsRxText)
        statsTxText = findViewById(R.id.statsTxText)
        statsPacketsText = findViewById(R.id.statsPacketsText)
        statsUptimeText = findViewById(R.id.statsUptimeText)
        connectButton = findViewById(R.id.connectButton)

        configInput = findViewById(R.id.configInput)
        saveConfigButton = findViewById(R.id.saveConfigButton)
        saveFormButton = findViewById(R.id.saveFormButton)
        scanQrButton = findViewById(R.id.scanQrButton)
        pasteClipboardButton = findViewById(R.id.pasteClipboardButton)
        configStatusText = findViewById(R.id.configStatusText)
        saveConfigButton.setOnClickListener { saveConfigSection() }
        saveFormButton.setOnClickListener { saveFormSection() }
        findViewById<android.widget.RadioGroup>(R.id.formAuthMode)
            .setOnCheckedChangeListener { _, _ -> updateFormVisibility() }
        findViewById<android.widget.CheckBox>(R.id.formIpv6Enabled)
            .setOnCheckedChangeListener { _, _ -> updateFormVisibility() }
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
        val config = RvpnConfig.load(this)
        configInput.setText(config.rawClientToml)
        populateForm(config)
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
        saveConfigSection()
        configStatusText.text = "Loaded config from $source. " + configStatusText.text
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
            populateForm(updated)
            updateUiState(RvpnService.isConnected, statusText.text.toString())
            configStatusText.text = "Configuration saved for ${updated.server}."
            Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            configStatusText.text = "Could not parse config: ${e.message}"
        }
    }

    private fun populateForm(config: RvpnConfig) {
        fun field(id: Int, value: String) { findViewById<EditText>(id).setText(value) }
        field(R.id.formServer, config.server)
        field(R.id.formPsk, config.preSharedKey)
        field(R.id.formIdentitySeed, config.localIdentitySeed)
        field(R.id.formPeerKey, config.peerPublicKey)
        field(R.id.formCertificate, config.localCertificate)
        field(R.id.formCaKey, config.caPublicKey)
        field(R.id.formIpv4, "${config.tunnelAddress}/${config.tunnelPrefixLength}")
        field(R.id.formIpv6, if (config.tunnelAddressV6.isBlank()) "" else "${config.tunnelAddressV6}/${config.tunnelPrefixLengthV6}")
        field(R.id.formDns, config.dnsServers)
        field(R.id.formMtu, config.mtu.toString())
        field(R.id.formObfuscation, config.obfuscationKey)
        field(R.id.formRekey, config.rekeyPacketLimit.toString())
        field(R.id.formRetryInterval, config.retryIntervalMs.toString())
        field(R.id.formRetryLimit, config.retryLimit.toString())
        field(R.id.formSplitRoutesV4, config.splitTunnelRoutesV4)
        field(R.id.formSplitRoutesV6, config.splitTunnelRoutesV6)
        field(R.id.formExcludedApps, config.excludedApps.sorted().joinToString(", "))
        findViewById<android.widget.CheckBox>(R.id.formIpv6Enabled).isChecked = config.ipv6Enabled
        findViewById<android.widget.CheckBox>(R.id.formDefaultV4).isChecked = config.useDefaultRouteV4
        findViewById<android.widget.CheckBox>(R.id.formDefaultV6).isChecked = config.useDefaultRouteV6
        val authId = when (config.authMode) {
            "pinned-key" -> R.id.authPinned
            "certificate" -> R.id.authCertificate
            else -> R.id.authPsk
        }
        findViewById<android.widget.RadioGroup>(R.id.formAuthMode).check(authId)
        updateFormVisibility()
    }

    private fun updateFormVisibility() {
        val auth = findViewById<android.widget.RadioGroup>(R.id.formAuthMode).checkedRadioButtonId
        findViewById<EditText>(R.id.formPsk).visibility = if (auth == R.id.authPsk) View.VISIBLE else View.GONE
        findViewById<EditText>(R.id.formIdentitySeed).visibility = if (auth == R.id.authPsk) View.GONE else View.VISIBLE
        findViewById<EditText>(R.id.formPeerKey).visibility = if (auth == R.id.authPinned) View.VISIBLE else View.GONE
        findViewById<EditText>(R.id.formCertificate).visibility = if (auth == R.id.authCertificate) View.VISIBLE else View.GONE
        findViewById<EditText>(R.id.formCaKey).visibility = if (auth == R.id.authCertificate) View.VISIBLE else View.GONE
        val ipv6Enabled = findViewById<android.widget.CheckBox>(R.id.formIpv6Enabled).isChecked
        findViewById<EditText>(R.id.formIpv6).visibility = if (ipv6Enabled) View.VISIBLE else View.GONE
        findViewById<android.widget.CheckBox>(R.id.formDefaultV6).visibility = if (ipv6Enabled) View.VISIBLE else View.GONE
        findViewById<EditText>(R.id.formSplitRoutesV6).visibility = if (ipv6Enabled) View.VISIBLE else View.GONE
    }

    private fun saveFormSection() {
        fun value(id: Int) = findViewById<EditText>(id).text.toString().trim()
        fun cidr(id: Int, fallbackPrefix: Int): Pair<String, Int>? {
            val parts = value(id).split('/', limit = 2)
            if (parts[0].isBlank()) return null
            val isIpv6 = parts[0].contains(':')
            if (isIpv6 != (id == R.id.formIpv6)) {
                throw IllegalArgumentException(if (id == R.id.formIpv4) "Enter an IPv4 address" else "Enter an IPv6 address")
            }
            val prefix = if (parts.size == 2) {
                parts[1].toIntOrNull() ?: throw IllegalArgumentException("Address prefix must be a number")
            } else {
                fallbackPrefix
            }
            val max = if (isIpv6) 128 else 32
            if (prefix !in 0..max) throw IllegalArgumentException("Address prefix must be between 0 and $max")
            return parts[0] to prefix
        }
        try {
            val base = RvpnConfig.load(this)
            val ipv4 = cidr(R.id.formIpv4, 24) ?: throw IllegalArgumentException("Enter the device IPv4 address")
            val ipv6Enabled = findViewById<android.widget.CheckBox>(R.id.formIpv6Enabled).isChecked
            val ipv6 = if (ipv6Enabled) cidr(R.id.formIpv6, 64) else null
            if (ipv6Enabled && ipv6 == null) throw IllegalArgumentException("Enter the device IPv6 address or turn IPv6 off")
            val authMode = when (findViewById<android.widget.RadioGroup>(R.id.formAuthMode).checkedRadioButtonId) {
                R.id.authPinned -> "pinned-key"
                R.id.authCertificate -> "certificate"
                else -> "psk"
            }
            val updated = base.copy(
                server = value(R.id.formServer), authMode = authMode,
                preSharedKey = value(R.id.formPsk), localIdentitySeed = value(R.id.formIdentitySeed),
                peerPublicKey = value(R.id.formPeerKey), localCertificate = value(R.id.formCertificate),
                caPublicKey = value(R.id.formCaKey), tunnelAddress = ipv4.first, tunnelPrefixLength = ipv4.second,
                ipv6Enabled = ipv6Enabled, tunnelAddressV6 = ipv6?.first ?: "", tunnelPrefixLengthV6 = ipv6?.second ?: 64,
                dnsServers = value(R.id.formDns), mtu = value(R.id.formMtu).toIntOrNull() ?: 1400,
                obfuscationKey = value(R.id.formObfuscation), rekeyPacketLimit = value(R.id.formRekey).toLongOrNull() ?: 1048576L,
                retryIntervalMs = value(R.id.formRetryInterval).toLongOrNull() ?: 500L,
                retryLimit = value(R.id.formRetryLimit).toIntOrNull() ?: 5,
                splitTunnelRoutesV4 = value(R.id.formSplitRoutesV4),
                splitTunnelRoutesV6 = value(R.id.formSplitRoutesV6),
                excludedApps = value(R.id.formExcludedApps).split(',').map(String::trim).filter(String::isNotEmpty).toSet(),
                useDefaultRouteV4 = findViewById<android.widget.CheckBox>(R.id.formDefaultV4).isChecked,
                useDefaultRouteV6 = findViewById<android.widget.CheckBox>(R.id.formDefaultV6).isChecked,
            )
            if (updated.server.isBlank()) throw IllegalArgumentException("Enter the VPN server address")
            if (updated.mtu !in 576..65535) throw IllegalArgumentException("MTU must be between 576 and 65535")
            val authValid = when (authMode) {
                "psk" -> updated.preSharedKey.length == 64
                "pinned-key" -> updated.localIdentitySeed.length == 64 && updated.peerPublicKey.length == 64
                else -> updated.localIdentitySeed.length == 64 && updated.localCertificate.length == 224 && updated.caPublicKey.length == 64
            }
            if (!authValid) throw IllegalArgumentException("Fill in valid authentication key material for the selected mode")
            val rendered = TomlConfigParser.fromRvpnConfig(updated)
            val saved = updated.copy(rawClientToml = rendered)
            RvpnConfig.save(this, saved)
            configInput.setText(rendered)
            updateUiState(RvpnService.isConnected, statusText.text.toString())
            configStatusText.text = "Configuration saved for ${saved.server}."
            Toast.makeText(this, "Configuration saved", Toast.LENGTH_SHORT).show()
        } catch (e: Exception) {
            configStatusText.text = "Could not save configuration: ${e.message}"
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
        val config = RvpnConfig.load(this)
        val route4 = if (config.useDefaultRouteV4) "All IPv4 traffic" else "IPv4 split tunnel"
        val route6 = if (!config.ipv6Enabled) "IPv6 disabled" else if (config.useDefaultRouteV6) "All IPv6 traffic" else "IPv6 split tunnel"
        val dns = config.dnsServers.ifBlank { "System default" }
        diagnosticsText.text = "Server: ${config.server.ifBlank { "Not configured" }}\n" +
                "Tunnel status: ${if (connected) "Connected" else message}\n" +
                "Routing: $route4; $route6\nDNS: $dns\nConfigured MTU: ${config.mtu}"
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
