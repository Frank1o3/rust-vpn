package org.rvpn.client

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.RadioGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.switchmaterial.SwitchMaterial

class MainActivity : AppCompatActivity() {

    // Main section
    private lateinit var statusText: TextView
    private lateinit var statsRxText: TextView
    private lateinit var statsTxText: TextView
    private lateinit var statsPacketsText: TextView
    private lateinit var statsUptimeText: TextView
    private lateinit var connectButton: Button

    // Tunnel section
    private lateinit var tunnelIpInput: EditText
    private lateinit var ipv6EnableSwitch: SwitchMaterial
    private lateinit var tunnelIpv6Input: EditText
    private lateinit var routeAllV4Switch: SwitchMaterial
    private lateinit var splitRoutesV4Input: EditText
    private lateinit var routeAllV6Switch: SwitchMaterial
    private lateinit var splitRoutesV6Input: EditText
    private lateinit var dnsInput: EditText

    // Server section
    private lateinit var serverInput: EditText
    private lateinit var authModeGroup: RadioGroup
    private lateinit var pskGroup: View
    private lateinit var pinnedKeyGroup: View
    private lateinit var certificateGroup: View
    private lateinit var pskInput: EditText
    private lateinit var generatePskButton: Button
    private lateinit var identitySeedInput: EditText
    private lateinit var peerPublicKeyInput: EditText
    private lateinit var certIdentitySeedInput: EditText
    private lateinit var certificateInput: EditText
    private lateinit var caPublicKeyInput: EditText

    // Advanced section
    private lateinit var retryIntervalInput: EditText
    private lateinit var retryLimitInput: EditText
    private lateinit var rekeyLimitInput: EditText
    private lateinit var mtuInput: EditText
    private lateinit var excludedAppsInput: EditText

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

        tunnelIpInput = findViewById(R.id.tunnelIpInput)
        ipv6EnableSwitch = findViewById(R.id.ipv6EnableSwitch)
        tunnelIpv6Input = findViewById(R.id.tunnelIpv6Input)
        routeAllV4Switch = findViewById(R.id.routeAllV4Switch)
        splitRoutesV4Input = findViewById(R.id.splitRoutesV4Input)
        routeAllV6Switch = findViewById(R.id.routeAllV6Switch)
        splitRoutesV6Input = findViewById(R.id.splitRoutesV6Input)
        dnsInput = findViewById(R.id.dnsInput)
        findViewById<Button>(R.id.saveTunnelButton).setOnClickListener { saveTunnelSection() }

        serverInput = findViewById(R.id.serverInput)
        authModeGroup = findViewById(R.id.authModeGroup)
        pskGroup = findViewById(R.id.pskGroup)
        pinnedKeyGroup = findViewById(R.id.pinnedKeyGroup)
        certificateGroup = findViewById(R.id.certificateGroup)
        pskInput = findViewById(R.id.pskInput)
        generatePskButton = findViewById(R.id.generatePskButton)
        identitySeedInput = findViewById(R.id.identitySeedInput)
        peerPublicKeyInput = findViewById(R.id.peerPublicKeyInput)
        certIdentitySeedInput = findViewById(R.id.certIdentitySeedInput)
        certificateInput = findViewById(R.id.certificateInput)
        caPublicKeyInput = findViewById(R.id.caPublicKeyInput)
        findViewById<Button>(R.id.saveServerButton).setOnClickListener { saveServerSection() }

        authModeGroup.setOnCheckedChangeListener { _, checkedId ->
            showAuthGroup(authModeFromCheckedId(checkedId))
        }

        retryIntervalInput = findViewById(R.id.retryIntervalInput)
        retryLimitInput = findViewById(R.id.retryLimitInput)
        rekeyLimitInput = findViewById(R.id.rekeyLimitInput)
        mtuInput = findViewById(R.id.mtuInput)
        excludedAppsInput = findViewById(R.id.excludedAppsInput)
        findViewById<Button>(R.id.saveAdvancedButton).setOnClickListener { saveAdvancedSection() }

        sections = mapOf(
            R.id.nav_main to findViewById(R.id.sectionMain),
            R.id.nav_tunnel to findViewById(R.id.sectionTunnel),
            R.id.nav_server to findViewById(R.id.sectionServer),
            R.id.nav_advanced to findViewById(R.id.sectionAdvanced)
        )
        findViewById<com.google.android.material.bottomnavigation.BottomNavigationView>(R.id.bottomNav)
            .setOnItemSelectedListener { item ->
                showSection(item.itemId)
                true
            }

        ipv6EnableSwitch.setOnCheckedChangeListener { _, checked -> applyIpv6Enabled(checked) }
        routeAllV4Switch.setOnCheckedChangeListener { _, checked ->
            splitRoutesV4Input.isEnabled = !checked
            splitRoutesV4Input.alpha = if (checked) 0.4f else 1f
        }
        routeAllV6Switch.setOnCheckedChangeListener { _, checked ->
            splitRoutesV6Input.isEnabled = !checked
            splitRoutesV6Input.alpha = if (checked) 0.4f else 1f
        }

        generatePskButton.setOnClickListener {
            pskInput.setText(RvpnConfig.generateRandomPsk())
            Toast.makeText(this, "Generated secure 256-bit PSK", Toast.LENGTH_SHORT).show()
        }

        connectButton.setOnClickListener {
            if (RvpnService.isConnected || RvpnNative.isTunnelRunning()) {
                disconnectVpn()
            } else {
                saveAllSections()
                connectWithCurrentConfig()
            }
        }

        loadSavedConfig()
        showSection(R.id.nav_main)
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

    private fun showSection(id: Int) {
        sections.forEach { (sectionId, view) -> view.visibility = if (sectionId == id) View.VISIBLE else View.GONE }
    }

    private fun authModeFromCheckedId(checkedId: Int): String = when (checkedId) {
        R.id.radioPinnedKey -> "pinned-key"
        R.id.radioCertificate -> "certificate"
        else -> "psk"
    }

    private fun checkedIdFromAuthMode(mode: String): Int = when (mode) {
        "pinned-key" -> R.id.radioPinnedKey
        "certificate" -> R.id.radioCertificate
        else -> R.id.radioPsk
    }

    private fun showAuthGroup(mode: String) {
        pskGroup.visibility = if (mode == "psk") View.VISIBLE else View.GONE
        pinnedKeyGroup.visibility = if (mode == "pinned-key") View.VISIBLE else View.GONE
        certificateGroup.visibility = if (mode == "certificate") View.VISIBLE else View.GONE
    }

    /** Grays out the IPv6 fields but never clears them, so a value typed in
     *  while disabled is still there if the switch is re-enabled later. */
    private fun applyIpv6Enabled(enabled: Boolean) {
        tunnelIpv6Input.isEnabled = enabled
        tunnelIpv6Input.alpha = if (enabled) 1f else 0.4f
        routeAllV6Switch.isEnabled = enabled
        routeAllV6Switch.alpha = if (enabled) 1f else 0.4f
        splitRoutesV6Input.isEnabled = enabled && !routeAllV6Switch.isChecked
        splitRoutesV6Input.alpha = if (splitRoutesV6Input.isEnabled) 1f else 0.4f
    }

    private fun loadSavedConfig() {
        val config = RvpnConfig.load(this)
        tunnelIpInput.setText(config.tunnelAddress)
        tunnelIpv6Input.setText(config.tunnelAddressV6)
        ipv6EnableSwitch.isChecked = config.ipv6Enabled
        routeAllV4Switch.isChecked = config.useDefaultRouteV4
        splitRoutesV4Input.setText(config.splitTunnelRoutesV4)
        splitRoutesV4Input.isEnabled = !config.useDefaultRouteV4
        splitRoutesV4Input.alpha = if (config.useDefaultRouteV4) 0.4f else 1f
        routeAllV6Switch.isChecked = config.useDefaultRouteV6
        splitRoutesV6Input.setText(config.splitTunnelRoutesV6)
        dnsInput.setText(config.dnsServers)
        applyIpv6Enabled(config.ipv6Enabled)

        serverInput.setText(config.server)
        authModeGroup.check(checkedIdFromAuthMode(config.authMode))
        showAuthGroup(config.authMode)
        pskInput.setText(config.preSharedKey)
        identitySeedInput.setText(config.localIdentitySeed)
        peerPublicKeyInput.setText(config.peerPublicKey)
        certIdentitySeedInput.setText(config.localIdentitySeed)
        certificateInput.setText(config.localCertificate)
        caPublicKeyInput.setText(config.caPublicKey)

        retryIntervalInput.setText(config.retryIntervalMs.toString())
        retryLimitInput.setText(config.retryLimit.toString())
        rekeyLimitInput.setText(config.rekeyPacketLimit.toString())
        mtuInput.setText(config.mtu.toString())
        excludedAppsInput.setText(config.excludedApps.joinToString(", "))
    }

    private fun currentConfig(): RvpnConfig {
        val mode = authModeFromCheckedId(authModeGroup.checkedRadioButtonId)
        val seed = if (mode == "certificate") certIdentitySeedInput.text.toString().trim()
        else identitySeedInput.text.toString().trim()
        return RvpnConfig.load(this).copy(
            tunnelAddress = tunnelIpInput.text.toString().trim().ifEmpty { "10.42.0.2" },
            ipv6Enabled = ipv6EnableSwitch.isChecked,
            tunnelAddressV6 = tunnelIpv6Input.text.toString().trim(),
            useDefaultRouteV4 = routeAllV4Switch.isChecked,
            splitTunnelRoutesV4 = splitRoutesV4Input.text.toString().trim(),
            useDefaultRouteV6 = routeAllV6Switch.isChecked,
            splitTunnelRoutesV6 = splitRoutesV6Input.text.toString().trim(),
            dnsServers = dnsInput.text.toString().trim().ifEmpty { "1.1.1.1" },
            server = serverInput.text.toString().trim(),
            authMode = mode,
            preSharedKey = pskInput.text.toString().trim(),
            localIdentitySeed = seed,
            peerPublicKey = peerPublicKeyInput.text.toString().trim(),
            localCertificate = certificateInput.text.toString().trim(),
            caPublicKey = caPublicKeyInput.text.toString().trim(),
            retryIntervalMs = retryIntervalInput.text.toString().toLongOrNull() ?: 500L,
            retryLimit = retryLimitInput.text.toString().toIntOrNull() ?: 5,
            rekeyPacketLimit = rekeyLimitInput.text.toString().toLongOrNull() ?: 1048576L,
            mtu = mtuInput.text.toString().toIntOrNull() ?: 1400,
            excludedApps = excludedAppsInput.text.toString().split(",")
                .map { it.trim() }.filter { it.isNotEmpty() }.toSet()
        )
    }

    private fun saveTunnelSection() {
        RvpnConfig.save(this, currentConfig())
        Toast.makeText(this, "Tunnel settings saved", Toast.LENGTH_SHORT).show()
    }

    private fun saveServerSection() {
        if (serverInput.text.toString().trim().isEmpty()) {
            serverInput.error = "Server address required"
            return
        }
        when (authModeFromCheckedId(authModeGroup.checkedRadioButtonId)) {
            "psk" -> if (pskInput.text.toString().trim().length != 64) {
                pskInput.error = "PSK must be 64 hexadecimal characters"
                return
            }

            "pinned-key" -> {
                if (identitySeedInput.text.toString().trim().length != 64) {
                    identitySeedInput.error = "Identity seed must be 64 hexadecimal characters"
                    return
                }
                if (peerPublicKeyInput.text.toString().trim().length != 64) {
                    peerPublicKeyInput.error = "Public key must be 64 hexadecimal characters"
                    return
                }
            }

            "certificate" -> {
                if (certIdentitySeedInput.text.toString().trim().length != 64) {
                    certIdentitySeedInput.error = "Identity seed must be 64 hexadecimal characters"
                    return
                }
                if (certificateInput.text.toString().trim().length != 224) {
                    certificateInput.error = "Certificate must be 224 hexadecimal characters"
                    return
                }
                if (caPublicKeyInput.text.toString().trim().length != 64) {
                    caPublicKeyInput.error = "CA public key must be 64 hexadecimal characters"
                    return
                }
            }
        }
        RvpnConfig.save(this, currentConfig())
        Toast.makeText(this, "Server settings saved", Toast.LENGTH_SHORT).show()
    }

    private fun saveAdvancedSection() {
        RvpnConfig.save(this, currentConfig())
        Toast.makeText(this, "Advanced settings saved", Toast.LENGTH_SHORT).show()
    }

    private fun saveAllSections() {
        RvpnConfig.save(this, currentConfig())
    }

    private fun connectWithCurrentConfig() {
        val config = RvpnConfig.load(this)
        if (config.server.isEmpty()) {
            showSection(R.id.nav_server)
            serverInput.error = "Server address required"
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
            showSection(R.id.nav_server)
            Toast.makeText(this, "Fix the authentication fields before connecting", Toast.LENGTH_SHORT).show()
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