package com.example.tendederoiot_auto

import android.Manifest
import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.bluetooth.BluetoothAdapter
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.view.View
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import java.text.SimpleDateFormat
import java.util.*

class MainActivity : AppCompatActivity() {

    private lateinit var securityManager: SecurityManager
    private lateinit var btController: BluetoothController

    private lateinit var layoutLogin: LinearLayout
    private lateinit var layoutRegister: LinearLayout
    private lateinit var layoutDashboard: LinearLayout
    private lateinit var tvBtStatus: TextView
    private lateinit var btnConnectBt: Button
    private lateinit var tvRainState: TextView
    private lateinit var tvServoState: TextView
    private lateinit var tvBuzzerState: TextView
    private lateinit var tvAuditLog: TextView

    private var lastRainState = false
    private val pendingLogs = mutableListOf<String>()

    private val permissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestMultiplePermissions()
    ) { permissions ->
        val granted = permissions.values.all { it }
        if (granted) {
            verifyBluetoothEnabledAndShowDevices()
        } else {
            appendLog("PERMISO DENEGADO: Se requiere permiso Bluetooth para conectar dispositivos.")
            Toast.makeText(this, "Debes conceder los permisos de Bluetooth", Toast.LENGTH_LONG).show()
        }
    }

    private val enableBluetoothLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            showRealPairedDevicesDialog()
        } else {
            appendLog("BT -> El usuario canceló el encendido de Bluetooth.")
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        securityManager = SecurityManager(this)
        initViews()

        btController = BluetoothController(
            context = this,
            securityManager = securityManager,
            onDataReceived = { encryptedFrame -> handleIncomingTelemetry(encryptedFrame) },
            onConnectionStateChanged = { connected, msg ->
                tvBtStatus.text = "Estado: $msg"
                if (connected) {
                    tvBtStatus.setTextColor(Color.parseColor("#2E7D32"))
                    btnConnectBt.text = "Desconectar Dispositivo Bluetooth"
                    btnConnectBt.setBackgroundColor(Color.parseColor("#C62828"))
                } else {
                    tvBtStatus.setTextColor(Color.parseColor("#C62828"))
                    btnConnectBt.text = "Conectar Dispositivo Bluetooth"
                    btnConnectBt.setBackgroundColor(Color.parseColor("#6200EE"))
                    tvRainState.text = "Sensor de Lluvia: Sin conexión"
                    tvRainState.setTextColor(Color.parseColor("#546E7A"))
                    tvServoState.text = "Servomotor (Tendedero): Sin conexión"
                    tvBuzzerState.text = "Bocina de Alerta: Apagada"
                }
                appendLog("BT -> $msg")
            }
        )
    }

    private fun initViews() {
        layoutLogin = findViewById(R.id.layoutLogin)
        layoutRegister = findViewById(R.id.layoutRegister)
        layoutDashboard = findViewById(R.id.layoutDashboard)
        tvBtStatus = findViewById(R.id.tvBtStatus)
        btnConnectBt = findViewById(R.id.btnConnectBt)
        tvRainState = findViewById(R.id.tvRainState)
        tvServoState = findViewById(R.id.tvServoState)
        tvBuzzerState = findViewById(R.id.tvBuzzerState)
        tvAuditLog = findViewById(R.id.tvAuditLog)

        val etUser = findViewById<EditText>(R.id.etUser)
        val etPin = findViewById<EditText>(R.id.etPin)

        val etNewUser = findViewById<EditText>(R.id.etNewUser)
        val etNewPin = findViewById<EditText>(R.id.etNewPin)
        val etConfirmPin = findViewById<EditText>(R.id.etConfirmPin)

        // Navegación entre Login y Registro
        findViewById<Button>(R.id.btnGoToRegister).setOnClickListener {
            etPin.text.clear()
            layoutLogin.visibility = View.GONE
            layoutRegister.visibility = View.VISIBLE
        }

        findViewById<Button>(R.id.btnCancelRegister).setOnClickListener {
            etNewUser.text.clear()
            etNewPin.text.clear()
            etConfirmPin.text.clear()
            layoutRegister.visibility = View.GONE
            layoutLogin.visibility = View.VISIBLE
        }

        // Registro de usuario con cifrado ISO 27000
        findViewById<Button>(R.id.btnSaveUser).setOnClickListener {
            val newUserText = etNewUser.text.toString()
            val (success, message) = securityManager.registerUser(
                rawUser = newUserText,
                rawPin = etNewPin.text.toString(),
                confirmPin = etConfirmPin.text.toString()
            )

            Toast.makeText(this, message, Toast.LENGTH_LONG).show()

            if (success) {
                val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
                pendingLogs.add("[$time] REGISTRO -> Usuario '${newUserText.trim().lowercase()}' cifrado en bóveda AES-256")

                etUser.setText(newUserText.trim().lowercase())
                etNewUser.text.clear()
                etNewPin.text.clear()
                etConfirmPin.text.clear()

                layoutRegister.visibility = View.GONE
                layoutLogin.visibility = View.VISIBLE
            }
        }

        // Inicio de sesión con defensa contra fuerza bruta
        findViewById<Button>(R.id.btnLogin).setOnClickListener {
            val remainingSec = securityManager.getRemainingLockoutSeconds()
            if (remainingSec > 0) {
                Toast.makeText(
                    this,
                    "BLOQUEO ANTI-FUERZA BRUTA: Espere $remainingSec segundos",
                    Toast.LENGTH_LONG
                ).show()
                return@setOnClickListener
            }

            val loggedUser = etUser.text.toString().trim().lowercase()
            if (securityManager.authenticate(loggedUser, etPin.text.toString())) {
                etPin.text.clear()
                btController.disconnect(notify = true)
                layoutLogin.visibility = View.GONE
                layoutDashboard.visibility = View.VISIBLE

                if (pendingLogs.isNotEmpty()) {
                    pendingLogs.forEach { tvAuditLog.append("$it\n") }
                    pendingLogs.clear()
                }
                appendLog("AUTH -> Sesión iniciada por '$loggedUser' (SHA-256 + Salt + AES-256)")
            } else {
                etPin.text.clear()
                val newLockout = securityManager.getRemainingLockoutSeconds()
                if (newLockout > 0) {
                    Toast.makeText(
                        this,
                        "¡Alerta de Fuerza Bruta! Acceso bloqueado por $newLockout segundos.",
                        Toast.LENGTH_LONG
                    ).show()
                } else {
                    val left = securityManager.getRemainingAttempts()
                    Toast.makeText(
                        this,
                        "Credenciales incorrectas. Intentos restantes: $left de 3",
                        Toast.LENGTH_SHORT
                    ).show()
                }
            }
        }

        // Botón real de conexión / desconexión Bluetooth
        btnConnectBt.setOnClickListener {
            if (btController.isNodeConnected()) {
                btController.disconnect(notify = true)
            } else {
                checkBluetoothPermissionsAndConnect()
            }
        }

        findViewById<Button>(R.id.btnExtend).setOnClickListener {
            if (!ensureConnected()) return@setOnClickListener
            btController.sendCommand("CMD:EXTEND", lifecycleScope) { cipher ->
                appendLog("TX [AES:${cipher.take(14)}...] -> Extender tendedero")
            }
        }

        findViewById<Button>(R.id.btnRetract).setOnClickListener {
            if (!ensureConnected()) return@setOnClickListener
            btController.sendCommand("CMD:RETRACT", lifecycleScope) { cipher ->
                appendLog("TX [AES:${cipher.take(14)}...] -> Resguardar ropa")
            }
        }

        findViewById<Button>(R.id.btnAutoMode).setOnClickListener {
            if (!ensureConnected()) return@setOnClickListener
            btController.sendCommand("CMD:AUTO", lifecycleScope) { cipher ->
                appendLog("TX [AES:${cipher.take(14)}...] -> Modo automático activado")
            }
        }

        findViewById<Button>(R.id.btnMuteBuzzer).setOnClickListener {
            if (!ensureConnected()) return@setOnClickListener
            btController.sendCommand("CMD:MUTE", lifecycleScope) { cipher ->
                appendLog("TX [AES:${cipher.take(14)}...] -> Bocina silenciada")
            }
        }

        findViewById<Button>(R.id.btnLogout).setOnClickListener {
            btController.disconnect(notify = true)
            layoutDashboard.visibility = View.GONE
            layoutLogin.visibility = View.VISIBLE
            tvAuditLog.text = ""
        }
    }

    private fun ensureConnected(): Boolean {
        if (!btController.isNodeConnected()) {
            Toast.makeText(this, "Conecta primero un dispositivo Bluetooth activo", Toast.LENGTH_SHORT).show()
            return false
        }
        return true
    }

    private fun checkBluetoothPermissionsAndConnect() {
        if (!btController.isBluetoothSupported()) {
            Toast.makeText(this, "Este dispositivo no cuenta con hardware Bluetooth", Toast.LENGTH_LONG).show()
            appendLog("ERROR -> Hardware Bluetooth no disponible en este equipo.")
            return
        }

        val requiredPermissions = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            arrayOf(Manifest.permission.BLUETOOTH_CONNECT, Manifest.permission.BLUETOOTH_SCAN)
        } else {
            arrayOf(Manifest.permission.ACCESS_FINE_LOCATION)
        }

        val missing = requiredPermissions.filter {
            ContextCompat.checkSelfPermission(this, it) != PackageManager.PERMISSION_GRANTED
        }

        if (missing.isEmpty()) {
            verifyBluetoothEnabledAndShowDevices()
        } else {
            permissionLauncher.launch(missing.toTypedArray())
        }
    }

    @SuppressLint("MissingPermission")
    private fun verifyBluetoothEnabledAndShowDevices() {
        if (!btController.isBluetoothEnabled()) {
            val enableIntent = Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE)
            enableBluetoothLauncher.launch(enableIntent)
            return
        }
        showRealPairedDevicesDialog()
    }

    @SuppressLint("MissingPermission")
    private fun showRealPairedDevicesDialog() {
        val devices = btController.getPairedDevices()
        if (devices.isEmpty()) {
            AlertDialog.Builder(this)
                .setTitle("Sin dispositivos vinculados")
                .setMessage("No hay dispositivos Bluetooth emparejados en este teléfono. Vincúlalo primero en los ajustes de Android.")
                .setPositiveButton("Abrir Ajustes Bluetooth") { _, _ ->
                    startActivity(Intent(Settings.ACTION_BLUETOOTH_SETTINGS))
                }
                .setNegativeButton("Cancelar", null)
                .show()
            return
        }

        val deviceLabels = devices.map { device ->
            val name = device.name ?: "Dispositivo desconocido"
            "$name\nMAC: ${device.address}"
        }.toTypedArray()

        AlertDialog.Builder(this)
            .setTitle("Selecciona Dispositivo Bluetooth")
            .setItems(deviceLabels) { _, index ->
                val selectedDevice = devices[index]
                securityManager.saveLastDeviceMac(selectedDevice.address)
                btController.connect(selectedDevice, lifecycleScope)
            }
            .setNegativeButton("Cancelar", null)
            .show()
    }

    private fun handleIncomingTelemetry(encryptedFrame: String) {
        val decryptedFrame = securityManager.decryptData(encryptedFrame)
        if (decryptedFrame == null) {
            appendLog("ISO 27000 ALERTA -> Paquete rechazado: firma AES-256-GCM inválida")
            return
        }

        val data = securityManager.validateTelemetryFrame(decryptedFrame)
        if (data == null) {
            appendLog("ISO 27000 ALERTA -> Trama corrupta descartada: $decryptedFrame")
            return
        }

        val isRaining = data["rain"] == 1
        val isRetracted = data["servo"] == 1
        val isBuzzerOn = data["buzzer"] == 1

        tvRainState.text = if (isRaining) "Sensor de Lluvia: ¡LLUVIA DETECTADA!" else "Sensor de Lluvia: Clima Seco"
        tvRainState.setTextColor(if (isRaining) Color.parseColor("#C62828") else Color.parseColor("#2E7D32"))

        tvServoState.text = if (isRetracted) "Servomotor: Ropa Resguardada (180°)" else "Servomotor: Tendedero Extendido (0°)"
        tvBuzzerState.text = if (isBuzzerOn) "Bocina de Alerta: ¡SONANDO!" else "Bocina de Alerta: Silenciada"

        if (isRaining && !lastRainState) {
            appendLog("RX [AES:${encryptedFrame.take(14)}...] -> Lluvia detectada, ropa resguardada")
        }
        lastRainState = isRaining
    }

    private fun appendLog(message: String) {
        val time = SimpleDateFormat("HH:mm:ss", Locale.getDefault()).format(Date())
        tvAuditLog.append("[$time] $message\n")
    }

    override fun onDestroy() {
        super.onDestroy()
        btController.disconnect(notify = false)
    }
}