package com.example.tendederoiot_auto

import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import kotlinx.coroutines.*
import java.io.BufferedReader
import java.io.IOException
import java.io.InputStreamReader
import java.io.OutputStream
import java.util.UUID

class BluetoothController(
    context: Context,
    private val securityManager: SecurityManager,
    private val onDataReceived: (String) -> Unit,
    private val onConnectionStateChanged: (Boolean, String) -> Unit
) {
    private val bluetoothManager = context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter

    private var socket: BluetoothSocket? = null
    private var outputStream: OutputStream? = null
    private var connectJob: Job? = null
    private var listenJob: Job? = null

    // UUID estándar del perfil de puerto serie (SPP) utilizado por módulos HC-05 / HC-06 / ESP32
    private val sppUuid: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")

    fun isBluetoothSupported(): Boolean = adapter != null

    fun isBluetoothEnabled(): Boolean = adapter?.isEnabled == true

    fun isNodeConnected(): Boolean = socket?.isConnected == true

    @SuppressLint("MissingPermission")
    fun getPairedDevices(): List<BluetoothDevice> {
        return adapter?.bondedDevices?.toList() ?: emptyList()
    }

    @SuppressLint("MissingPermission")
    fun connect(device: BluetoothDevice, scope: CoroutineScope) {
        disconnect(notify = false)
        val deviceLabel = device.name ?: device.address
        onConnectionStateChanged(false, "Conectando vía RFCOMM a $deviceLabel...")

        connectJob = scope.launch(Dispatchers.IO) {
            try {
                adapter?.cancelDiscovery()
                val rfcommSocket = device.createRfcommSocketToServiceRecord(sppUuid)
                rfcommSocket.connect()

                socket = rfcommSocket
                outputStream = rfcommSocket.outputStream

                withContext(Dispatchers.Main) {
                    onConnectionStateChanged(true, "Conectado a $deviceLabel (${device.address})")
                }
                startListening(scope)
            } catch (e: IOException) {
                disconnect(notify = false)
                withContext(Dispatchers.Main) {
                    onConnectionStateChanged(
                        false,
                        "Sin respuesta del dispositivo ($deviceLabel): verifica que esté encendido y al alcance"
                    )
                }
            } catch (se: SecurityException) {
                disconnect(notify = false)
                withContext(Dispatchers.Main) {
                    onConnectionStateChanged(false, "Permiso Bluetooth denegado por el sistema")
                }
            }
        }
    }

    private fun startListening(scope: CoroutineScope) {
        listenJob = scope.launch(Dispatchers.IO) {
            try {
                val input = socket?.inputStream ?: return@launch
                val reader = BufferedReader(InputStreamReader(input, Charsets.UTF_8))

                while (isActive && socket?.isConnected == true) {
                    val line = reader.readLine() ?: break
                    if (line.isNotBlank()) {
                        withContext(Dispatchers.Main) {
                            onDataReceived(line)
                        }
                    }
                }
                withContext(Dispatchers.Main) {
                    disconnect(notify = true)
                }
            } catch (e: IOException) {
                withContext(Dispatchers.Main) {
                    onConnectionStateChanged(false, "Enlace Bluetooth interrumpido")
                    disconnect(notify = false)
                }
            }
        }
    }

    fun sendCommand(plainCmd: String, scope: CoroutineScope, onSent: (String) -> Unit) {
        val currentOut = outputStream
        if (socket?.isConnected != true || currentOut == null) {
            onConnectionStateChanged(false, "Desconectado")
            return
        }

        scope.launch(Dispatchers.IO) {
            try {
                // Cifra el comando con AES-256-GCM antes de transmitirlo por el socket Bluetooth
                val encryptedPayload = securityManager.encryptData(plainCmd)
                currentOut.write("$encryptedPayload\n".toByteArray(Charsets.UTF_8))
                currentOut.flush()

                withContext(Dispatchers.Main) {
                    onSent(encryptedPayload)
                }
            } catch (e: IOException) {
                withContext(Dispatchers.Main) {
                    onConnectionStateChanged(false, "Error al transmitir datos por Bluetooth")
                    disconnect(notify = false)
                }
            }
        }
    }

    fun disconnect(notify: Boolean = true) {
        connectJob?.cancel()
        listenJob?.cancel()
        try {
            outputStream?.close()
        } catch (_: IOException) {
        }
        try {
            socket?.close()
        } catch (_: IOException) {
        }
        outputStream = null
        socket = null

        if (notify) {
            onConnectionStateChanged(false, "Desconectado")
        }
    }
}