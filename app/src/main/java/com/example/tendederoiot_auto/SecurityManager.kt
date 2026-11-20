package com.example.tendederoiot_auto

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

class SecurityManager(context: Context) {

    private val masterKey = MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build()

    // Bóveda cifrada en disco (Protección de datos en reposo - ISO 27000)
    private val securePrefs: SharedPreferences = EncryptedSharedPreferences.create(
        context,
        "iso27000_secure_vault",
        masterKey,
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
    )

    private val maxAttempts = 3

    init {
        // Crea el usuario administrador por defecto con contraseña robusta si aún no existe
        if (!securePrefs.contains("user_admin_hash")) {
            val salt = generateRandomBase64(16)
            securePrefs.edit()
                .putString("user_admin_salt", salt)
                .putString("user_admin_hash", hashSHA256WithSalt("Admin@1234", salt))
                .apply()
        }

        // Genera la llave maestra AES-256 para comunicaciones IoT si no existe
        if (!securePrefs.contains("iot_aes_key")) {
            val aesSessionKey = generateRandomBase64(32) // 256 bits
            securePrefs.edit()
                .putString("iot_aes_key", aesSessionKey)
                .putInt("failed_attempts", 0)
                .putInt("lockout_level", 0)
                .putLong("lockout_until", 0L)
                .apply()
        }
    }

    private fun generateRandomBase64(numBytes: Int): String {
        val bytes = ByteArray(numBytes)
        SecureRandom().nextBytes(bytes)
        return Base64.encodeToString(bytes, Base64.NO_WRAP)
    }

    private fun hashSHA256WithSalt(input: String, salt: String): String {
        val saltedInput = "$salt:$input"
        val bytes = MessageDigest.getInstance("SHA-256").digest(saltedInput.toByteArray(Charsets.UTF_8))
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // --- REGISTRO SEGURO DE NUEVOS USUARIOS CON CONTRASEÑA ROBUSTA (ISO 27000) ---

    fun registerUser(rawUser: String, rawPassword: String, confirmPassword: String): Pair<Boolean, String> {
        val cleanUser = rawUser.trim().lowercase()

        // 1. Validación de formato de usuario
        if (!Regex("^[a-z0-9_]{3,20}$").matches(cleanUser)) {
            return Pair(false, "El usuario debe tener entre 3 y 20 caracteres (solo letras, números o '_').")
        }

        // 2. Validación de longitud y ausencia de espacios
        if (rawPassword.length < 8 || rawPassword.length > 32) {
            return Pair(false, "La contraseña debe tener entre 8 y 32 caracteres.")
        }

        if (rawPassword.contains(" ")) {
            return Pair(false, "La contraseña no puede contener espacios en blanco.")
        }

        // 3. Validación de complejidad criptográfica (Mayúscula, minúscula, número y símbolo)
        val hasUppercase = Regex(".*[A-Z].*").matches(rawPassword)
        val hasLowercase = Regex(".*[a-z].*").matches(rawPassword)
        val hasDigit = Regex(".*\\d.*").matches(rawPassword)
        val hasSpecial = Regex(".*[^A-Za-z0-9\\s].*").matches(rawPassword)

        if (!hasUppercase || !hasLowercase || !hasDigit || !hasSpecial) {
            return Pair(
                false,
                "Contraseña débil: debe incluir al menos 1 mayúscula, 1 minúscula, 1 número y 1 símbolo especial (@, #, $, %, etc.)."
            )
        }

        // 4. Evitar que la contraseña contenga el nombre de usuario
        if (rawPassword.lowercase().contains(cleanUser)) {
            return Pair(false, "Por seguridad, la contraseña no puede contener el nombre de usuario.")
        }

        // 5. Confirmación de coincidencia
        if (rawPassword != confirmPassword) {
            return Pair(false, "Las contraseñas ingresadas no coinciden.")
        }

        // 6. Verificar que el usuario no exista previamente
        if (securePrefs.contains("user_${cleanUser}_hash")) {
            return Pair(false, "El usuario '$cleanUser' ya se encuentra registrado.")
        }

        // 7. Generar Salt único y almacenar hash SHA-256 en bóveda cifrada AES-256
        val uniqueSalt = generateRandomBase64(16)
        val hashedPassword = hashSHA256WithSalt(rawPassword, uniqueSalt)

        securePrefs.edit()
            .putString("user_${cleanUser}_salt", uniqueSalt)
            .putString("user_${cleanUser}_hash", hashedPassword)
            .apply()

        return Pair(true, "Usuario '$cleanUser' registrado con contraseña segura y cifrado AES-256.")
    }

    // --- DEFENSA CONTRA FUERZA BRUTA PERSISTENTE ---

    fun getRemainingLockoutSeconds(): Long {
        val lockoutUntil = securePrefs.getLong("lockout_until", 0L)
        val diff = lockoutUntil - System.currentTimeMillis()
        return if (diff > 0) (diff / 1000L) + 1 else 0L
    }

    fun isLockedOut(): Boolean = getRemainingLockoutSeconds() > 0L

    fun getRemainingAttempts(): Int {
        val failed = securePrefs.getInt("failed_attempts", 0)
        return (maxAttempts - failed).coerceAtLeast(0)
    }

    fun authenticate(user: String, password: String): Boolean {
        if (isLockedOut()) return false

        val cleanUser = user.trim().lowercase()

        val storedSalt = securePrefs.getString("user_${cleanUser}_salt", null)
        val storedHash = securePrefs.getString("user_${cleanUser}_hash", null)

        val saltToUse = storedSalt ?: "dummy_salt_protection_iso27000"
        val inputHash = hashSHA256WithSalt(password, saltToUse)

        return if (storedHash != null && inputHash == storedHash) {
            securePrefs.edit()
                .putInt("failed_attempts", 0)
                .putInt("lockout_level", 0)
                .putLong("lockout_until", 0L)
                .apply()
            true
        } else {
            val failed = securePrefs.getInt("failed_attempts", 0) + 1
            if (failed >= maxAttempts) {
                val nextLevel = securePrefs.getInt("lockout_level", 0) + 1
                val penaltyMillis = nextLevel * 30_000L // 30s, 60s, 90s...
                securePrefs.edit()
                    .putInt("failed_attempts", 0)
                    .putInt("lockout_level", nextLevel)
                    .putLong("lockout_until", System.currentTimeMillis() + penaltyMillis)
                    .apply()
            } else {
                securePrefs.edit()
                    .putInt("failed_attempts", failed)
                    .apply()
            }
            false
        }
    }

    // --- CIFRADO AES-256-GCM PARA DATOS EN TRÁNSITO ---

    fun encryptData(plainText: String): String {
        val keyBase64 = securePrefs.getString("iot_aes_key", "") ?: ""
        val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
        val secretKey = SecretKeySpec(keyBytes, "AES")

        val iv = ByteArray(12)
        SecureRandom().nextBytes(iv)

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
        val cipherBytes = cipher.doFinal(plainText.toByteArray(Charsets.UTF_8))

        val combined = ByteArray(iv.size + cipherBytes.size)
        System.arraycopy(iv, 0, combined, 0, iv.size)
        System.arraycopy(cipherBytes, 0, combined, iv.size, cipherBytes.size)

        return Base64.encodeToString(combined, Base64.NO_WRAP)
    }

    fun decryptData(encryptedBase64: String): String? {
        return try {
            val keyBase64 = securePrefs.getString("iot_aes_key", "") ?: ""
            val keyBytes = Base64.decode(keyBase64, Base64.NO_WRAP)
            val secretKey = SecretKeySpec(keyBytes, "AES")

            val combined = Base64.decode(encryptedBase64.trim(), Base64.NO_WRAP)
            if (combined.size < 13) return null

            val iv = combined.copyOfRange(0, 12)
            val cipherBytes = combined.copyOfRange(12, combined.size)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, secretKey, GCMParameterSpec(128, iv))
            val plainBytes = cipher.doFinal(cipherBytes)

            String(plainBytes, Charsets.UTF_8)
        } catch (e: Exception) {
            null
        }
    }

    fun saveLastDeviceMac(mac: String) {
        securePrefs.edit().putString("paired_mac", mac).apply()
    }

    fun validateTelemetryFrame(frame: String): Map<String, Int>? {
        val regex = Regex("^<R:([01]);S:([01]);B:([01]);M:([01]);C:(\\d+)>$")
        val match = regex.matchEntire(frame.trim()) ?: return null

        val r = match.groupValues[1].toInt()
        val s = match.groupValues[2].toInt()
        val b = match.groupValues[3].toInt()
        val m = match.groupValues[4].toInt()
        val checksum = match.groupValues[5].toInt()

        if (r + s + b + m != checksum) return null

        return mapOf("rain" to r, "servo" to s, "buzzer" to b, "mode" to m)
    }
}