package com.proxyguard.relay

import android.content.Context
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import kotlin.random.Random

/**
 * Управляет «мостовым» секретом — это тот самый secret, который пользователь
 * вводит в Telegram один раз (Settings → Proxy → MTProto → Secret).
 *
 * Генерируется при первом запуске, хранится в EncryptedSharedPreferences.
 * Формат: "dd" + 32 hex символа (padded intermediate, 16 случайных байт).
 */
object BridgeSecret {

    private const val PREFS_FILE = "proxyguard_secure"
    private const val KEY_SECRET = "bridge_secret"

    /** Возвращает hex-строку вида "dd0a1b2c..." для показа пользователю */
    fun getHex(context: Context): String = prefs(context).getString(KEY_SECRET, null)
        ?: generate(context)

    /** Возвращает сырые байты секрета (без "dd" префикса) для крипто-операций */
    fun getBytes(context: Context): ByteArray = getHex(context)
        .removePrefix("dd")
        .chunked(2)
        .map { it.toInt(16).toByte() }
        .toByteArray()

    private fun generate(context: Context): String {
        val bytes = Random.Default.nextBytes(16)
        val hex = "dd" + bytes.joinToString("") { "%02x".format(it) }
        prefs(context).edit().putString(KEY_SECRET, hex).apply()
        return hex
    }

    private fun prefs(context: Context) = EncryptedSharedPreferences.create(
        context,
        PREFS_FILE,
        MasterKey.Builder(context).setKeyScheme(MasterKey.KeyScheme.AES256_GCM).build(),
        EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
        EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
    )
}
