package com.proxyguard.proxy

/**
 * MTProto прокси.
 *
 * Форматы секрета:
 *  dd + 32 hex chars          → simple MTProto с random padding
 *  ee + 32 hex chars + domain → FakeTLS (домен закодирован в hex)
 */
data class MtProtoProxy(
    val server: String,
    val port: Int,
    val secret: String,
    val comment: String = "",
    /** true — добавлен вручную одной ссылкой (доверенный, в приоритете перед авто-пулом) */
    val isManual: Boolean = false,
) {
    val isFakeTls: Boolean
        get() = secret.startsWith("ee", ignoreCase = true)

    /**
     * 16-байтовый ключ обфускации (без prefix).
     * Для dd: secret[2..34] hex → 16 bytes
     * Для ee: secret[2..34] hex → 16 bytes (остаток — домен, не ключ)
     */
    val secretKey: ByteArray
        get() = secret.drop(2).take(32)
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    /** Алиас для обратной совместимости */
    val secretBytes: ByteArray get() = secretKey

    /**
     * SNI-домен для FakeTLS (только для ee-prefix).
     * Закодирован в hex начиная с позиции 34 (2 prefix + 32 key).
     */
    val tlsDomain: String?
        get() {
            if (!isFakeTls) return null
            val domainHex = secret.drop(34)
            if (domainHex.isEmpty()) return server  // fallback: используем сам сервер
            return runCatching {
                domainHex.chunked(2)
                    .map { it.toInt(16).toByte() }
                    .toByteArray()
                    .toString(Charsets.UTF_8)
            }.getOrDefault(server)
        }

    fun toTgLink() = "tg://proxy?server=$server&port=$port&secret=$secret"
}

data class RankedProxy(
    val proxy: MtProtoProxy,
    val pingMs: Long,
)
