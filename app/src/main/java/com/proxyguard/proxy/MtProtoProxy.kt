package com.proxyguard.proxy

/**
 * MTProto прокси. Секрет — hex-строка с префиксом "dd" (random-padded)
 * или "ee" (FakeTLS, поддержка будет добавлена позже).
 */
data class MtProtoProxy(
    val server: String,
    val port: Int,
    val secret: String,          // например "dd0a1b2c3d..."
    val comment: String = "",    // источник/пометка
) {
    /** Сырые байты секрета без префикса */
    val secretBytes: ByteArray
        get() = secret
            .removePrefix("ee")
            .removePrefix("dd")
            .chunked(2)
            .map { it.toInt(16).toByte() }
            .toByteArray()

    val isFakeTls: Boolean get() = secret.startsWith("ee", ignoreCase = true)

    /** Ссылка для ручного добавления в Telegram */
    fun toTgLink(): String =
        "tg://proxy?server=$server&port=$port&secret=$secret"
}

data class RankedProxy(
    val proxy: MtProtoProxy,
    val pingMs: Long,
)
