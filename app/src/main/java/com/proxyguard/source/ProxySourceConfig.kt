package com.proxyguard.source

import java.util.UUID

/**
 * Один источник прокси-листа.
 * @param id        UUID — ключ в хранилище
 * @param name      читаемое название
 * @param url       URL для fetch (http/https)
 * @param enabled   включён ли сейчас
 * @param isDefault true = встроенный, нельзя удалить
 * @param lastDdCount сколько dd-прокси нашли в прошлый раз
 * @param lastTestedMs timestamp последней проверки
 */
data class ProxySourceConfig(
    val id: String = UUID.randomUUID().toString(),
    val name: String,
    val url: String,
    val enabled: Boolean = true,
    val isDefault: Boolean = false,
    val lastDdCount: Int = -1,          // -1 = ещё не проверяли
    val lastTestedMs: Long = 0L,
) {
    val shortUrl: String get() {
        return url.removePrefix("https://").removePrefix("http://")
            .let { if (it.length > 55) it.take(52) + "…" else it }
    }
}
