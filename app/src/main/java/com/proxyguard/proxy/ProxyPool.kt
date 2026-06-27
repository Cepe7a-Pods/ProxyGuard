package com.proxyguard.proxy

import android.util.Log

class ProxyPool {

    @Volatile private var sorted: List<MtProtoProxy> = emptyList()
    @Volatile private var failed: Set<String>        = emptySet()
    private val rng = kotlin.random.Random.Default
    @Volatile private var connectionRoundRobin: Int  = 0   // для round-robin в getForConnection

    // Счётчик мягких отказов (health-check провалы).
    // Сбрасывается при каждом update() — после полной ре-валидации.
    private val softFailCounts: MutableMap<String, Int> = mutableMapOf()

    @Synchronized
    fun update(ranked: List<RankedProxy>) {
        // Ручные прокси всегда впереди автосписка, внутри каждой группы — по пингу.
        sorted = ranked
            .sortedWith(compareBy({ !it.proxy.isManual }, { it.pingMs }))
            .map { it.proxy }
        failed = emptySet()
        softFailCounts.clear()          // ← сбрасываем soft-fail счётчики после ре-валидации
        val manualCount = sorted.count { it.isManual }
        Log.i(TAG, "Pool updated: ${sorted.size} proxies ($manualCount ручных). Best: ${sorted.firstOrNull()?.server}")
    }

    /** Лучший живой прокси (для статуса на главном экране и ручной кнопки "следующий") */
    fun getBest(): MtProtoProxy? = sorted.firstOrNull { it.key() !in failed }

    /**
     * Прокси для НОВОГО relay-соединения.
     * Если есть хоть один живой РУЧНОЙ прокси — выбираем случайный СРЕДИ РУЧНЫХ
     * (не обязательно среди них только один: если их несколько, всё равно
     * спред нужен, чтобы не упереться в лимит соединений с одного IP).
     * Авто-пул из источников — только когда ручных не осталось вообще.
     *
     * Использует round-robin (не random): гарантирует равномерное распределение.
     * Без round-robin вероятность N подряд к одному прокси = (1/k)^(N-1) ненулевая
     * и при всплеске соединений Telegram это случается → лимит прокси → разрыв.
     */
    fun getForConnection(): MtProtoProxy? {
        val alive = sorted.filter { it.key() !in failed }
        if (alive.isEmpty()) return null
        val manualAlive = alive.filter { it.isManual }
        val candidates = if (manualAlive.isNotEmpty()) manualAlive else alive.take(CONNECTION_SPREAD)
        val idx = (connectionRoundRobin++ % candidates.size).coerceAtLeast(0)
        return candidates[idx]
    }

    /** Принудительно ротировать: пометить текущий как failed → следующий getBest() вернёт другой */
    @Synchronized
    fun rotateToNext(): MtProtoProxy? {
        val current = getBest() ?: return null
        failed = failed + current.key()
        Log.i(TAG, "Rotated from ${current.server}. Failed: ${failed.size}/${sorted.size}")
        // Если все помечены — сбрасываем (начинаем круг заново)
        if (getBest() == null) {
            failed = emptySet()
            Log.i(TAG, "All proxies were failed, resetting rotation")
        }
        return getBest()
    }

    @Synchronized
    fun markFailed(proxy: MtProtoProxy) {
        val key = proxy.key()
        failed = failed + key
        softFailCounts.remove(key)      // relay-смерть сбрасывает soft-счётчик
        Log.w(TAG, "Hard-failed: ${proxy.server}:${proxy.port}. Failed: ${failed.size}/${sorted.size}")
    }

    /**
     * Мягкий отказ — используется health-checker при неудачной проверке.
     *
     * 1-й провал → прокси временно выводится из ротации (added to [failed]),
     *              но остаётся в пуле. Возможно, был разовый сетевой сбой.
     * 2-й провал подряд → прокси удаляется из пула полностью.
     *              При следующем update() он вернётся, если снова пройдёт валидацию.
     *
     * @return true если прокси удалён из пула (нужно уведомить сервис)
     */
    @Synchronized
    fun softFail(proxy: MtProtoProxy): Boolean {
        val key   = proxy.key()
        val count = (softFailCounts[key] ?: 0) + 1
        softFailCounts[key] = count

        return if (count >= SOFT_FAIL_LIMIT) {
            // Удаляем из пула полностью
            sorted = sorted.filter { it.key() != key }
            softFailCounts.remove(key)
            failed = failed - key
            Log.w(TAG, "Soft-evicted: ${proxy.server}:${proxy.port} (failed ${count}×). Pool: ${sorted.size}")
            true
        } else {
            // Временно убираем из ротации
            failed = failed + key
            Log.w(TAG, "Soft-fail: ${proxy.server}:${proxy.port} ($count/$SOFT_FAIL_LIMIT). Suspended temporarily")
            false
        }
    }

    fun size(): Int            = sorted.size
    fun isEmpty(): Boolean     = sorted.isEmpty()
    fun all(): List<MtProtoProxy> = sorted

    private fun MtProtoProxy.key() = "$server:$port"

    companion object {
        private const val TAG             = "ProxyPool"
        private const val CONNECTION_SPREAD = 5
        private const val SOFT_FAIL_LIMIT = 2   // 2 провала подряд → удалить из пула
    }
}
