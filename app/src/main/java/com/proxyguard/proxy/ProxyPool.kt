package com.proxyguard.proxy

import android.util.Log

class ProxyPool {

    @Volatile private var sorted: List<MtProtoProxy> = emptyList()
    @Volatile private var failed: Set<String>        = emptySet()

    // Счётчик мягких отказов (health-check провалы). При 2+ подряд — удаляем из пула.
    // Очищается при каждом pool.update() (= после полной ре-валидации).
    private val softFailCounts: MutableMap<String, Int> = mutableMapOf()

    private val rng = kotlin.random.Random.Default

    @Synchronized
    fun update(ranked: List<RankedProxy>) {
        sorted = ranked
            .sortedWith(compareBy({ !it.proxy.isManual }, { it.pingMs }))
            .map { it.proxy }
        failed         = emptySet()
        softFailCounts.clear()   // ← полная ре-валидация прошла, сбрасываем soft-fail счётчики
        val manualCount = sorted.count { it.isManual }
        Log.i(TAG, "Pool updated: ${sorted.size} proxies ($manualCount ручных). Best: ${sorted.firstOrNull()?.server}")
    }

    fun getBest(): MtProtoProxy? = sorted.firstOrNull { it.key() !in failed }

    fun getForConnection(): MtProtoProxy? {
        val alive = sorted.filter { it.key() !in failed }
        if (alive.isEmpty()) return null
        val manualAlive = alive.filter { it.isManual }
        val candidates = if (manualAlive.isNotEmpty()) manualAlive else alive.take(CONNECTION_SPREAD)
        return candidates[rng.nextInt(candidates.size)]
    }

    @Synchronized
    fun rotateToNext(): MtProtoProxy? {
        val current = getBest() ?: return null
        failed = failed + current.key()
        Log.i(TAG, "Rotated from ${current.server}. Failed: ${failed.size}/${sorted.size}")
        if (getBest() == null) {
            failed = emptySet()
            Log.i(TAG, "All proxies were failed, resetting rotation")
        }
        return getBest()
    }

    /**
     * Жёсткий отказ — используется relay при реальном обрыве соединения.
     * Немедленно исключает прокси из ротации (до следующего pool.update()).
     */
    @Synchronized
    fun markFailed(proxy: MtProtoProxy) {
        val key = proxy.key()
        failed = failed + key
        softFailCounts.remove(key)   // сбрасываем soft-счётчик — жёсткий > мягкого
        Log.w(TAG, "Hard-failed: ${proxy.server}:${proxy.port}. Failed: ${failed.size}/${sorted.size}")
    }

    /**
     * Мягкий отказ — используется health-checker при неудачной проверке.
     *
     * Логика:
     *   1-й провал → временно убираем из ротации (failed), но оставляем в пуле.
     *               Возможно, был разовый сетевой сбой.
     *   2-й провал подряд → удаляем из пула полностью. При следующем pool.update()
     *               прокси будет заново проверен и вернётся, если снова живой.
     *
     * @return true если прокси был удалён из пула (нужно оповестить сервис)
     */
    @Synchronized
    fun softFail(proxy: MtProtoProxy): Boolean {
        val key = proxy.key()
        val count = (softFailCounts[key] ?: 0) + 1
        softFailCounts[key] = count

        return if (count >= SOFT_FAIL_LIMIT) {
            // Удаляем из пула
            sorted = sorted.filter { it.key() != key }
            softFailCounts.remove(key)
            failed = failed - key
            Log.w(TAG, "Soft-evicted: ${proxy.server}:${proxy.port} (failed $count×). Pool: ${sorted.size}")
            true
        } else {
            // Временно не используем
            failed = failed + key
            Log.w(TAG, "Soft-fail: ${proxy.server}:${proxy.port} ($count/$SOFT_FAIL_LIMIT). Suspended temporarily")
            false
        }
    }

    fun size(): Int               = sorted.size
    fun isEmpty(): Boolean        = sorted.isEmpty()
    fun all(): List<MtProtoProxy> = sorted

    private fun MtProtoProxy.key() = "$server:$port"

    companion object {
        private const val TAG              = "ProxyPool"
        private const val CONNECTION_SPREAD = 5
        private const val SOFT_FAIL_LIMIT  = 2   // 2 провала подряд → удалить из пула
    }
}
