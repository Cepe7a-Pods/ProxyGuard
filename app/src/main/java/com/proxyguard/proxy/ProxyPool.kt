package com.proxyguard.proxy

import android.util.Log

class ProxyPool {

    @Volatile private var sorted: List<MtProtoProxy> = emptyList()
    @Volatile private var failed: Set<String>        = emptySet()
    private val rng = kotlin.random.Random.Default

    @Synchronized
    fun update(ranked: List<RankedProxy>) {
        // Ручные прокси всегда впереди автосписка, внутри каждой группы — по пингу.
        sorted = ranked
            .sortedWith(compareBy({ !it.proxy.isManual }, { it.pingMs }))
            .map { it.proxy }
        failed = emptySet()
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
     */
    fun getForConnection(): MtProtoProxy? {
        val alive = sorted.filter { it.key() !in failed }
        if (alive.isEmpty()) return null
        val manualAlive = alive.filter { it.isManual }
        val candidates = if (manualAlive.isNotEmpty()) manualAlive else alive.take(CONNECTION_SPREAD)
        return candidates[rng.nextInt(candidates.size)]
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
        failed = failed + proxy.key()
        Log.w(TAG, "Marked failed: ${proxy.server}:${proxy.port}. Failed: ${failed.size}/${sorted.size}")
    }

    fun size(): Int            = sorted.size
    fun isEmpty(): Boolean     = sorted.isEmpty()
    fun all(): List<MtProtoProxy> = sorted

    private fun MtProtoProxy.key() = "$server:$port"

    companion object {
        private const val TAG = "ProxyPool"
        private const val CONNECTION_SPREAD = 5
    }
}
