package com.proxyguard.proxy

import android.util.Log

class ProxyPool {

    @Volatile private var sorted: List<MtProtoProxy> = emptyList()
    @Volatile private var failed: Set<String>        = emptySet()

    @Synchronized
    fun update(ranked: List<RankedProxy>) {
        sorted = ranked.sortedBy { it.pingMs }.map { it.proxy }
        failed = emptySet()
        Log.i(TAG, "Pool updated: ${sorted.size} proxies. Best: ${sorted.firstOrNull()?.server}")
    }

    /** Лучший живой прокси */
    fun getBest(): MtProtoProxy? = sorted.firstOrNull { it.key() !in failed }

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

    companion object { private const val TAG = "ProxyPool" }
}
