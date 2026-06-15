package com.proxyguard.proxy

import android.util.Log

/**
 * Потокобезопасный пул прокси, отсортированных по пингу.
 *
 * Используем @Volatile + synchronized для простоты и надёжности.
 * Писатель один (сервис обновления), читателей много (relay-соединения).
 */
class ProxyPool {

    @Volatile private var sorted: List<MtProtoProxy> = emptyList()
    @Volatile private var failed: Set<String>        = emptySet()

    /** Полная замена пула после валидации */
    @Synchronized
    fun update(ranked: List<RankedProxy>) {
        sorted = ranked.sortedBy { it.pingMs }.map { it.proxy }
        failed = emptySet()
        Log.i(TAG, "Pool updated: ${sorted.size} proxies. Best: ${sorted.firstOrNull()?.server}")
        sorted.take(3).forEachIndexed { i, p ->
            val ping = ranked.find { it.proxy == p }?.pingMs
            Log.d(TAG, "  #${i + 1}: ${p.server}:${p.port}  ping=${ping}ms")
        }
    }

    /** Лучший живой прокси (не в списке упавших) */
    fun getBest(): MtProtoProxy? = sorted.firstOrNull { it.key() !in failed }

    /** Помечаем прокси как нерабочий — следующий getBest() вернёт другой */
    @Synchronized
    fun markFailed(proxy: MtProtoProxy) {
        failed = failed + proxy.key()
        Log.w(TAG, "Marked failed: ${proxy.server}:${proxy.port}. Failed count: ${failed.size}/${sorted.size}")
    }

    fun size(): Int      = sorted.size
    fun isEmpty(): Boolean = sorted.isEmpty()
    fun all(): List<MtProtoProxy> = sorted

    private fun MtProtoProxy.key() = "$server:$port"

    companion object { private const val TAG = "ProxyPool" }
}
