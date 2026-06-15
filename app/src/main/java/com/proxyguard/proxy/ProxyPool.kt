package com.proxyguard.proxy

import android.util.Log
import java.util.concurrent.atomic.AtomicReference

/**
 * Потокобезопасный пул прокси, отсортированных по пингу.
 * При падении прокси — помечаем как плохой, используем следующий.
 */
class ProxyPool {

    private val state = AtomicReference(State())

    data class State(
        val sorted: List<MtProtoProxy> = emptyList(),
        val failed: Set<String> = emptySet(),  // server:port
    )

    /** Обновляем пул после очередной валидации */
    fun update(ranked: List<RankedProxy>) {
        val sorted = ranked.sortedBy { it.pingMs }.map { it.proxy }
        state.updateAndGet { it.copy(sorted = sorted, failed = emptySet()) }
        Log.i(TAG, "Pool updated: ${sorted.size} proxies")
        sorted.take(3).forEachIndexed { i, p ->
            Log.d(TAG, "  #${i+1}: ${p.server}:${p.port} (${ranked.find { r -> r.proxy == p }?.pingMs}ms)")
        }
    }

    /** Лучший доступный прокси (не в списке failed) */
    fun getBest(): MtProtoProxy? {
        val s = state.get()
        return s.sorted.firstOrNull { it.key() !in s.failed }
    }

    /** Помечаем прокси как упавший — следующий getBest() вернёт другой */
    fun markFailed(proxy: MtProtoProxy) {
        state.updateAndGet { it.copy(failed = it.failed + proxy.key()) }
        Log.w(TAG, "Proxy marked failed: ${proxy.server}:${proxy.port}")
    }

    fun size(): Int = state.get().sorted.size
    fun isEmpty(): Boolean = size() == 0

    private fun MtProtoProxy.key() = "$server:$port"

    companion object { private const val TAG = "ProxyPool" }
}

private fun <T> AtomicReference<T>.updateAndGet(update: (T) -> T): T {
    while (true) {
        val current = get()
        val next = update(current)
        if (compareAndSet(current, next)) return next
    }
}
