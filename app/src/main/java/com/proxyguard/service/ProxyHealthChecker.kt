package com.proxyguard.service

import android.util.Log
import com.proxyguard.proxy.ProxyPool
import com.proxyguard.proxy.ProxyValidator
import kotlinx.coroutines.*

/**
 * Фоновая проверка текущего лучшего прокси каждые [CHECK_INTERVAL_MS].
 *
 * Использует [ProxyPool.softFail] вместо [ProxyPool.markFailed]:
 *   - 1-й провал → прокси временно выводится из ротации (вдруг разовый сетевой сбой)
 *   - 2-й провал подряд → прокси удаляется из пула, [onProxyFailed] вызывается
 *
 * Счётчики soft-fail сбрасываются при каждом pool.update() (полная ре-валидация).
 */
class ProxyHealthChecker(
    private val proxyPool: ProxyPool,
    private val validator: ProxyValidator,
    private val onProxyFailed: (dead: String, next: String?) -> Unit,
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun start() {
        scope.launch {
            delay(INITIAL_DELAY_MS)
            while (isActive) {
                runCheck()
                delay(CHECK_INTERVAL_MS)
            }
        }
        Log.i(TAG, "Health checker started (interval=${CHECK_INTERVAL_MS / 1000}s)")
    }

    fun stop() {
        scope.cancel()
        Log.i(TAG, "Health checker stopped")
    }

    private suspend fun runCheck() {
        val current = proxyPool.getBest() ?: return
        Log.d(TAG, "Checking ${current.server}...")

        val ping = validator.validate(current)
        if (ping != null) {
            Log.d(TAG, "${current.server}: OK ${ping}ms")
            return
        }

        // Прокси не ответил — мягкий отказ (с учётом счётчика повторов)
        Log.w(TAG, "${current.server}: health check FAILED → softFail")
        val evicted = proxyPool.softFail(current)

        if (evicted) {
            // Прокси удалён из пула (2-й провал подряд) — оповещаем сервис
            val next = proxyPool.getBest()
            Log.w(TAG, "Evicted from pool: ${current.server}. Next: ${next?.server ?: "none"}")
            onProxyFailed(current.server, next?.server)
        } else {
            // Первый провал — прокси временно недоступен, ждём следующей проверки
            Log.i(TAG, "${current.server}: suspended (1st soft-fail), will retry in ${CHECK_INTERVAL_MS / 1000}s")
        }
    }

    companion object {
        private const val TAG               = "ProxyHealthChecker"
        private const val INITIAL_DELAY_MS  = 90_000L          // не мешаем первичной валидации
        private const val CHECK_INTERVAL_MS = 2 * 60 * 1000L   // каждые 2 минуты
    }
}
