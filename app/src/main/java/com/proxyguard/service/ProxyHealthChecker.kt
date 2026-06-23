package com.proxyguard.service

import android.util.Log
import com.proxyguard.proxy.ProxyPool
import com.proxyguard.proxy.ProxyValidator
import kotlinx.coroutines.*

/**
 * Фоновый health-check текущего лучшего прокси.
 *
 * Каждые [checkIntervalMs] проверяет [ProxyPool.getBest()] через [ProxyValidator].
 * Если прокси мёртв:
 *   1. Помечает его failed в пуле.
 *   2. Вызывает [onProxyFailed] — сервис обновляет статус и, если пул пуст,
 *      инициирует полный refresh источников.
 *
 * Запускать через [start], останавливать через [stop] вместе с сервисом.
 */
class ProxyHealthChecker(
    private val proxyPool: ProxyPool,
    private val validator: ProxyValidator,
    private val onProxyFailed: (dead: String, next: String?) -> Unit,
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    fun start() {
        scope.launch {
            delay(INITIAL_DELAY_MS)   // не мешаем первичной валидации пула
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

        // Прокси мёртв
        Log.w(TAG, "${current.server}: health check FAILED → markFailed")
        proxyPool.markFailed(current)

        val next = proxyPool.getBest()
        Log.w(TAG, "Rotated to: ${next?.server ?: "none (pool exhausted)"}")
        onProxyFailed(current.server, next?.server)
    }

    companion object {
        private const val TAG              = "ProxyHealthChecker"
        private const val INITIAL_DELAY_MS = 90_000L    // ждём пока пул наберётся после старта
        private const val CHECK_INTERVAL_MS = 2 * 60 * 1000L  // каждые 2 минуты
    }
}
