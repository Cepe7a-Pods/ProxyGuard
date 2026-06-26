package com.proxyguard.service

import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
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
    private val onProxyFailed: (dead: MtProtoProxy, next: MtProtoProxy?) -> Unit,
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

        // Прокси не ответил — мягкий отказ:
        //   1-й провал: временно убираем из ротации, ждём следующей проверки
        //   2-й провал подряд: удаляем из пула, уведомляем сервис
        Log.w(TAG, "${current.server}: health check FAILED → softFail")
        val evicted = proxyPool.softFail(current)

        if (evicted) {
            val next = proxyPool.getBest()
            Log.w(TAG, "Evicted: ${current.server}. Next: ${next?.server ?: "none"}")
            onProxyFailed(current, next)
        } else {
            Log.i(TAG, "${current.server}: suspended (soft-fail #1), retry in ${CHECK_INTERVAL_MS / 1000}s")
        }
    }

    companion object {
        private const val TAG              = "ProxyHealthChecker"
        private const val INITIAL_DELAY_MS = 90_000L    // ждём пока пул наберётся после старта
        private const val CHECK_INTERVAL_MS = 2 * 60 * 1000L  // каждые 2 минуты
    }
}
