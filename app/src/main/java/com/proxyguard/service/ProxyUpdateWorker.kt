package com.proxyguard.service

import android.content.Context
import android.util.Log
import androidx.work.*
import com.proxyguard.proxy.ProxyRepository
import com.proxyguard.proxy.ProxyValidator
import com.proxyguard.source.SourceParser
import java.util.concurrent.TimeUnit

/**
 * WorkManager worker — резервный механизм обновления прокси.
 *
 * Зачем: MIUI/EMUI/etc могут убить ForegroundService.
 * WorkManager гарантирует выполнение даже после kill.
 *
 * Запускается каждые 30 минут, сохраняет свежий список в ProxyRepository.
 * При следующем старте сервиса он берёт кэш из репозитория — без долгого ожидания.
 */
class ProxyUpdateWorker(
    private val context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        Log.i(TAG, "Starting background proxy update")

        return try {
            val sourceParser = SourceParser()
            val validator    = ProxyValidator(connectTimeoutMs = 6_000, readTimeoutMs = 6_000)
            val repository   = ProxyRepository(context)

            val proxies = sourceParser.fetchAll()
            if (proxies.isEmpty()) {
                Log.w(TAG, "No proxies fetched")
                return Result.retry()
            }

            val ranked = validator.validateAll(proxies, batchSize = 15)
            if (ranked.isEmpty()) {
                Log.w(TAG, "No live proxies found")
                return Result.retry()
            }

            repository.save(ranked)
            Log.i(TAG, "Background update done: ${ranked.size} live proxies")
            Result.success()

        } catch (e: Exception) {
            Log.e(TAG, "Worker failed: ${e.message}")
            Result.retry()
        }
    }

    companion object {
        private const val TAG        = "ProxyUpdateWorker"
        private const val WORK_NAME  = "proxy_update_periodic"

        fun schedule(context: Context) {
            val request = PeriodicWorkRequestBuilder<ProxyUpdateWorker>(
                repeatInterval = 30,
                repeatIntervalTimeUnit = TimeUnit.MINUTES,
            )
                .setConstraints(
                    Constraints.Builder()
                        .setRequiredNetworkType(NetworkType.CONNECTED)
                        .build()
                )
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 5, TimeUnit.MINUTES)
                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP,
                request,
            )
            Log.d(TAG, "Periodic work scheduled")
        }

        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
        }
    }
}
