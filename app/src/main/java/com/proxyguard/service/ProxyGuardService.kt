package com.proxyguard.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.os.IBinder
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import androidx.lifecycle.lifecycleScope
import com.proxyguard.R
import com.proxyguard.proxy.ProxyPool
import com.proxyguard.proxy.ProxyValidator
import com.proxyguard.relay.BridgeSecret
import com.proxyguard.relay.LocalRelayServer
import com.proxyguard.source.SourceParser
import com.proxyguard.ui.MainActivity
import kotlinx.coroutines.*

/**
 * ForegroundService — сердце приложения.
 *
 * Запускает LocalRelayServer и периодически:
 *   1. Обновляет список прокси (каждые UPDATE_INTERVAL_MIN минут)
 *   2. Проверяет здоровье текущего прокси (каждые HEALTH_CHECK_INTERVAL_SEC секунд)
 */
class ProxyGuardService : LifecycleService() {

    private lateinit var relayServer: LocalRelayServer
    private val proxyPool    = ProxyPool()
    private val validator    = ProxyValidator()
    private val sourceParser = SourceParser()

    @Volatile private var isUpdating = false

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, buildNotification("Инициализация..."))

        val bridgeSecret = BridgeSecret.getBytes(this)
        relayServer = LocalRelayServer(PORT, bridgeSecret, proxyPool)
        relayServer.start()

        lifecycleScope.launch {
            // Первое обновление — сразу
            updateProxies()
            // Периодическое обновление
            while (isActive) {
                delay(UPDATE_INTERVAL_MS)
                updateProxies()
            }
        }
    }

    private suspend fun updateProxies() {
        if (isUpdating) return
        isUpdating = true
        updateNotification("Обновление списка прокси...")

        try {
            Log.i(TAG, "Fetching proxy sources...")
            val all = sourceParser.fetchAll { name, count ->
                Log.d(TAG, "Source '$name': $count proxies")
            }

            if (all.isEmpty()) {
                Log.w(TAG, "No proxies fetched from any source")
                updateNotification("Нет прокси. Повтор через $UPDATE_INTERVAL_MIN мин.")
                return
            }

            updateNotification("Проверка ${all.size} прокси...")
            Log.i(TAG, "Validating ${all.size} proxies...")

            val ranked = validator.validateAll(all, batchSize = 20) { done, total ->
                if (done % 40 == 0) updateNotification("Проверка: $done/$total...")
            }

            if (ranked.isEmpty()) {
                Log.w(TAG, "No live proxies found")
                updateNotification("Нет рабочих прокси. Повтор через $UPDATE_INTERVAL_MIN мин.")
                return
            }

            proxyPool.update(ranked)
            val best = ranked.first()
            Log.i(TAG, "Pool updated: ${ranked.size} live. Best: ${best.proxy.server} ${best.pingMs}ms")
            updateNotification("✓ Активен: ${best.proxy.server} (${best.pingMs}ms) | Пул: ${ranked.size}")

        } catch (e: Exception) {
            Log.e(TAG, "Update failed: ${e.message}")
            updateNotification("Ошибка обновления. Повтор через $UPDATE_INTERVAL_MIN мин.")
        } finally {
            isUpdating = false
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_STOP -> stopSelf()
            ACTION_REFRESH -> lifecycleScope.launch { updateProxies() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        relayServer.stop()
        super.onDestroy()
    }

    override fun onBind(intent: Intent): IBinder? {
        super.onBind(intent)
        return null
    }

    // ─── Notification ────────────────────────────────────────────────────────

    private fun updateNotification(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        ensureChannel()

        val openIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val stopIntent = PendingIntent.getService(
            this, 1,
            Intent(this, ProxyGuardService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val refreshIntent = PendingIntent.getService(
            this, 2,
            Intent(this, ProxyGuardService::class.java).setAction(ACTION_REFRESH),
            PendingIntent.FLAG_IMMUTABLE,
        )

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("ProxyGuard")
            .setContentText(text)
            .setContentIntent(openIntent)
            .addAction(0, "Обновить", refreshIntent)
            .addAction(0, "Стоп", stopIntent)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        NotificationChannel(CHANNEL_ID, "ProxyGuard", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "MTProto relay status" }
            .also { nm.createNotificationChannel(it) }
    }

    companion object {
        private const val TAG              = "ProxyGuardService"
        const val PORT                     = 1080
        const val ACTION_STOP              = "com.proxyguard.STOP"
        const val ACTION_REFRESH           = "com.proxyguard.REFRESH"
        private const val NOTIFICATION_ID  = 1001
        private const val CHANNEL_ID       = "proxyguard_status"
        private const val UPDATE_INTERVAL_MIN = 15L
        private const val UPDATE_INTERVAL_MS  = UPDATE_INTERVAL_MIN * 60 * 1000L

        fun start(context: Context) {
            val intent = Intent(context, ProxyGuardService::class.java)
            context.startForegroundService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, ProxyGuardService::class.java).setAction(ACTION_STOP)
            context.startService(intent)
        }
    }
}
