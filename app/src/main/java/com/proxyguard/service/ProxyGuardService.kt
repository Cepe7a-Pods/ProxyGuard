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
import com.proxyguard.proxy.ProxyRepository
import com.proxyguard.proxy.ProxyPool
import com.proxyguard.proxy.ProxyValidator
import com.proxyguard.relay.BridgeSecret
import com.proxyguard.relay.LocalRelayServer
import com.proxyguard.source.SourceParser
import com.proxyguard.ui.MainActivity
import kotlinx.coroutines.*

class ProxyGuardService : LifecycleService() {

    private lateinit var relayServer: LocalRelayServer
    private val proxyPool    = ProxyPool()
    private val validator    = ProxyValidator()
    private val sourceParser = SourceParser()
    private lateinit var repository: ProxyRepository

    @Volatile private var isUpdating = false

    // Публичный статус для UI
    companion object {
        private const val TAG             = "ProxyGuardService"
        const val PORT                    = 1080
        const val ACTION_STOP             = "com.proxyguard.STOP"
        const val ACTION_REFRESH          = "com.proxyguard.REFRESH"
        const val ACTION_STATUS           = "com.proxyguard.STATUS"
        const val EXTRA_STATUS_TEXT       = "status_text"
        const val EXTRA_POOL_SIZE         = "pool_size"
        private const val NOTIFICATION_ID = 1001
        private const val CHANNEL_ID      = "proxyguard_status"
        private const val UPDATE_INTERVAL = 15 * 60 * 1000L  // 15 минут

        fun start(context: Context) =
            context.startForegroundService(Intent(context, ProxyGuardService::class.java))

        fun stop(context: Context) =
            context.startService(Intent(context, ProxyGuardService::class.java).setAction(ACTION_STOP))

        fun refresh(context: Context) =
            context.startService(Intent(context, ProxyGuardService::class.java).setAction(ACTION_REFRESH))
    }

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, buildNotification("Запуск..."))
        repository = ProxyRepository(this)

        val bridgeSecret = BridgeSecret.getBytes(this)
        relayServer = LocalRelayServer(PORT, bridgeSecret, proxyPool)
        relayServer.start()

        // Планируем WorkManager как резервный механизм
        ProxyUpdateWorker.schedule(this)

        lifecycleScope.launch {
            // Сначала пробуем загрузить кэш — быстрый старт
            val cached = repository.load()
            if (cached.isNotEmpty()) {
                proxyPool.update(cached)
                val best = cached.first()
                notify("✓ Кэш: ${best.proxy.server} (${best.pingMs}ms) | Пул: ${cached.size}")
                Log.i(TAG, "Loaded ${cached.size} proxies from cache")
            }

            // Полное обновление
            updateProxies()

            // Периодическое обновление
            while (isActive) {
                delay(UPDATE_INTERVAL)
                updateProxies()
            }
        }
    }

    private suspend fun updateProxies() {
        if (isUpdating) return
        isUpdating = true

        try {
            notify("Загрузка источников...")
            val all = sourceParser.fetchAll()

            if (all.isEmpty()) {
                notify("⚠ Нет прокси. Повтор через 15 мин.")
                return
            }

            notify("Проверка ${all.size} прокси...")
            val ranked = validator.validateAll(all, batchSize = 20) { done, total ->
                if (done % 60 == 0) notify("Проверка: $done/$total...")
            }

            if (ranked.isEmpty()) {
                notify("⚠ Нет рабочих прокси. Повтор через 15 мин.")
                return
            }

            proxyPool.update(ranked)
            repository.save(ranked)

            val best = ranked.first()
            val text = "✓ ${best.proxy.server}  ${best.pingMs}ms | Пул: ${ranked.size}"
            notify(text)
            broadcastStatus(text, ranked.size)

        } catch (e: Exception) {
            Log.e(TAG, "Update error: ${e.message}")
            notify("⚠ Ошибка обновления. Повтор через 15 мин.")
        } finally {
            isUpdating = false
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        when (intent?.action) {
            ACTION_STOP    -> stopSelf()
            ACTION_REFRESH -> lifecycleScope.launch { updateProxies() }
        }
        return START_STICKY
    }

    override fun onDestroy() {
        relayServer.stop()
        super.onDestroy()
        Log.i(TAG, "Service destroyed")
    }

    override fun onBind(intent: Intent): IBinder? { super.onBind(intent); return null }

    private fun broadcastStatus(text: String, poolSize: Int) {
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_STATUS_TEXT, text)
            putExtra(EXTRA_POOL_SIZE, poolSize)
        })
    }

    private fun notify(text: String) {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun buildNotification(text: String): Notification {
        ensureChannel()
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE)
        val stop = PendingIntent.getService(
            this, 1, Intent(this, ProxyGuardService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE)
        val refresh = PendingIntent.getService(
            this, 2, Intent(this, ProxyGuardService::class.java).setAction(ACTION_REFRESH),
            PendingIntent.FLAG_IMMUTABLE)

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_shield)
            .setContentTitle("ProxyGuard")
            .setContentText(text)
            .setContentIntent(open)
            .addAction(0, "🔄", refresh)
            .addAction(0, "⏹", stop)
            .setOngoing(true)
            .setSilent(true)
            .build()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) != null) return
        NotificationChannel(CHANNEL_ID, "ProxyGuard статус", NotificationManager.IMPORTANCE_LOW)
            .apply { description = "MTProto relay status" }
            .also { nm.createNotificationChannel(it) }
    }
}
