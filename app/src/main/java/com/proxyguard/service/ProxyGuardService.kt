package com.proxyguard.service

import android.app.*
import android.content.Context
import android.content.Intent
import android.content.SharedPreferences
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
    private lateinit var prefs: SharedPreferences

    @Volatile private var isUpdating = false

    companion object {
        private const val TAG              = "ProxyGuardService"
        const val PORT                     = 1080
        const val ACTION_STOP              = "com.proxyguard.STOP"
        const val ACTION_REFRESH           = "com.proxyguard.REFRESH"
        const val ACTION_STATUS            = "com.proxyguard.STATUS"
        const val EXTRA_STATUS_TEXT        = "status_text"
        const val EXTRA_POOL_SIZE          = "pool_size"
        const val EXTRA_IS_LOADING         = "is_loading"
        private const val NOTIFICATION_ID  = 1001
        private const val CHANNEL_ID       = "proxyguard_status"
        private const val UPDATE_INTERVAL  = 15 * 60 * 1000L

        // SharedPreferences — единственный источник истины для UI
        private const val PREFS_NAME       = "proxyguard_state"
        const val PREF_RUNNING             = "running"
        const val PREF_STATUS_TEXT         = "status_text"
        const val PREF_POOL_SIZE           = "pool_size"
        const val PREF_IS_LOADING          = "is_loading"

        fun prefs(context: Context): SharedPreferences =
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

        fun isRunning(context: Context) = prefs(context).getBoolean(PREF_RUNNING, false)

        fun start(context: Context) =
            context.startForegroundService(Intent(context, ProxyGuardService::class.java))

        fun stop(context: Context) =
            context.startService(Intent(context, ProxyGuardService::class.java).setAction(ACTION_STOP))

        fun refresh(context: Context) =
            context.startService(Intent(context, ProxyGuardService::class.java).setAction(ACTION_REFRESH))
    }

    override fun onCreate() {
        super.onCreate()
        prefs = prefs(this)
        startForeground(NOTIFICATION_ID, buildNotification("Запуск..."))

        // Помечаем сервис как запущенный
        prefs.edit().putBoolean(PREF_RUNNING, true).apply()

        repository = ProxyRepository(this)
        val bridgeSecret = BridgeSecret.getBytes(this)
        relayServer = LocalRelayServer(PORT, bridgeSecret, proxyPool)
        relayServer.start()

        ProxyUpdateWorker.schedule(this)

        lifecycleScope.launch {
            // Быстрый старт из кэша
            val cached = repository.load()
            if (cached.isNotEmpty()) {
                proxyPool.update(cached)
                val best = cached.first()
                val text = "✓ Кэш: ${best.proxy.server} (${best.pingMs}ms) | Пул: ${cached.size}"
                persistAndBroadcast(text, cached.size, isLoading = false)
                Log.i(TAG, "Loaded ${cached.size} proxies from cache")
            } else {
                // Нет кэша — показываем что идёт загрузка
                persistAndBroadcast("Загрузка прокси...", 0, isLoading = true)
            }

            updateProxies()

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
            persistAndBroadcast("Загрузка источников...", proxyPool.size(), isLoading = true)

            val all = sourceParser.fetchAll()
            if (all.isEmpty()) {
                val text = "⚠ Источники недоступны. Повтор через 15 мин."
                persistAndBroadcast(text, proxyPool.size(), isLoading = false)
                notify(text)
                return
            }

            persistAndBroadcast("Проверка ${all.size} прокси...", proxyPool.size(), isLoading = true)

            val ranked = validator.validateAll(all, batchSize = 20) { done, total ->
                if (done % 40 == 0) {
                    persistAndBroadcast("Проверка: $done/$total...", proxyPool.size(), isLoading = true)
                }
            }

            if (ranked.isEmpty()) {
                val text = "⚠ Нет рабочих прокси. Повтор через 15 мин."
                persistAndBroadcast(text, 0, isLoading = false)
                notify(text)
                return
            }

            proxyPool.update(ranked)
            repository.save(ranked)

            val best = ranked.first()
            val text = "✓ ${best.proxy.server}  ${best.pingMs}ms | Пул: ${ranked.size}"
            persistAndBroadcast(text, ranked.size, isLoading = false)
            notify(text)

        } catch (e: Exception) {
            Log.e(TAG, "Update error: ${e.message}")
            val text = "⚠ Ошибка обновления. Повтор через 15 мин."
            persistAndBroadcast(text, proxyPool.size(), isLoading = false)
            notify(text)
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
        prefs.edit()
            .putBoolean(PREF_RUNNING, false)
            .putString(PREF_STATUS_TEXT, "")
            .putInt(PREF_POOL_SIZE, 0)
            .apply()
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_STATUS_TEXT, "")
            putExtra(EXTRA_POOL_SIZE, 0)
            putExtra(EXTRA_IS_LOADING, false)
        })
        super.onDestroy()
        Log.i(TAG, "Service destroyed")
    }

    override fun onBind(intent: Intent): IBinder? { super.onBind(intent); return null }

    /** Сохраняет состояние в SharedPrefs И шлёт broadcast в UI */
    private fun persistAndBroadcast(text: String, poolSize: Int, isLoading: Boolean) {
        prefs.edit()
            .putString(PREF_STATUS_TEXT, text)
            .putInt(PREF_POOL_SIZE, poolSize)
            .putBoolean(PREF_IS_LOADING, isLoading)
            .apply()
        sendBroadcast(Intent(ACTION_STATUS).apply {
            putExtra(EXTRA_STATUS_TEXT, text)
            putExtra(EXTRA_POOL_SIZE, poolSize)
            putExtra(EXTRA_IS_LOADING, isLoading)
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
            this, 1,
            Intent(this, ProxyGuardService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE,
        )
        val refresh = PendingIntent.getService(
            this, 2,
            Intent(this, ProxyGuardService::class.java).setAction(ACTION_REFRESH),
            PendingIntent.FLAG_IMMUTABLE,
        )
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
