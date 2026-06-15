package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.ServerSocket

/**
 * Локальный TCP-сервер на localhost:1080.
 * Принимает входящие соединения от Telegram (настроен как MTProto прокси)
 * и для каждого запускает RelayConnection.
 */
class LocalRelayServer(
    private val port: Int = 1080,
    private val bridgeSecret: ByteArray,
    private val proxyPool: ProxyPool,
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())

    @Volatile
    private var serverSocket: ServerSocket? = null

    @Volatile
    var isRunning: Boolean = false
        private set

    fun start() {
        if (isRunning) {
            Log.w(TAG, "Already running on port $port")
            return
        }

        val ss = try {
            ServerSocket(port, 50, InetAddress.getLoopbackAddress())
        } catch (e: Exception) {
            Log.e(TAG, "Cannot bind to port $port: ${e.message}")
            return
        }

        serverSocket = ss
        isRunning = true
        Log.i(TAG, "MTProto relay started on 127.0.0.1:$port")

        scope.launch {
            while (isActive && !ss.isClosed) {
                try {
                    val client = withContext(Dispatchers.IO) { ss.accept() }.apply {
                        tcpNoDelay = true
                        soTimeout = INIT_READ_TIMEOUT_MS  // таймаут только для чтения nonce
                    }
                    // Запускаем relay для каждого клиента в отдельной корутине
                    launch {
                        try {
                            RelayConnection(client, proxyPool, bridgeSecret).handle()
                        } catch (e: Exception) {
                            Log.w(TAG, "Relay error: ${e.message}")
                            runCatching { client.close() }
                        }
                    }
                } catch (e: Exception) {
                    if (isActive) Log.e(TAG, "Accept error: ${e.message}")
                }
            }
        }
    }

    fun stop() {
        isRunning = false
        scope.cancel()
        runCatching { serverSocket?.close() }
        Log.i(TAG, "MTProto relay stopped")
    }

    companion object {
        private const val TAG = "LocalRelayServer"
        private const val INIT_READ_TIMEOUT_MS = 15_000
    }
}
