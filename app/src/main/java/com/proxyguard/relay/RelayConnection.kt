package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

class RelayConnection(
    private val telegramSocket: Socket,
    private val proxyPool: ProxyPool,
    private val bridgeSecret: ByteArray,
) {

    suspend fun handle() {
        // 1. Читаем 64-байтовый nonce от Telegram
        val init = ByteArray(64)
        try {
            telegramSocket.getInputStream().readFully(init)
        } catch (e: Exception) {
            Log.w(TAG, "Init read failed: ${e.message}")
            telegramSocket.close(); return
        }

        // 2. Проверяем protocol tag
        val (protocolTag, bridgeCipher) = MtProtoObfuscation.fromClientInit(init, bridgeSecret)
        if (!protocolTag.contentEquals(MtProtoObfuscation.PADDED_INTERMEDIATE_TAG)) {
            Log.w(TAG, "Unknown tag: ${protocolTag.toHex()}, drop")
            telegramSocket.close(); return
        }
        telegramSocket.soTimeout = 0

        // 3. Ждём прокси в пуле (на первом запуске пул ещё загружается)
        //    Telegram держит соединение ~90 сек, так что ждём до 80 сек.
        val proxy = waitForProxy() ?: run {
            Log.e(TAG, "Pool empty after wait, closing")
            telegramSocket.close(); return
        }

        // 4. Подключаемся к внешнему прокси
        val proxySocket = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(proxy.server, proxy.port), CONNECT_TIMEOUT)
                soTimeout = 0
            }
        } catch (e: Exception) {
            Log.w(TAG, "Connect to ${proxy.server}:${proxy.port} failed: ${e.message}")
            proxyPool.markFailed(proxy)
            telegramSocket.close(); return
        }

        // 5. Отправляем наш nonce внешнему прокси
        val (initToSend, proxyCipher) = MtProtoObfuscation.generateForProxy(proxy.secretBytes)
        try {
            proxySocket.getOutputStream().write(initToSend)
            proxySocket.getOutputStream().flush()
        } catch (e: Exception) {
            Log.w(TAG, "Proxy init send failed: ${e.message}")
            telegramSocket.close(); proxySocket.close(); return
        }

        Log.i(TAG, "Relay up: Telegram ↔ ${proxy.server}:${proxy.port}")

        // 6. Двунаправленный relay
        try {
            coroutineScope {
                val t2p = launch(Dispatchers.IO) {
                    pipe(telegramSocket.getInputStream(), proxySocket.getOutputStream()) { chunk ->
                        proxyCipher.encrypt(bridgeCipher.decrypt(chunk))
                    }
                }
                val p2t = launch(Dispatchers.IO) {
                    pipe(proxySocket.getInputStream(), telegramSocket.getOutputStream()) { chunk ->
                        bridgeCipher.encrypt(proxyCipher.decrypt(chunk))
                    }
                }
                // Если одно направление упало — закрываем сокеты, это разблокирует read() в другом
                t2p.invokeOnCompletion {
                    p2t.cancel()
                    runCatching { telegramSocket.close() }
                    runCatching { proxySocket.close() }
                }
                p2t.invokeOnCompletion {
                    t2p.cancel()
                    runCatching { telegramSocket.close() }
                    runCatching { proxySocket.close() }
                }
            }
        } catch (_: CancellationException) {
        } catch (e: Exception) {
            Log.w(TAG, "Relay error: ${e.message}")
            proxyPool.markFailed(proxy)
        } finally {
            runCatching { telegramSocket.close() }
            runCatching { proxySocket.close() }
            Log.d(TAG, "Relay closed: ${proxy.server}:${proxy.port}")
        }
    }

    /** Ждём пока пул заполнится. Возвращает null если так и не дождались. */
    private suspend fun waitForProxy() = withTimeoutOrNull(POOL_WAIT_TIMEOUT_MS) {
        while (proxyPool.isEmpty()) {
            Log.d(TAG, "Pool empty, waiting for proxies to load...")
            delay(POOL_POLL_INTERVAL_MS)
        }
        proxyPool.getBest()
    }

    private fun pipe(from: InputStream, to: OutputStream, transform: (ByteArray) -> ByteArray) {
        val buf = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(transform(buf.copyOfRange(0, n)))
                to.flush()
            }
        } catch (_: Exception) { }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG                 = "RelayConnection"
        private const val CONNECT_TIMEOUT     = 10_000
        private const val BUFFER_SIZE         = 8192
        private const val POOL_WAIT_TIMEOUT_MS = 80_000L   // ждём до 80 сек
        private const val POOL_POLL_INTERVAL_MS = 2_000L   // проверяем каждые 2 сек
    }
}

fun InputStream.readFully(buf: ByteArray) {
    var off = 0
    while (off < buf.size) {
        val n = read(buf, off, buf.size - off)
        if (n < 0) throw java.io.EOFException("Stream ended at $off/${buf.size}")
        off += n
    }
}
