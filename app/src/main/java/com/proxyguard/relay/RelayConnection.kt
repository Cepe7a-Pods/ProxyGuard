package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Обрабатывает одно входящее соединение от Telegram.
 *
 * Жизненный цикл:
 *   1. Читаем 64-байтовый MTProto nonce от Telegram
 *   2. Выводим ключи (bridge secret)
 *   3. Подключаемся к лучшему внешнему прокси
 *   4. Отправляем ему наш nonce (proxy secret)
 *   5. Запускаем двунаправленный relay с перешифрованием
 */
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
            Log.w(TAG, "Failed to read init from Telegram: ${e.message}")
            telegramSocket.close()
            return
        }

        // 2. Выводим ключи из nonce + bridge secret
        val (protocolTag, bridgeCipher) = MtProtoObfuscation.fromClientInit(init, bridgeSecret)

        // Проверяем тег — должен быть padded intermediate
        if (!protocolTag.contentEquals(MtProtoObfuscation.PADDED_INTERMEDIATE_TAG)) {
            Log.w(TAG, "Unknown protocol tag: ${protocolTag.toHex()}, dropping")
            telegramSocket.close()
            return
        }

        // Убираем жёсткий таймаут — соединение может жить долго
        telegramSocket.soTimeout = 0

        // 3. Берём лучший прокси из пула
        val proxy = proxyPool.getBest()
        if (proxy == null) {
            Log.e(TAG, "No proxies available in pool")
            telegramSocket.close()
            return
        }

        // 4. Подключаемся к внешнему прокси
        val proxySocket = try {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(proxy.server, proxy.port), PROXY_CONNECT_TIMEOUT_MS)
                soTimeout = 0
            }
        } catch (e: Exception) {
            Log.w(TAG, "Cannot connect to ${proxy.server}:${proxy.port}: ${e.message}")
            proxyPool.markFailed(proxy)
            telegramSocket.close()
            return
        }

        // 5. Отправляем наш nonce внешнему прокси
        val (initToSend, proxyCipher) = MtProtoObfuscation.generateForProxy(proxy.secretBytes)
        try {
            proxySocket.getOutputStream().write(initToSend)
            proxySocket.getOutputStream().flush()
        } catch (e: Exception) {
            Log.w(TAG, "Cannot send init to proxy: ${e.message}")
            telegramSocket.close()
            proxySocket.close()
            return
        }

        Log.d(TAG, "Relay established: Telegram ↔ ${proxy.server}:${proxy.port}")

        // 6. Двунаправленный relay
        try {
            coroutineScope {
                // Telegram → External Proxy
                val t2p = launch(Dispatchers.IO) {
                    pipe(
                        from = telegramSocket.getInputStream(),
                        to   = proxySocket.getOutputStream(),
                    ) { chunk -> proxyCipher.encrypt(bridgeCipher.decrypt(chunk)) }
                }
                // External Proxy → Telegram
                val p2t = launch(Dispatchers.IO) {
                    pipe(
                        from = proxySocket.getInputStream(),
                        to   = telegramSocket.getOutputStream(),
                    ) { chunk -> bridgeCipher.encrypt(proxyCipher.decrypt(chunk)) }
                }
                // Если одно направление закрылось — завершаем оба
                t2p.invokeOnCompletion { p2t.cancel() }
                p2t.invokeOnCompletion { t2p.cancel() }
            }
        } catch (_: CancellationException) {
            // нормальное завершение через cancel()
        } catch (e: Exception) {
            Log.w(TAG, "Relay error: ${e.message}")
            proxyPool.markFailed(proxy)
        } finally {
            runCatching { telegramSocket.close() }
            runCatching { proxySocket.close() }
            Log.d(TAG, "Relay closed: ${proxy.server}:${proxy.port}")
        }
    }

    private fun pipe(
        from: InputStream,
        to: OutputStream,
        transform: (ByteArray) -> ByteArray,
    ) {
        val buffer = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buffer)
                if (n < 0) break
                val transformed = transform(buffer.copyOfRange(0, n))
                to.write(transformed)
                to.flush()
            }
        } catch (_: Exception) {
            // соединение закрыто с той или другой стороны
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG = "RelayConnection"
        private const val PROXY_CONNECT_TIMEOUT_MS = 10_000
        private const val BUFFER_SIZE = 8192
    }
}

fun InputStream.readFully(buf: ByteArray) {
    var offset = 0
    while (offset < buf.size) {
        val n = read(buf, offset, buf.size - offset)
        if (n < 0) throw java.io.EOFException("Stream ended after $offset/${buf.size} bytes")
        offset += n
    }
}
