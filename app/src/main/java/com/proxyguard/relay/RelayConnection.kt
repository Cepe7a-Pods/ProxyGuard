package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference

class RelayConnection(
    private val telegramSocket: Socket,
    private val proxyPool: ProxyPool,
    private val bridgeSecret: ByteArray,
) {

    /**
     * Результат работы одного pipe-направления.
     * CLEAN  = read() вернул -1 (нормальный EOF, удалённая сторона закрыла соединение)
     * ERROR  = бросил исключение (socket reset, timeout, и т.д.)
     */
    private enum class PipeEnd { CLEAN, ERROR }

    suspend fun handle() {
        // 1. Читаем 64-байтовый init от Telegram
        val init = ByteArray(64)
        try {
            telegramSocket.getInputStream().readFully(init)
        } catch (e: Exception) {
            Log.w(TAG, "Init read failed: ${e.message}")
            telegramSocket.close(); return
        }
        Log.i(TAG, "Init received: 64 bytes from ${telegramSocket.remoteSocketAddress}")

        // 2. Проверяем bridge secret
        val (protocolTag, bridgeCipher) = MtProtoObfuscation.fromClientInit(init, bridgeSecret)
        if (!protocolTag.contentEquals(MtProtoObfuscation.PADDED_INTERMEDIATE_TAG)) {
            Log.w(TAG, "Unknown protocol tag: ${protocolTag.toHex()}")
            telegramSocket.close(); return
        }
        telegramSocket.soTimeout = 0

        // 3. Ждём прокси в пуле
        val proxy = waitForProxy() ?: run {
            Log.e(TAG, "Pool empty after ${POOL_WAIT_MS}ms"); telegramSocket.close(); return
        }

        // 4. Подключаемся к внешнему прокси
        val proxyLink: ProxyTls.Link = try {
            connectToProxy(proxy)
        } catch (e: Exception) {
            Log.w(TAG, "${proxy.server}: connect failed — ${e.message}")
            proxyPool.markFailed(proxy); telegramSocket.close(); return
        }

        // 5. MTProto рукопожатие с прокси
        val proxyCipher: MtProtoObfuscation = try {
            val (initToSend, cipher) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
            proxyLink.output.write(initToSend)
            proxyLink.output.flush()
            cipher
        } catch (e: Exception) {
            Log.w(TAG, "${proxy.server}: nonce send failed — ${e.message}")
            proxyPool.markFailed(proxy)
            telegramSocket.close(); proxyLink.close(); return
        }

        Log.i(TAG, "Relay up: ${proxy.server}:${proxy.port} (${if (proxy.isFakeTls) "TLS" else "dd"})")

        // 6. Двунаправленный relay
        //
        // Логика определения причины обрыва:
        //   Первый pipe, который завершился — ИНИЦИАТОР обрыва.
        //   Если инициатор — сторона proxy (p2t) → прокси умер → markFailed.
        //   Если инициатор — сторона Telegram (t2p) → Telegram закрыл сам → прокси живой.
        //   Второй pipe всегда получает ERROR (мы сами закрываем его сокет в invokeOnCompletion).
        //
        val firstTerminator = AtomicReference<String?>(null)  // "telegram:CLEAN/ERROR" или "proxy:CLEAN/ERROR"

        try {
            coroutineScope {
                val t2p = launch(Dispatchers.IO) {
                    val (end, msg) = pipe(
                        telegramSocket.getInputStream(), proxyLink.output
                    ) { chunk -> proxyCipher.encrypt(bridgeCipher.decrypt(chunk)) }
                    val isFirst = firstTerminator.compareAndSet(null, "telegram:$end")
                    Log.d(TAG, "${proxy.server}: t→p $end${if (isFirst) " [init]" else ""}${msg?.let { " — $it" } ?: ""}")
                }
                val p2t = launch(Dispatchers.IO) {
                    val (end, msg) = pipe(
                        proxyLink.input, telegramSocket.getOutputStream()
                    ) { chunk -> bridgeCipher.encrypt(proxyCipher.decrypt(chunk)) }
                    val isFirst = firstTerminator.compareAndSet(null, "proxy:$end")
                    Log.d(TAG, "${proxy.server}: p→t $end${if (isFirst) " [init]" else ""}${msg?.let { " — $it" } ?: ""}")
                }
                t2p.invokeOnCompletion {
                    p2t.cancel()
                    runCatching { telegramSocket.close() }
                    proxyLink.close()
                }
                p2t.invokeOnCompletion {
                    t2p.cancel()
                    runCatching { telegramSocket.close() }
                    proxyLink.close()
                }
            }
        } catch (_: CancellationException) {
        } catch (e: Exception) {
            Log.w(TAG, "Relay error: ${e.message}")
        } finally {
            runCatching { telegramSocket.close() }
            proxyLink.close()
        }

        // Оцениваем причину завершения
        val term = firstTerminator.get() ?: "unknown"
        when {
            term.startsWith("proxy:") -> {
                // Прокси закрыл соединение первым (EOF или ошибка) — помечаем мёртвым
                Log.w(TAG, "Relay ended: ${proxy.server} closed first ($term) → markFailed")
                proxyPool.markFailed(proxy)
            }
            term.startsWith("telegram:") -> {
                // Telegram закрыл первым — нормально, прокси живой
                Log.i(TAG, "Relay ended: Telegram closed first ($term), proxy ${proxy.server} OK")
            }
            else -> Log.w(TAG, "Relay ended: unknown terminator=$term")
        }
    }

    private fun connectToProxy(proxy: MtProtoProxy): ProxyTls.Link {
        val link = ProxyTls.connect(proxy, CONNECT_TIMEOUT)
        link.socket.soTimeout  = 0
        link.socket.tcpNoDelay = true
        link.socket.keepAlive  = true   // TCP keepalive — OS детектирует мёртвые соединения
        return link
    }

    /**
     * Читает из [from], трансформирует, пишет в [to].
     * @return Pair(PipeEnd, errorMessage?) — CLEAN если read()=-1, ERROR если исключение.
     */
    private fun pipe(
        from: InputStream,
        to: OutputStream,
        transform: (ByteArray) -> ByteArray,
    ): Pair<PipeEnd, String?> {
        val buf = ByteArray(BUFFER_SIZE)
        return try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) return Pair(PipeEnd.CLEAN, null)
                to.write(transform(buf.copyOfRange(0, n)))
                to.flush()
            }
            @Suppress("UNREACHABLE_CODE")
            Pair(PipeEnd.CLEAN, null)
        } catch (e: Exception) {
            Pair(PipeEnd.ERROR, "${e.javaClass.simpleName}: ${e.message}")
        }
    }

    private suspend fun waitForProxy() = withTimeoutOrNull(POOL_WAIT_MS) {
        while (proxyPool.isEmpty()) { delay(POOL_POLL_MS) }
        proxyPool.getForConnection()   // load-spread по ручным прокси, не всегда один и тот же
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG             = "RelayConnection"
        private const val CONNECT_TIMEOUT = 5_000        // 10s → 5s, быстрее детектируем мёртвые
        private const val BUFFER_SIZE     = 8_192
        private const val POOL_WAIT_MS    = 30_000L      // 80s → 30s
        private const val POOL_POLL_MS    = 2_000L
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
