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
                        from  = telegramSocket.getInputStream(),
                        to    = proxyLink.output,
                        step1 = bridgeCipher::decryptInto,   // bridge-шифр → plaintext
                        step2 = proxyCipher::encryptInto,    // plaintext → proxy-шифр
                    )
                    val isFirst = firstTerminator.compareAndSet(null, "telegram:$end")
                    Log.d(TAG, "${proxy.server}: t→p $end${if (isFirst) " [init]" else ""}${msg?.let { " — $it" } ?: ""}")
                }
                val p2t = launch(Dispatchers.IO) {
                    val (end, msg) = pipe(
                        from  = proxyLink.input,
                        to    = telegramSocket.getOutputStream(),
                        step1 = proxyCipher::decryptInto,    // proxy-шифр → plaintext
                        step2 = bridgeCipher::encryptInto,   // plaintext → bridge-шифр
                    )
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
                // Прокси закрыл соединение первым — возможен rate-limit, а не гибель.
                // softFail: 1-й раз → убираем из ротации временно,
                //           2-й раз → удаляем из пула (SOFT_FAIL_LIMIT = 2)
                val evicted = proxyPool.softFail(proxy)
                if (evicted) {
                    Log.w(TAG, "Relay ended: ${proxy.server} closed first ($term) → evicted from pool")
                } else {
                    Log.w(TAG, "Relay ended: ${proxy.server} closed first ($term) → suspended (soft-fail)")
                }
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
        link.socket.keepAlive  = true
        return link
    }

    /**
     * Zero-copy relay pipe: 3 буфера выделяются ОДИН РАЗ при старте функции
     * и переиспользуются на всём протяжении соединения.
     *
     * Было: buf.copyOfRange(0,n) + Cipher.update × 2 = 3 новых ByteArray на каждый чанк
     *        → при видео ~1500 аллокаций/сек × 8KB = 12MB/с мусора → GC-паузы → таймауты
     * Стало: 0 аллокаций на чанк
     *
     * @param step1  первый шаг: decrypt (input → mid)
     * @param step2  второй шаг: encrypt (mid → out)
     */
    private fun pipe(
        from:  InputStream,
        to:    OutputStream,
        step1: (ByteArray, Int, ByteArray) -> Unit,
        step2: (ByteArray, Int, ByteArray) -> Unit,
    ): Pair<PipeEnd, String?> {
        val readBuf = ByteArray(BUFFER_SIZE)
        val midBuf  = ByteArray(BUFFER_SIZE)
        val outBuf  = ByteArray(BUFFER_SIZE)
        return try {
            while (true) {
                val n = from.read(readBuf)
                if (n < 0) return Pair(PipeEnd.CLEAN, null)
                step1(readBuf, n, midBuf)
                step2(midBuf,  n, outBuf)
                to.write(outBuf, 0, n)
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
        private const val BUFFER_SIZE     = 16_384   // 8KB → 16KB: меньше read() при видео
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
