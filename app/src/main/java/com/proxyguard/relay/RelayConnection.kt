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
        // Zero-copy: каждый из двух pipe() выделяет 3 буфера по BUFFER_SIZE ОДИН РАЗ
        // и переиспользует их на протяжении всей жизни соединения.
        // До этого фикса pipe создавал 3 новых ByteArray на КАЖДЫЙ чанк:
        //   copyOfRange + Cipher.update (×2) = 3 аллокации × 8KB × ~500 чанков/сек = GC death.
        //
        // Кто завершился первым — тот инициатор обрыва:
        //   proxy: (p→t) → прокси умер → markFailed
        //   telegram: (t→p) → Telegram закрыл сам → прокси живой
        //
        val firstTerminator = AtomicReference<String?>(null)

        try {
            coroutineScope {
                val t2p = launch(Dispatchers.IO) {
                    // Telegram → ProxyGuard: decrypt bridge, encrypt proxy
                    val (end, msg) = pipe(
                        from   = telegramSocket.getInputStream(),
                        to     = proxyLink.output,
                        step1  = bridgeCipher::decryptInto,   // снять bridge-шифрование
                        step2  = proxyCipher::encryptInto,    // наложить proxy-шифрование
                    )
                    val isFirst = firstTerminator.compareAndSet(null, "telegram:$end")
                    Log.d(TAG, "${proxy.server}: t→p $end${if (isFirst) " [init]" else ""}${msg?.let { " — $it" } ?: ""}")
                }
                val p2t = launch(Dispatchers.IO) {
                    // Proxy → Telegram: decrypt proxy, encrypt bridge
                    val (end, msg) = pipe(
                        from   = proxyLink.input,
                        to     = telegramSocket.getOutputStream(),
                        step1  = proxyCipher::decryptInto,    // снять proxy-шифрование
                        step2  = bridgeCipher::encryptInto,   // наложить bridge-шифрование
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

        val term = firstTerminator.get() ?: "unknown"
        when {
            term.startsWith("proxy:") -> {
                Log.w(TAG, "Relay ended: ${proxy.server} closed first ($term) → markFailed")
                proxyPool.markFailed(proxy)
            }
            term.startsWith("telegram:") -> {
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
     * Zero-copy relay pipe.
     *
     * Выделяет 3 буфера по [BUFFER_SIZE] ОДИН раз при запуске.
     * На каждом чанке вызывает [step1] и [step2] — Cipher.update(in,off,len,out,off) —
     * которые пишут результат напрямую в предоставленный буфер без аллокаций.
     *
     * Итого: 0 аллокаций на чанк вместо 3 × 8KB при старом подходе.
     *
     * @param step1  первое криптопреобразование: (input, len, output) → Unit
     * @param step2  второе криптопреобразование: (input, len, output) → Unit
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
        proxyPool.getBest()   // всегда лучший по ping — load-spread здесь противопоказан
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG             = "RelayConnection"
        private const val CONNECT_TIMEOUT = 5_000
        private const val BUFFER_SIZE     = 16_384   // 8KB → 16KB: меньше read() вызовов при видео
        private const val POOL_WAIT_MS    = 30_000L
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
