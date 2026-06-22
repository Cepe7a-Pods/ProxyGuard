package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.Socket

class RelayConnection(
    private val telegramSocket: Socket,
    private val proxyPool: ProxyPool,
    private val bridgeSecret: ByteArray,
) {

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

        // 4. Подключаемся к внешнему прокси (dd: TCP, ee: FakeTLS — см. ProxyTls/FakeTls)
        val proxyLink: ProxyTls.Link = try {
            connectToProxy(proxy)
        } catch (e: Exception) {
            Log.w(TAG, "${proxy.server}: connect failed — ${e.message}")
            proxyPool.markFailed(proxy); telegramSocket.close(); return
        }

        // 5. MTProto рукопожатие с прокси (отправляем наш nonce)
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

        // 6. Двунаправленный relay — одинаковый для dd и ee (framing прозрачен внутри Link)
        try {
            coroutineScope {
                val t2p = launch(Dispatchers.IO) {
                    pipe(telegramSocket.getInputStream(), proxyLink.output) { chunk ->
                        proxyCipher.encrypt(bridgeCipher.decrypt(chunk))
                    }
                }
                val p2t = launch(Dispatchers.IO) {
                    pipe(proxyLink.input, telegramSocket.getOutputStream()) { chunk ->
                        bridgeCipher.encrypt(proxyCipher.decrypt(chunk))
                    }
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
            proxyPool.markFailed(proxy)
        } finally {
            runCatching { telegramSocket.close() }
            proxyLink.close()
        }
    }

    /**
     * dd: обычный TCP Socket.
     * ee: FakeTLS-хендшейк (HMAC-digest в ClientHello.random, см. FakeTls.kt) —
     *     НЕ настоящий TLS, никакого SSLSocket.
     */
    private fun connectToProxy(proxy: MtProtoProxy): ProxyTls.Link {
        val link = ProxyTls.connect(proxy, CONNECT_TIMEOUT)
        link.socket.soTimeout = 0
        link.socket.tcpNoDelay = true
        return link
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

    private suspend fun waitForProxy() = withTimeoutOrNull(POOL_WAIT_MS) {
        while (proxyPool.isEmpty()) { delay(POOL_POLL_MS) }
        proxyPool.getBest()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG                  = "RelayConnection"
        private const val CONNECT_TIMEOUT      = 10_000
        private const val BUFFER_SIZE          = 8_192
        private const val POOL_WAIT_MS         = 80_000L
        private const val POOL_POLL_MS         = 2_000L
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
