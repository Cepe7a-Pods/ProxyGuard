package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
import com.proxyguard.proxy.ProxyPool
import kotlinx.coroutines.*
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.ssl.SSLSocket

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
        val proxySocket: Socket = try {
            connectToProxy(proxy)
        } catch (e: Exception) {
            Log.w(TAG, "${proxy.server}: connect failed — ${e.message}")
            proxyPool.markFailed(proxy); telegramSocket.close(); return
        }

        // 5. MTProto рукопожатие с прокси (отправляем наш nonce)
        val proxyCipher: MtProtoObfuscation = try {
            val (initToSend, cipher) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
            proxySocket.getOutputStream().write(initToSend)
            proxySocket.getOutputStream().flush()
            cipher
        } catch (e: Exception) {
            Log.w(TAG, "${proxy.server}: nonce send failed — ${e.message}")
            proxyPool.markFailed(proxy)
            telegramSocket.close(); proxySocket.close(); return
        }

        Log.i(TAG, "Relay up: ${proxy.server}:${proxy.port} (${if (proxy.isFakeTls) "TLS" else "dd"})")

        // 6. Двунаправленный relay — одинаковый для dd и ee (TLS прозрачен)
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
        }
    }

    /**
     * dd: обычный TCP Socket
     * ee: SSLSocket с реальным TLS 1.3 (MTProto идёт ВНУТРИ TLS сессии)
     */
    private fun connectToProxy(proxy: MtProtoProxy): Socket {
        return if (!proxy.isFakeTls) {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(proxy.server, proxy.port), CONNECT_TIMEOUT)
                soTimeout = 0
            }
        } else {
            val domain = proxy.tlsDomain ?: proxy.server
            val ssl = ProxyTls.connect(proxy.server, proxy.port, domain, CONNECT_TIMEOUT)
            ssl.soTimeout = TLS_HANDSHAKE_TIMEOUT
            ssl.startHandshake()
            ssl.soTimeout = 0
            ssl.tcpNoDelay = true
            ssl
        }
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
        private const val TLS_HANDSHAKE_TIMEOUT = 8_000
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
