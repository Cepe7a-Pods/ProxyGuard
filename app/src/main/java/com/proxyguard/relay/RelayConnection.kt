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
        val init = ByteArray(64)
        try {
            telegramSocket.getInputStream().readFully(init)
        } catch (e: Exception) {
            Log.w(TAG, "Init read failed: ${e.message}")
            telegramSocket.close(); return
        }

        val (protocolTag, bridgeCipher) = MtProtoObfuscation.fromClientInit(init, bridgeSecret)
        if (!protocolTag.contentEquals(MtProtoObfuscation.PADDED_INTERMEDIATE_TAG)) {
            Log.w(TAG, "Unknown tag: ${protocolTag.toHex()}")
            telegramSocket.close(); return
        }

        telegramSocket.soTimeout = 0

        val proxy = proxyPool.getBest()
        if (proxy == null) {
            Log.e(TAG, "No proxies available")
            telegramSocket.close(); return
        }

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

        val (initToSend, proxyCipher) = MtProtoObfuscation.generateForProxy(proxy.secretBytes)
        try {
            proxySocket.getOutputStream().write(initToSend)
            proxySocket.getOutputStream().flush()
        } catch (e: Exception) {
            Log.w(TAG, "Proxy init send failed: ${e.message}")
            telegramSocket.close(); proxySocket.close(); return
        }

        Log.d(TAG, "Relay up: Telegram ↔ ${proxy.server}:${proxy.port}")

        // ВАЖНО: блокирующий read() не прерывается отменой корутины.
        // Единственный способ разбудить заблокированный поток — закрыть сокет.
        // Поэтому в invokeOnCompletion закрываем ОБА сокета, а не только отменяем job.
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

                // Когда одно направление упало — закрываем сокеты.
                // Это прерывает блокирующий read() в другом направлении.
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
            // нормальное завершение
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
        val buf = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                to.write(transform(buf.copyOfRange(0, n)))
                to.flush()
            }
        } catch (_: Exception) { /* сокет закрыт — штатный выход */ }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG           = "RelayConnection"
        private const val CONNECT_TIMEOUT = 10_000
        private const val BUFFER_SIZE   = 8192
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
