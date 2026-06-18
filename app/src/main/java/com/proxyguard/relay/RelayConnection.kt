package com.proxyguard.relay

import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
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
        // 1. Читаем 64-байтовый init от Telegram
        val init = ByteArray(64)
        try {
            telegramSocket.getInputStream().readFully(init)
        } catch (e: Exception) {
            Log.w(TAG, "Init read failed: ${e.message}")
            telegramSocket.close(); return
        }

        // 2. Проверяем bridge secret и получаем шифр для Telegram-стороны
        val (protocolTag, bridgeCipher) = MtProtoObfuscation.fromClientInit(init, bridgeSecret)
        if (!protocolTag.contentEquals(MtProtoObfuscation.PADDED_INTERMEDIATE_TAG)) {
            Log.w(TAG, "Unknown protocol tag: ${protocolTag.toHex()}"); telegramSocket.close(); return
        }
        telegramSocket.soTimeout = 0

        // 3. Ждём прокси в пуле (при первом запуске загружаются ~1 мин)
        val proxy = waitForProxy() ?: run {
            Log.e(TAG, "Pool empty after wait"); telegramSocket.close(); return
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
            proxyPool.markFailed(proxy); telegramSocket.close(); return
        }

        // 5. Рукопожатие с внешним прокси (dd или ee)
        val proxyCipher = try {
            handshakeWithProxy(proxySocket, proxy)
        } catch (e: Exception) {
            Log.w(TAG, "Proxy handshake failed: ${e.message}")
            proxyPool.markFailed(proxy); telegramSocket.close(); proxySocket.close(); return
        }

        if (proxyCipher == null) {
            Log.w(TAG, "Handshake returned null cipher")
            proxyPool.markFailed(proxy); telegramSocket.close(); proxySocket.close(); return
        }

        Log.i(TAG, "Relay up: Telegram ↔ ${proxy.server}:${proxy.port} (${if (proxy.isFakeTls) "ee/FakeTLS" else "dd"})")

        // 6. Двунаправленный relay
        val isFakeTls = proxy.isFakeTls
        try {
            coroutineScope {
                // Telegram → Proxy
                val t2p = launch(Dispatchers.IO) {
                    if (isFakeTls) {
                        pipeWithTlsWrap(
                            from      = telegramSocket.getInputStream(),
                            to        = proxySocket.getOutputStream(),
                            transform = { chunk -> proxyCipher.encrypt(bridgeCipher.decrypt(chunk)) },
                        )
                    } else {
                        pipe(
                            from      = telegramSocket.getInputStream(),
                            to        = proxySocket.getOutputStream(),
                            transform = { chunk -> proxyCipher.encrypt(bridgeCipher.decrypt(chunk)) },
                        )
                    }
                }
                // Proxy → Telegram
                val p2t = launch(Dispatchers.IO) {
                    if (isFakeTls) {
                        pipeWithTlsRead(
                            from      = proxySocket.getInputStream(),
                            to        = telegramSocket.getOutputStream(),
                            transform = { chunk -> bridgeCipher.encrypt(proxyCipher.decrypt(chunk)) },
                        )
                    } else {
                        pipe(
                            from      = proxySocket.getInputStream(),
                            to        = telegramSocket.getOutputStream(),
                            transform = { chunk -> bridgeCipher.encrypt(proxyCipher.decrypt(chunk)) },
                        )
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
     * Рукопожатие с внешним прокси.
     * dd: отправляем 64-байтовый nonce напрямую.
     * ee: FakeTLS ClientHello → ServerHello → nonce в TLS AppData.
     * Возвращает MtProtoObfuscation для проксийной стороны (или null при ошибке).
     */
    private fun handshakeWithProxy(
        proxySocket: Socket,
        proxy: MtProtoProxy,
    ): MtProtoObfuscation? {
        val (initToSend, proxyCipher) = MtProtoObfuscation.generateForProxy(proxy.secretKey)

        return if (!proxy.isFakeTls) {
            // ── dd: просто шлём nonce ──────────────────────────────────────
            proxySocket.getOutputStream().write(initToSend)
            proxySocket.getOutputStream().flush()
            proxyCipher

        } else {
            // ── ee: FakeTLS рукопожатие ──────────────────────────────────
            val domain = proxy.tlsDomain ?: proxy.server

            // a) Отправляем ClientHello
            val clientHello = FakeTls.buildClientHello(proxy.secretKey, domain)
            proxySocket.getOutputStream().write(clientHello)
            proxySocket.getOutputStream().flush()

            // b) Читаем ServerHello + ChangeCipherSpec + первый AppData
            proxySocket.soTimeout = 8_000
            val ok = FakeTls.readServerHandshake(proxySocket.getInputStream())
            proxySocket.soTimeout = 0

            if (!ok) {
                Log.w(TAG, "FakeTLS: no ServerHello from ${proxy.server}")
                return null
            }

            // c) Отправляем MTProto nonce обёрнутый в TLS AppData
            proxySocket.getOutputStream().write(FakeTls.wrap(initToSend))
            proxySocket.getOutputStream().flush()

            proxyCipher
        }
    }

    // ── Pipe: dd (raw bytes) ────────────────────────────────────────────

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

    // ── Pipe: ee (TLS Application Data) ────────────────────────────────

    /** Читаем raw от Telegram, шлём в TLS AppData записях к прокси */
    private fun pipeWithTlsWrap(from: InputStream, to: OutputStream, transform: (ByteArray) -> ByteArray) {
        val buf = ByteArray(BUFFER_SIZE)
        try {
            while (true) {
                val n = from.read(buf)
                if (n < 0) break
                val transformed = transform(buf.copyOfRange(0, n))
                to.write(FakeTls.wrap(transformed))
                to.flush()
            }
        } catch (_: Exception) { }
    }

    /** Читаем TLS AppData записи от прокси, шлём raw к Telegram */
    private fun pipeWithTlsRead(from: InputStream, to: OutputStream, transform: (ByteArray) -> ByteArray) {
        try {
            while (true) {
                val payload = FakeTls.readAppData(from) ?: break
                to.write(transform(payload))
                to.flush()
            }
        } catch (_: Exception) { }
    }

    // ── Утилиты ──────────────────────────────────────────────────────────

    private suspend fun waitForProxy() = withTimeoutOrNull(POOL_WAIT_MS) {
        while (proxyPool.isEmpty()) {
            Log.d(TAG, "Pool empty, waiting...")
            delay(POOL_POLL_MS)
        }
        proxyPool.getBest()
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }

    companion object {
        private const val TAG              = "RelayConnection"
        private const val CONNECT_TIMEOUT  = 10_000
        private const val BUFFER_SIZE      = 8_192
        private const val POOL_WAIT_MS     = 80_000L
        private const val POOL_POLL_MS     = 2_000L
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
