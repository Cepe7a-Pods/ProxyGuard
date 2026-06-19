package com.proxyguard.proxy

import android.util.Log
import com.proxyguard.relay.MtProtoObfuscation
import com.proxyguard.relay.ProxyTls
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Валидирует MTProto прокси через РЕАЛЬНЫЙ round-trip к Telegram DC.
 *
 * Раньше: проверяли "тишину" после nonce — но любой TCP black-hole
 * (мёртвый сервер за NAT, заглушка) тоже молчит и проходил как "рабочий".
 *
 * Теперь: отправляем req_pq_multi, ждём resPQ. Только проксі которые
 * РЕАЛЬНО пересылают трафик к Telegram дадут осмысленный ответ.
 */
class ProxyValidator(
    private val connectTimeoutMs: Int = 5_000,
    private val ddSilenceMs: Int      = 1_500,    // оставлено для совместимости (не используется в новой логике)
    private val eeResponseMs: Int     = 6_000,    // оставлено для совместимости
    private val pingTimeoutMs: Int    = 7_000,    // сколько ждать resPQ от Telegram через прокси
) {

    suspend fun validate(proxy: MtProtoProxy): Long? = withContext(Dispatchers.IO) {
        try {
            if (proxy.isFakeTls) validateViaPing(proxy, useTls = true)
            else validateViaPing(proxy, useTls = false)
        } catch (e: Exception) {
            Log.d(TAG, "${proxy.server}: ${e.javaClass.simpleName} ${e.message}")
            null
        }
    }

    private fun validateViaPing(proxy: MtProtoProxy, useTls: Boolean): Long? {
        val t0 = System.currentTimeMillis()

        val socket = if (useTls) {
            val domain = proxy.tlsDomain ?: proxy.server
            val ssl = ProxyTls.connect(proxy.server, proxy.port, domain, connectTimeoutMs)
            ssl.soTimeout = eeResponseMs
            ssl.startHandshake()
            ssl
        } else {
            Socket().apply {
                tcpNoDelay = true
                connect(InetSocketAddress(proxy.server, proxy.port), connectTimeoutMs)
            }
        }

        socket.use { sock ->
            // 1. MTProto handshake
            val (initToSend, cipher) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
            sock.getOutputStream().write(initToSend)
            sock.getOutputStream().flush()

            // 2. Реальный запрос req_pq_multi
            val request = MtProtoPing.buildRequest(cipher)
            sock.getOutputStream().write(request)
            sock.getOutputStream().flush()

            // 3. Ждём ответ — если прокси реально пересылает трафик, Telegram ответит resPQ
            sock.soTimeout = pingTimeoutMs
            val header = ByteArray(4)
            readFully(sock.getInputStream(), header)
            val decryptedHeader = cipher.decrypt(header)
            val respLen = MtProtoPing.isValidResponse(decryptedHeader)
                ?: run {
                    Log.d(TAG, "${proxy.server}: invalid response length")
                    return null
                }

            // Дочитываем тело ответа (не обязательно для решения, но дренируем буфер)
            val body = ByteArray(respLen)
            readFully(sock.getInputStream(), body)

            val ping = System.currentTimeMillis() - t0
            Log.d(TAG, "${proxy.server}: ✓ REAL proxy, resPQ ${respLen}b, ping=${ping}ms")
            return ping
        }
    }

    private fun readFully(input: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException("closed at $off/${buf.size}")
            off += n
        }
    }

    suspend fun validateAll(
        proxies: List<MtProtoProxy>,
        batchSize: Int = 30,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
    ): List<RankedProxy> {
        val results = mutableListOf<RankedProxy>()
        var done = 0
        proxies.chunked(batchSize).forEach { batch ->
            coroutineScope {
                batch.map { proxy -> async { proxy to validate(proxy) } }.awaitAll()
            }.forEach { (proxy, ping) ->
                if (ping != null) results.add(RankedProxy(proxy, ping))
            }
            done += batch.size
            onProgress?.invoke(done, proxies.size)
        }
        Log.i(TAG, "Validated: ${results.size}/${proxies.size} REAL working proxies (req_pq confirmed)")
        return results.sortedBy { it.pingMs }
    }

    companion object { private const val TAG = "ProxyValidator" }
}
