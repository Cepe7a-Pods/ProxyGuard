package com.proxyguard.proxy

import android.util.Log
import com.proxyguard.relay.MtProtoObfuscation
import com.proxyguard.relay.ProxyTls
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Валидирует MTProto прокси.
 *
 * dd: TCP → send nonce → ждём молчания
 *   timeout (тишина) = прокси ждёт данных = ✓ настоящий MTProto
 *   read() == -1 = сервер закрыл = ✗
 *
 * ee: TLS handshake → send nonce → ждём молчания
 *   То же, но поверх реального TLS 1.3.
 *   TLS handshake не завершился = ✗ не наш прокси
 */
class ProxyValidator(
    private val connectTimeoutMs: Int = 5_000,
    private val ddSilenceMs: Int      = 1_500,
    private val eeResponseMs: Int     = 6_000,
) {

    suspend fun validate(proxy: MtProtoProxy): Long? = withContext(Dispatchers.IO) {
        if (proxy.isFakeTls) validateTls(proxy) else validateDd(proxy)
    }

    // ── dd (plain TCP + MTProto nonce) ───────────────────────────────────

    private fun validateDd(proxy: MtProtoProxy): Long? = try {
        val (initToSend, _) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
        Socket().use { sock ->
            val t0 = System.currentTimeMillis()
            sock.connect(InetSocketAddress(proxy.server, proxy.port), connectTimeoutMs)
            val ping = System.currentTimeMillis() - t0
            sock.tcpNoDelay = true
            sock.getOutputStream().write(initToSend)
            sock.getOutputStream().flush()
            sock.soTimeout = ddSilenceMs
            try {
                val b = sock.getInputStream().read()
                // Ответил сразу — не MTProto прокси
                Log.d(TAG, "dd ${proxy.server}: got byte=$b immediately")
                null
            } catch (_: SocketTimeoutException) {
                // Тишина = прокси ждёт наших данных = ✓
                Log.d(TAG, "dd ${proxy.server}: silent ✓ ping=${ping}ms")
                ping
            }
        }
    } catch (e: Exception) {
        Log.d(TAG, "dd ${proxy.server}: ${e.javaClass.simpleName}")
        null
    }

    // ── ee (реальный TLS 1.3 + MTProto nonce внутри) ────────────────────

    private fun validateTls(proxy: MtProtoProxy): Long? = try {
        val domain = proxy.tlsDomain ?: proxy.server
        val (initToSend, _) = MtProtoObfuscation.generateForProxy(proxy.secretKey)

        val t0 = System.currentTimeMillis()
        val ssl = ProxyTls.connect(proxy.server, proxy.port, domain, connectTimeoutMs)
        ssl.use { sock ->
            // TLS рукопожатие — если провалится, это не наш прокси
            sock.soTimeout = eeResponseMs
            sock.startHandshake()
            val ping = System.currentTimeMillis() - t0

            // Отправляем MTProto nonce поверх TLS
            sock.outputStream.write(initToSend)
            sock.outputStream.flush()

            // Ждём тишины (прокси должен молчать, ожидая данных)
            sock.soTimeout = ddSilenceMs
            try {
                val b = sock.inputStream.read()
                Log.d(TAG, "ee ${proxy.server}: got byte=$b immediately")
                null
            } catch (_: SocketTimeoutException) {
                Log.d(TAG, "ee ${proxy.server}: silent after TLS ✓ ping=${ping}ms")
                ping
            }
        }
    } catch (e: Exception) {
        Log.d(TAG, "ee ${proxy.server}: ${e.javaClass.simpleName} ${e.message}")
        null
    }

    // ── Батч ─────────────────────────────────────────────────────────────

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
        Log.i(TAG, "Validated: ${results.size}/${proxies.size} live")
        return results.sortedBy { it.pingMs }
    }

    companion object { private const val TAG = "ProxyValidator" }
}
