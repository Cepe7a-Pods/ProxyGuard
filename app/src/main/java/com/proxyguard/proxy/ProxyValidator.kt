package com.proxyguard.proxy

import android.util.Log
import com.proxyguard.relay.FakeTls
import com.proxyguard.relay.MtProtoObfuscation
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException

/**
 * Валидирует MTProto прокси — и dd (simple), и ee (FakeTLS).
 *
 * dd-логика: send init → ждём 1.5 сек
 *   • SocketTimeoutException = соединение открыто, прокси молчит → ПРАВИЛЬНО (dd не отвечает сразу)
 *   • read() == -1 = сервер закрыл соединение → не MTProto прокси
 *   • получили байт сразу = HTTP/TLS banner → не MTProto прокси
 *
 * ee-логика: send ClientHello → ждём ServerHello
 *   • получили TLS Handshake record (0x16) → ПРАВИЛЬНО (сервер ответил)
 *   • timeout / закрытие → не FakeTLS прокси
 */
class ProxyValidator(
    private val connectTimeoutMs: Int = 5_000,
    private val ddSilenceMs: Int      = 1_500,   // dd: ждём что прокси НЕ ответит
    private val eeResponseMs: Int     = 4_000,   // ee: ждём ServerHello
) {

    suspend fun validate(proxy: MtProtoProxy): Long? = withContext(Dispatchers.IO) {
        if (proxy.isFakeTls) validateFakeTls(proxy) else validateDd(proxy)
    }

    // ── dd (random-padded) ────────────────────────────────────────────────

    private fun validateDd(proxy: MtProtoProxy): Long? {
        return try {
            val (initToSend, _) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
            Socket().use { sock ->
                val t0 = System.currentTimeMillis()
                sock.connect(InetSocketAddress(proxy.server, proxy.port), connectTimeoutMs)
                val ping = System.currentTimeMillis() - t0
                sock.tcpNoDelay = true
                sock.getOutputStream().write(initToSend)
                sock.getOutputStream().flush()
                sock.soTimeout = ddSilenceMs
                return@use try {
                    val b = sock.getInputStream().read()
                    // Сервер что-то прислал сразу → HTTP/TLS banner, не MTProto
                    Log.d(TAG, "dd ${proxy.server}: got immediate byte=$b — not MTProto")
                    null
                } catch (_: SocketTimeoutException) {
                    // Молчание = соединение живо, прокси ждёт данных → ✓ MTProto
                    Log.d(TAG, "dd ${proxy.server}: silent ✓ ping=${ping}ms")
                    ping
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "dd ${proxy.server}: ${e.javaClass.simpleName} ${e.message}")
            null
        }
    }

    // ── ee (FakeTLS) ──────────────────────────────────────────────────────

    private fun validateFakeTls(proxy: MtProtoProxy): Long? {
        val domain = proxy.tlsDomain ?: proxy.server
        return try {
            Socket().use { sock ->
                val t0 = System.currentTimeMillis()
                sock.connect(InetSocketAddress(proxy.server, proxy.port), connectTimeoutMs)
                val ping = System.currentTimeMillis() - t0
                sock.tcpNoDelay = true
                sock.soTimeout = eeResponseMs

                val hello = FakeTls.buildClientHello(proxy.secretKey, domain)
                sock.getOutputStream().write(hello)
                sock.getOutputStream().flush()

                // Читаем первую TLS-запись от сервера
                val header = ByteArray(5)
                return@use try {
                    if (!FakeTls.readFull(sock.getInputStream(), header)) {
                        Log.d(TAG, "ee ${proxy.server}: closed immediately"); null
                    } else {
                        val type = header[0].toInt() and 0xFF
                        if (type == 0x16) {
                            // ServerHello → сервер принял наш ClientHello ✓
                            Log.d(TAG, "ee ${proxy.server}: ServerHello ✓ ping=${ping}ms")
                            ping
                        } else {
                            Log.d(TAG, "ee ${proxy.server}: unexpected type=0x${type.toString(16)}")
                            null
                        }
                    }
                } catch (_: SocketTimeoutException) {
                    Log.d(TAG, "ee ${proxy.server}: no ServerHello (timeout)")
                    null
                }
            }
        } catch (e: Exception) {
            Log.d(TAG, "ee ${proxy.server}: ${e.javaClass.simpleName} ${e.message}")
            null
        }
    }

    // ── Батч-валидация ────────────────────────────────────────────────────

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
        Log.i(TAG, "Validated: ${results.size}/${proxies.size} live (dd+ee)")
        return results.sortedBy { it.pingMs }
    }

    companion object { private const val TAG = "ProxyValidator" }
}
