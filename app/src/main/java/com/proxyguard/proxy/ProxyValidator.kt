package com.proxyguard.proxy

import android.util.Log
import com.proxyguard.relay.MtProtoObfuscation
import kotlinx.coroutines.*
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Проверяет MTProto прокси на работоспособность.
 *
 * Логика: подключаемся, шлём корректный nonce, ждём ответа.
 * Живой прокси прочитает nonce и начнёт слать данные (или подождёт ещё).
 * Мёртвый — либо не примет TCP, либо закроет соединение сразу.
 * Измеряем время до первого байта ответа = latency.
 */
class ProxyValidator(
    private val connectTimeoutMs: Int = 5_000,
    private val readTimeoutMs: Int    = 5_000,
) {

    /**
     * Валидирует один прокси.
     * @return pingMs или null если прокси недоступен.
     */
    suspend fun validate(proxy: MtProtoProxy): Long? = withContext(Dispatchers.IO) {
        try {
            val (initToSend, _) = MtProtoObfuscation.generateForProxy(proxy.secretBytes)

            Socket().use { socket ->
                val start = System.currentTimeMillis()

                socket.connect(InetSocketAddress(proxy.server, proxy.port), connectTimeoutMs)
                socket.tcpNoDelay = true
                socket.soTimeout  = readTimeoutMs

                socket.getOutputStream().write(initToSend)
                socket.getOutputStream().flush()

                // Ждём хоть один байт ответа — признак живого прокси
                val firstByte = socket.getInputStream().read()
                if (firstByte < 0) return@withContext null

                System.currentTimeMillis() - start
            }
        } catch (e: Exception) {
            Log.d(TAG, "${proxy.server}:${proxy.port} — dead (${e.javaClass.simpleName})")
            null
        }
    }

    /**
     * Валидирует список прокси параллельно, батчами по [batchSize].
     * @return список живых прокси с пингом, отсортированный по пингу.
     */
    suspend fun validateAll(
        proxies: List<MtProtoProxy>,
        batchSize: Int = 20,
        onProgress: ((done: Int, total: Int) -> Unit)? = null,
    ): List<RankedProxy> {
        val results = mutableListOf<RankedProxy>()
        var done = 0

        proxies.chunked(batchSize).forEach { batch ->
            val batchResults = coroutineScope {
                batch.map { proxy ->
                    async { proxy to validate(proxy) }
                }.awaitAll()
            }
            batchResults.forEach { (proxy, ping) ->
                if (ping != null) results.add(RankedProxy(proxy, ping))
            }
            done += batch.size
            onProgress?.invoke(done, proxies.size)
            Log.d(TAG, "Validated $done/${proxies.size}, alive so far: ${results.size}")
        }

        Log.i(TAG, "Validation done: ${results.size}/${proxies.size} alive")
        return results.sortedBy { it.pingMs }
    }

    companion object { private const val TAG = "ProxyValidator" }
}
