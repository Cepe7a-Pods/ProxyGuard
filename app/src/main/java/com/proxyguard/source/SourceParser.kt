package com.proxyguard.source

import android.net.Uri
import android.util.Log
import com.proxyguard.proxy.MtProtoProxy
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import okhttp3.OkHttpClient
import okhttp3.Request
import java.net.URLDecoder
import java.util.Base64
import java.util.concurrent.TimeUnit

class SourceParser {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    suspend fun fetchAll(
        sources: List<ProxySourceConfig>,
        onSourceDone: ((name: String, count: Int) -> Unit)? = null,
    ): List<MtProtoProxy> = coroutineScope {
        val enabled = sources.filter { it.enabled }
        if (enabled.isEmpty()) return@coroutineScope emptyList()

        val jobs = enabled.map { src ->
            async(Dispatchers.IO) {
                try {
                    val proxies = fetchSource(src)
                    onSourceDone?.invoke(src.name, proxies.size)
                    Log.d(TAG, "${src.name}: ${proxies.size} dd-прокси")
                    proxies
                } catch (e: Exception) {
                    Log.w(TAG, "${src.name} failed: ${e.message}")
                    onSourceDone?.invoke(src.name, 0)
                    emptyList()
                }
            }
        }
        deduplicate(jobs.awaitAll().flatten())
            .also { Log.i(TAG, "Total unique dd-proxies: ${it.size}") }
    }

    suspend fun fetchAll(
        onSourceDone: ((name: String, count: Int) -> Unit)? = null,
    ) = fetchAll(SourceRepository.DEFAULT_SOURCES, onSourceDone)

    private fun fetchSource(src: ProxySourceConfig): List<MtProtoProxy> {
        // Если URL сам является tg://proxy или t.me/proxy ссылкой — парсим напрямую
        if (isSingleProxyUrl(src.url)) {
            val proxy = parseTgLink(src.url)?.copy(isManual = true)
            return if (proxy != null) listOf(proxy) else emptyList()
        }

        val req  = Request.Builder().url(src.url).build()
        val body = client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                Log.w(TAG, "HTTP ${resp.code} from ${src.url}"); return emptyList()
            }
            resp.body?.string() ?: return emptyList()
        }
        return parseText(body)
    }

    /**
     * Парсит текст и возвращает dd-прокси.
     * Публичный метод — используется из SourcesScreen для теста.
     */
    fun parseText(text: String): List<MtProtoProxy> {
        val result  = mutableListOf<MtProtoProxy>()
        val pattern = Regex(
            """(?:tg://proxy|https?://t\.me/proxy)\?([^\s"'<>\[\]]+)""",
            RegexOption.IGNORE_CASE,
        )
        pattern.findAll(text).forEach { m ->
            parseTgLink("tg://proxy?${m.groupValues[1]}")?.let { result.add(it) }
        }
        return result
    }

    /**
     * Парсит одну tg://proxy или t.me/proxy ссылку.
     * Принимает только dd-prefix секреты.
     */
    fun parseTgLink(url: String): MtProtoProxy? = runCatching {
        val normalized = url
            .replace(Regex("^https?://t\\.me/proxy", RegexOption.IGNORE_CASE), "tg://proxy")
            .replace("tg://proxy", "https://tg.proxy")
        val uri    = Uri.parse(normalized)
        val server = uri.getQueryParameter("server")?.trim('.')?.ifEmpty { null } ?: return null
        val port   = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
        val raw    = uri.getQueryParameter("secret") ?: return null
        val hex    = normalizeSecret(raw) ?: return null
        if (!hex.startsWith("dd") && !hex.startsWith("ee")) return null
        MtProtoProxy(server = server, port = port, secret = hex)
    }.getOrNull()

    /** True если URL — это прямая tg://proxy или t.me/proxy ссылка (не список) */
    fun isSingleProxyUrl(url: String): Boolean =
        url.contains(Regex("""^(tg://proxy|https?://t\.me/proxy)\?""", RegexOption.IGNORE_CASE))

    private fun normalizeSecret(raw: String): String? {
        val s = runCatching { URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)
        return if (isHex(s)) s.lowercase()
        else runCatching {
            val bytes = Base64.getDecoder().decode(s.replace('-', '+').replace('_', '/'))
            bytes.joinToString("") { "%02x".format(it) }
        }.getOrNull()
    }

    private fun isHex(s: String) = s.isNotEmpty() &&
        s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun deduplicate(proxies: List<MtProtoProxy>): List<MtProtoProxy> {
        val seen = mutableSetOf<String>()
        return proxies.filter { p -> seen.add("${p.server}:${p.port}:${p.secret}") }
    }

    companion object { private const val TAG = "SourceParser" }
}
