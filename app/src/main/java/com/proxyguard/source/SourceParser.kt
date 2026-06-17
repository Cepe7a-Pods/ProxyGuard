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

/**
 * Загружает и парсит MTProto dd-прокси из списка источников.
 * Принимает ТОЛЬКО dd-prefix (0xDD = padded intermediate режим).
 * ee-prefix (FakeTLS) — в будущем.
 */
class SourceParser {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    /** Загружает все включённые источники параллельно */
    suspend fun fetchAll(
        sources: List<ProxySourceConfig>,
        onSourceDone: ((name: String, count: Int) -> Unit)? = null,
    ): List<MtProtoProxy> = coroutineScope {
        val enabled = sources.filter { it.enabled }
        if (enabled.isEmpty()) return@coroutineScope emptyList()

        val jobs = enabled.map { src ->
            async(Dispatchers.IO) {
                try {
                    val proxies = fetchSource(src.url)
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
        val all = jobs.awaitAll().flatten()
        deduplicate(all).also { Log.i(TAG, "Total unique dd-proxies: ${it.size}") }
    }

    /** Перегрузка без SourceRepository для совместимости (тест в SourcesScreen) */
    suspend fun fetchAll(
        onSourceDone: ((name: String, count: Int) -> Unit)? = null,
    ): List<MtProtoProxy> = fetchAll(
        sources     = SourceRepository.DEFAULT_SOURCES,
        onSourceDone = onSourceDone,
    )

    private fun fetchSource(url: String): List<MtProtoProxy> {
        val req  = Request.Builder().url(url).build()
        val body = client.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) {
                Log.w(TAG, "HTTP ${resp.code} from $url"); return emptyList()
            }
            resp.body?.string() ?: return emptyList()
        }
        return parseText(body)
    }

    /**
     * Парсит текст и возвращает dd-прокси.
     * Поддерживает:
     *   • tg://proxy?server=...&port=...&secret=...
     *   • https://t.me/proxy?server=...&port=...&secret=...
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

    fun parseTgLink(url: String): MtProtoProxy? = runCatching {
        val normalized = url.replace("tg://proxy", "https://tg.proxy")
        val uri    = Uri.parse(normalized)
        val server = uri.getQueryParameter("server")?.trim('.')?.ifEmpty { null } ?: return null
        val port   = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
        val rawSecret = uri.getQueryParameter("secret") ?: return null

        val hexSecret = normalizeSecret(rawSecret) ?: return null
        if (!hexSecret.startsWith("dd")) return null   // только dd; ee — не поддерживаем пока

        MtProtoProxy(server = server, port = port, secret = hexSecret)
    }.getOrNull()

    /**
     * Нормализует секрет в нижний hex.
     * Варианты:
     *   • hex (все символы 0-9 a-f A-F) → lowercase
     *   • base64 (содержит нехексовые символы) → decode → hex
     */
    private fun normalizeSecret(raw: String): String? {
        val s = runCatching { URLDecoder.decode(raw, "UTF-8") }.getOrDefault(raw)
        return if (isHex(s)) {
            s.lowercase()
        } else {
            runCatching {
                val bytes = Base64.getDecoder().decode(
                    s.replace('-', '+').replace('_', '/')
                )
                bytes.joinToString("") { "%02x".format(it) }
            }.getOrNull()
        }
    }

    private fun isHex(s: String) = s.isNotEmpty() &&
            s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun deduplicate(proxies: List<MtProtoProxy>): List<MtProtoProxy> {
        val seen = mutableSetOf<String>()
        return proxies.filter { p -> seen.add("${p.server}:${p.port}:${p.secret}") }
    }

    companion object { private const val TAG = "SourceParser" }
}
