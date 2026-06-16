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
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * Парсит списки MTProto прокси из GitHub-источников.
 *
 * Поддерживаемые форматы секрета:
 *   • hex dd...  (34+ символов, dd-prefix = simple MTProto с padding)
 *   • base64 3Q... (= hex dd..., base64-кодировка того же)
 *
 * ee-prefix (FakeTLS) — не поддерживается relay'ем, пропускается.
 */
class SourceParser {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    data class ProxySource(val name: String, val url: String)

    /**
     * Проверенные рабочие источники MTProto dd-прокси.
     */
    private val sources = listOf(
        ProxySource(
            name = "SoliSpirit MTProto",
            url  = "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
        ),
        ProxySource(
            name = "ALIILAPRO MTProtoProxy",
            url  = "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
        ),
    )

    /**
     * Загружает и парсит все источники параллельно.
     * @return дедуплицированный список dd-прокси
     */
    suspend fun fetchAll(
        onSourceDone: ((name: String, found: Int) -> Unit)? = null,
    ): List<MtProtoProxy> = coroutineScope {
        val jobs = sources.map { source ->
            async(Dispatchers.IO) {
                try {
                    val proxies = fetchSource(source)
                    onSourceDone?.invoke(source.name, proxies.size)
                    Log.d(TAG, "${source.name}: ${proxies.size} proxies")
                    proxies
                } catch (e: Exception) {
                    Log.w(TAG, "${source.name} failed: ${e.message}")
                    onSourceDone?.invoke(source.name, 0)
                    emptyList()
                }
            }
        }
        val all = jobs.awaitAll().flatten()
        deduplicate(all).also { Log.i(TAG, "Total unique dd-proxies: ${it.size}") }
    }

    private fun fetchSource(source: ProxySource): List<MtProtoProxy> {
        val request = Request.Builder().url(source.url).build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                Log.w(TAG, "${source.name} HTTP ${response.code}")
                return emptyList()
            }
            response.body?.string() ?: return emptyList()
        }
        return parseText(body, source.name)
    }

    /**
     * Ищет в тексте все ссылки t.me/proxy и tg://proxy.
     * Принимает ТОЛЬКО dd-prefix (секрет начинается на "dd" в hex
     * или "3Q" в base64, что равнозначно байту 0xDD).
     */
    fun parseText(text: String, sourceTag: String = ""): List<MtProtoProxy> {
        val result = mutableListOf<MtProtoProxy>()
        val pattern = Regex(
            """(?:tg://proxy|https?://t\.me/proxy)\?([^\s"'<>]+)""",
            RegexOption.IGNORE_CASE,
        )
        pattern.findAll(text).forEach { match ->
            parseTgLink("tg://proxy?${match.groupValues[1]}", sourceTag)
                ?.let { result.add(it) }
        }
        return result
    }

    /**
     * Парсит ссылку tg://proxy?server=...&port=...&secret=...
     * Принимает секреты в hex (dd...) и base64 (3Q...).
     * ee-FakeTLS (hex ee... или base64 7g...) — отклоняются.
     */
    fun parseTgLink(url: String, sourceTag: String = ""): MtProtoProxy? {
        return try {
            val normalized = url.replace("tg://proxy", "https://tg.proxy")
            val uri = Uri.parse(normalized)
            val server  = uri.getQueryParameter("server")?.trim('.') ?: return null
            val port    = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
            val rawSecret = uri.getQueryParameter("secret") ?: return null

            // Нормализуем секрет в hex
            val hexSecret = normalizeSecret(rawSecret) ?: return null

            // Принимаем только dd-prefix
            if (!hexSecret.startsWith("dd")) return null

            MtProtoProxy(
                server  = server,
                port    = port,
                secret  = hexSecret,
                comment = sourceTag,
            )
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Приводит секрет к нижнему hex-регистру.
     * Если секрет — base64 (содержит / + = или не hex-символы) → декодируем.
     * Возвращает null если секрет невалиден.
     */
    private fun normalizeSecret(raw: String): String? {
        // URL-decode на случай %3D и т.п.
        val s = try {
            java.net.URLDecoder.decode(raw, "UTF-8")
        } catch (_: Exception) { raw }

        return if (isHex(s)) {
            s.lowercase()
        } else {
            // Пробуем base64
            runCatching {
                val bytes = Base64.getDecoder().decode(
                    s.replace('-', '+').replace('_', '/')   // URL-safe base64
                )
                bytes.joinToString("") { "%02x".format(it) }
            }.getOrNull()
        }
    }

    private fun isHex(s: String) = s.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }

    private fun deduplicate(proxies: List<MtProtoProxy>): List<MtProtoProxy> {
        val seen = mutableSetOf<String>()
        return proxies.filter { p ->
            seen.add("${p.server}:${p.port}:${p.secret}")
        }
    }

    companion object { private const val TAG = "SourceParser" }
}
