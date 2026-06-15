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
import java.util.concurrent.TimeUnit

/**
 * Парсит списки MTProto прокси из различных источников.
 *
 * Поддерживаемые форматы:
 *   • tg://proxy?server=...&port=...&secret=...
 *   • https://t.me/proxy?server=...&port=...&secret=...
 *   • IP:PORT:SECRET  (raw text)
 *   • JSON-массивы   (GitHub-репозитории)
 */
class SourceParser {

    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(15, TimeUnit.SECONDS)
        .build()

    data class ProxySource(
        val name: String,
        val url: String,
        val type: SourceType = SourceType.AUTO,
    )

    enum class SourceType { AUTO, RAW_TEXT, JSON }

    /**
     * Публичные GitHub-источники MTProto прокси.
     * Можно добавлять свои.
     */
    private val sources = listOf(
        ProxySource(
            name = "MTPoroxy (Black-Catt)",
            url  = "https://raw.githubusercontent.com/Black-Catt/MTPoroxy/main/MTP.txt",
        ),
        ProxySource(
            name = "MTProto list 1",
            url  = "https://raw.githubusercontent.com/hookzof/socks5_list/master/tg/mtproto.txt",
        ),
        ProxySource(
            name = "MTProto list 2",
            url  = "https://raw.githubusercontent.com/manuGMG/proxy-365/main/HTTPS.txt",
        ),
        ProxySource(
            name = "TgProxy collection",
            url  = "https://raw.githubusercontent.com/soroushmirzaei/telegram-proxies-collector/main/proxies",
        ),
    )

    /**
     * Загружает и парсит все источники.
     * @return дедуплицированный список прокси (только dd-prefix, без ee пока)
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
        deduplicate(all).also { Log.i(TAG, "Total unique proxies: ${it.size}") }
    }

    private fun fetchSource(source: ProxySource): List<MtProtoProxy> {
        val request = Request.Builder().url(source.url).build()
        val body = client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) return emptyList()
            response.body?.string() ?: return emptyList()
        }
        return parseText(body, source.name)
    }

    /**
     * Парсит сырой текст — ищет все упоминания tg://proxy или t.me/proxy
     * и raw-формат SERVER:PORT:SECRET.
     */
    fun parseText(text: String, sourceTag: String = ""): List<MtProtoProxy> {
        val result = mutableListOf<MtProtoProxy>()

        // Ищем tg://proxy?... и https://t.me/proxy?...
        val tgLinkPattern = Regex(
            """(?:tg://proxy|https?://t\.me/proxy)\?([^\s"'<>]+)""",
            RegexOption.IGNORE_CASE,
        )
        tgLinkPattern.findAll(text).forEach { match ->
            parseTgLink("tg://proxy?${match.groupValues[1]}", sourceTag)?.let { result.add(it) }
        }

        // Ищем raw-формат: SERVER PORT SECRET или SERVER:PORT:SECRET
        if (result.isEmpty()) {
            val rawPattern = Regex(
                """(\d{1,3}(?:\.\d{1,3}){3})[:\s]+(\d{2,5})[:\s]+((?:dd|ee)[0-9a-fA-F]{32,64})""",
                RegexOption.IGNORE_CASE,
            )
            rawPattern.findAll(text).forEach { match ->
                runCatching {
                    result.add(MtProtoProxy(
                        server  = match.groupValues[1],
                        port    = match.groupValues[2].toInt(),
                        secret  = match.groupValues[3].lowercase(),
                        comment = sourceTag,
                    ))
                }
            }
        }

        return result
    }

    /**
     * Парсит ссылку формата tg://proxy?server=...&port=...&secret=...
     */
    fun parseTgLink(url: String, sourceTag: String = ""): MtProtoProxy? {
        return try {
            // Uri.parse не работает с tg:// из коробки — заменяем схему
            val normalized = url.replace("tg://proxy", "https://tg.proxy")
            val uri = Uri.parse(normalized)
            val server = uri.getQueryParameter("server") ?: return null
            val port   = uri.getQueryParameter("port")?.toIntOrNull() ?: return null
            val secret = uri.getQueryParameter("secret") ?: return null

            // Принимаем только dd-prefix (ee — FakeTLS, пока не поддерживаем)
            if (!secret.startsWith("dd", ignoreCase = true) &&
                !secret.startsWith("ee", ignoreCase = true)) return null

            MtProtoProxy(
                server  = server,
                port    = port,
                secret  = secret.lowercase(),
                comment = sourceTag,
            )
        } catch (e: Exception) {
            null
        }
    }

    private fun deduplicate(proxies: List<MtProtoProxy>): List<MtProtoProxy> {
        val seen = mutableSetOf<String>()
        return proxies.filter { proxy ->
            val key = "${proxy.server}:${proxy.port}:${proxy.secret}"
            seen.add(key)
        }
    }

    companion object { private const val TAG = "SourceParser" }
}
