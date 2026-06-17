package com.proxyguard.source

import android.content.Context
import android.content.SharedPreferences
import org.json.JSONArray
import org.json.JSONObject
import java.util.UUID

/**
 * Хранит список источников в SharedPreferences (JSON).
 * Встроенные источники добавляются автоматически если их ещё нет.
 */
class SourceRepository(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    companion object {
        private const val PREFS_NAME = "proxyguard_sources"
        private const val KEY_SOURCES = "sources"

        /** Встроенные источники — нельзя удалить, только отключить */
        val DEFAULT_SOURCES = listOf(
            ProxySourceConfig(
                id        = "default_argh94",
                name      = "Argh94 MTProto",
                url       = "https://raw.githubusercontent.com/Argh94/Proxy-List/refs/heads/main/MTProto.txt",
                isDefault = true,
            ),
            ProxySourceConfig(
                id        = "default_kort0881",
                name      = "kort0881 Collector",
                url       = "https://raw.githubusercontent.com/kort0881/telegram-proxy-collector/refs/heads/main/proxy_list.txt",
                isDefault = true,
            ),
            ProxySourceConfig(
                id        = "default_sakha1370",
                name      = "sakha1370 Active",
                url       = "https://raw.githubusercontent.com/sakha1370/V2rayCollector/refs/heads/main/active_mtproto_proxies.txt",
                isDefault = true,
            ),
            ProxySourceConfig(
                id        = "default_surfboard",
                name      = "Surfboardv2ray Tested",
                url       = "https://raw.githubusercontent.com/Surfboardv2ray/TGProto/refs/heads/main/proxies-tested.txt",
                isDefault = true,
            ),
            ProxySourceConfig(
                id        = "default_solispirit",
                name      = "SoliSpirit MTProto",
                url       = "https://raw.githubusercontent.com/SoliSpirit/mtproto/master/all_proxies.txt",
                isDefault = true,
            ),
            ProxySourceConfig(
                id        = "default_aliilapro",
                name      = "ALIILAPRO MTProtoProxy",
                url       = "https://raw.githubusercontent.com/ALIILAPRO/MTProtoProxy/main/mtproto.txt",
                isDefault = true,
            ),
        )
    }

    /** Загружает все источники (встроенные + пользовательские) */
    fun loadAll(): List<ProxySourceConfig> {
        val json = prefs.getString(KEY_SOURCES, null)
        val saved: MutableMap<String, ProxySourceConfig> = if (json != null) {
            parseJson(json).associateBy { it.id }.toMutableMap()
        } else {
            mutableMapOf()
        }

        // Гарантируем что все default sources присутствуют
        for (def in DEFAULT_SOURCES) {
            if (def.id !in saved) {
                saved[def.id] = def
            }
        }

        // Сортировка: сначала default (в порядке списка), потом пользовательские
        val defaultOrder = DEFAULT_SOURCES.map { it.id }
        return saved.values.sortedWith(compareBy(
            { if (it.id in defaultOrder) 0 else 1 },
            { defaultOrder.indexOf(it.id).takeIf { i -> i >= 0 } ?: Int.MAX_VALUE },
            { it.name },
        ))
    }

    /** Возвращает только enabled источники для fetch */
    fun loadEnabled(): List<ProxySourceConfig> = loadAll().filter { it.enabled }

    /** Добавляет новый источник */
    fun add(name: String, url: String): ProxySourceConfig {
        val sources = loadAll().toMutableList()
        val newSource = ProxySourceConfig(
            id   = UUID.randomUUID().toString(),
            name = name.trim().ifEmpty { urlToName(url) },
            url  = url.trim(),
        )
        sources.add(newSource)
        save(sources)
        return newSource
    }

    /** Удаляет пользовательский источник */
    fun remove(id: String) {
        val sources = loadAll().filter { it.id != id || it.isDefault }
        save(sources)
    }

    /** Переключает enabled/disabled */
    fun setEnabled(id: String, enabled: Boolean) {
        val sources = loadAll().map {
            if (it.id == id) it.copy(enabled = enabled) else it
        }
        save(sources)
    }

    /** Обновляет счётчик dd-прокси после проверки */
    fun updateTestResult(id: String, ddCount: Int) {
        val sources = loadAll().map {
            if (it.id == id) it.copy(
                lastDdCount   = ddCount,
                lastTestedMs  = System.currentTimeMillis(),
            ) else it
        }
        save(sources)
    }

    // ── Приватные хелперы ─────────────────────────────────────────────────

    private fun save(sources: List<ProxySourceConfig>) {
        val arr = JSONArray()
        sources.forEach { arr.put(it.toJson()) }
        prefs.edit().putString(KEY_SOURCES, arr.toString()).apply()
    }

    private fun parseJson(json: String): List<ProxySourceConfig> = try {
        val arr = JSONArray(json)
        (0 until arr.length()).map { arr.getJSONObject(it).toConfig() }
    } catch (_: Exception) { emptyList() }

    private fun ProxySourceConfig.toJson() = JSONObject().apply {
        put("id", id); put("name", name); put("url", url)
        put("enabled", enabled); put("isDefault", isDefault)
        put("lastDdCount", lastDdCount); put("lastTestedMs", lastTestedMs)
    }

    private fun JSONObject.toConfig() = ProxySourceConfig(
        id           = optString("id", UUID.randomUUID().toString()),
        name         = optString("name", ""),
        url          = optString("url", ""),
        enabled      = optBoolean("enabled", true),
        isDefault    = optBoolean("isDefault", false),
        lastDdCount  = optInt("lastDdCount", -1),
        lastTestedMs = optLong("lastTestedMs", 0L),
    )

    private fun urlToName(url: String) = url
        .removePrefix("https://").removePrefix("http://")
        .substringBefore("/").substringBefore("?")
        .take(30)
}
