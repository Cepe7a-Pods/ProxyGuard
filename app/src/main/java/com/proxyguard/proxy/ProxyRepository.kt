package com.proxyguard.proxy

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken

/**
 * Сохраняет/загружает список прокси в SharedPreferences.
 *
 * Зачем: если сервис убили (MIUI/EMUI), при следующем запуске не нужно ждать
 * полного цикла fetch+validate — берём последний кэшированный список сразу.
 */
class ProxyRepository(context: Context) {

    private val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    private val gson  = Gson()

    /** Сохраняет ранжированный список (max [MAX_CACHED] записей) */
    fun save(ranked: List<RankedProxy>) {
        val toSave = ranked.take(MAX_CACHED)
        val json = gson.toJson(toSave)
        prefs.edit()
            .putString(KEY_PROXIES, json)
            .putLong(KEY_TIMESTAMP, System.currentTimeMillis())
            .apply()
        Log.d(TAG, "Saved ${toSave.size} proxies to cache")
    }

    /** Загружает кэш. Возвращает пустой список если кэш устарел или пуст. */
    fun load(maxAgeMs: Long = MAX_AGE_MS): List<RankedProxy> {
        val savedAt = prefs.getLong(KEY_TIMESTAMP, 0)
        if (System.currentTimeMillis() - savedAt > maxAgeMs) {
            Log.d(TAG, "Cache expired")
            return emptyList()
        }
        val json = prefs.getString(KEY_PROXIES, null) ?: return emptyList()
        return try {
            val type = object : TypeToken<List<RankedProxy>>() {}.type
            gson.fromJson<List<RankedProxy>>(json, type).also {
                Log.d(TAG, "Loaded ${it.size} proxies from cache")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Cache parse error: ${e.message}")
            emptyList()
        }
    }

    fun cacheAge(): Long {
        val savedAt = prefs.getLong(KEY_TIMESTAMP, 0)
        return if (savedAt == 0L) Long.MAX_VALUE else System.currentTimeMillis() - savedAt
    }

    companion object {
        private const val TAG          = "ProxyRepository"
        private const val PREFS_NAME   = "proxyguard_cache"
        private const val KEY_PROXIES  = "ranked_proxies"
        private const val KEY_TIMESTAMP = "saved_at"
        private const val MAX_CACHED   = 100
        private const val MAX_AGE_MS   = 24 * 60 * 60 * 1000L  // 24 часа
    }
}
