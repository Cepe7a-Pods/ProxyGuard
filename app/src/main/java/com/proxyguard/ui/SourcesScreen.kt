package com.proxyguard.ui

import android.util.Log
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.proxyguard.source.ProxySourceConfig
import com.proxyguard.source.SourceParser
import com.proxyguard.source.SourceRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.util.concurrent.TimeUnit

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SourcesScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    val repo    = remember { SourceRepository(context) }
    val scope   = rememberCoroutineScope()

    var sources by remember { mutableStateOf(repo.loadAll()) }
    var showAddDialog by remember { mutableStateOf(false) }

    val testResults = remember { mutableStateMapOf<String, String>() }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Источники прокси") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, "Назад")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Default.Add, "Добавить")
            }
        },
    ) { padding ->
        LazyColumn(
            contentPadding = PaddingValues(
                start = 12.dp, end = 12.dp,
                top = padding.calculateTopPadding() + 8.dp,
                bottom = padding.calculateBottomPadding() + 80.dp,
            ),
            verticalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            items(sources, key = { it.id }) { src ->
                SourceCard(
                    source     = src,
                    testResult = testResults[src.id],
                    onToggle   = { enabled ->
                        repo.setEnabled(src.id, enabled)
                        sources = repo.loadAll()
                    },
                    onDelete   = if (src.isDefault) null else ({
                        repo.remove(src.id)
                        sources = repo.loadAll()
                    }),
                    onTest     = {
                        testResults[src.id] = "testing"
                        scope.launch {
                            val result = testSource(src.url)
                            testResults[src.id] = result
                            repo.updateTestResult(src.id, parseDdCount(result))
                            sources = repo.loadAll()
                        }
                    },
                )
            }
        }
    }

    if (showAddDialog) {
        AddSourceDialog(
            repo      = repo,
            onDismiss = { showAddDialog = false },
            onAdded   = {
                sources = repo.loadAll()
                showAddDialog = false
            },
        )
    }
}

@Composable
private fun SourceCard(
    source: ProxySourceConfig,
    testResult: String?,
    onToggle: (Boolean) -> Unit,
    onDelete: (() -> Unit)?,
    onTest: () -> Unit,
) {
    val isTesting = testResult == "testing"

    Card(
        modifier = Modifier.fillMaxWidth(),
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (source.enabled)
                MaterialTheme.colorScheme.surface
            else
                MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
        ),
        elevation = CardDefaults.cardElevation(defaultElevation = if (source.enabled) 2.dp else 0.dp),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {

            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(6.dp),
            ) {
                if (source.isDefault) {
                    Surface(
                        shape = RoundedCornerShape(4.dp),
                        color = MaterialTheme.colorScheme.primaryContainer,
                    ) {
                        Text(
                            "встроен",
                            fontSize = 9.sp,
                            modifier = Modifier.padding(horizontal = 5.dp, vertical = 2.dp),
                            color    = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
                Text(
                    source.name,
                    style    = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.weight(1f),
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Switch(
                    checked         = source.enabled,
                    onCheckedChange = onToggle,
                    modifier        = Modifier.height(24.dp),
                )
            }

            Text(
                source.shortUrl,
                style    = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                color    = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 2,
                overflow = TextOverflow.Ellipsis,
                fontSize = 10.sp,
            )

            if (source.lastDdCount >= 0 && testResult == null) {
                Text(
                    "dd-прокси при последней проверке: ${source.lastDdCount}",
                    style = MaterialTheme.typography.bodySmall,
                    color = if (source.lastDdCount > 0)
                        MaterialTheme.colorScheme.primary
                    else
                        MaterialTheme.colorScheme.error,
                )
            }

            AnimatedVisibility(visible = testResult != null) {
                Row(
                    verticalAlignment     = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    if (isTesting) {
                        CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
                        Text("Проверяем...", style = MaterialTheme.typography.bodySmall)
                    } else {
                        val isGood = testResult?.startsWith("✓✓✓") == true ||
                            (testResult?.contains("Итого:") == true && !testResult.contains(": 0"))
                        Text(
                            testResult ?: "",
                            style      = MaterialTheme.typography.bodySmall.copy(fontFamily = FontFamily.Monospace),
                            fontSize   = 10.sp,
                            lineHeight = 13.sp,
                            color      = if (isGood) MaterialTheme.colorScheme.primary
                                         else MaterialTheme.colorScheme.error,
                        )
                    }
                }
            }

            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedButton(
                    onClick  = onTest,
                    enabled  = !isTesting,
                    modifier = Modifier.height(34.dp),
                    contentPadding = PaddingValues(horizontal = 12.dp),
                ) {
                    Text("Тест", fontSize = 12.sp)
                }
                if (onDelete != null) {
                    OutlinedButton(
                        onClick  = onDelete,
                        modifier = Modifier.height(34.dp),
                        contentPadding = PaddingValues(horizontal = 12.dp),
                        colors   = ButtonDefaults.outlinedButtonColors(
                            contentColor = MaterialTheme.colorScheme.error,
                        ),
                    ) {
                        Icon(Icons.Default.Delete, null, Modifier.size(16.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun AddSourceDialog(
    repo: SourceRepository,
    onDismiss: () -> Unit,
    onAdded: () -> Unit,
) {
    var name  by remember { mutableStateOf("") }
    var url   by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    val parser = remember { SourceParser() }

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Добавить источник") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                Text(
                    "Поддерживаются:\n" +
                    "• https://raw.githubusercontent.com/... (список)\n" +
                    "• tg://proxy?server=...&port=...&secret=...\n" +
                    "• https://t.me/proxy?...\n" +
                    "• t.me/proxy?...",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
                OutlinedTextField(
                    value         = name,
                    onValueChange = { name = it },
                    label         = { Text("Название (необязательно)") },
                    singleLine    = true,
                    modifier      = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value         = url,
                    onValueChange = { url = it; error = null },
                    label         = { Text("URL") },
                    placeholder   = { Text("https://... или tg://proxy?...") },
                    singleLine    = false,
                    maxLines      = 3,
                    isError       = error != null,
                    supportingText = error?.let { e -> { Text(e, color = MaterialTheme.colorScheme.error) } },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Uri),
                    modifier      = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = {
                val trimUrl = url.trim()
                when {
                    trimUrl.isEmpty() -> {
                        error = "Введите URL"
                    }
                    // Принимаем: https?://, tg://proxy?, t.me/proxy?
                    !trimUrl.startsWith("http", ignoreCase = true)
                    && !parser.isSingleProxyUrl(trimUrl) -> {
                        error = "Ссылка должна начинаться с https://, http:// или tg://proxy?"
                    }
                    else -> {
                        val added = repo.add(name, trimUrl)
                        if (added == null) {
                            error = "Этот источник уже добавлен"
                        } else {
                            onAdded()
                        }
                    }
                }
            }) { Text("Добавить") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Отмена") }
        },
    )
}

// ── Утилиты ────────────────────────────────────────────────────────────────

private val httpClient = OkHttpClient.Builder()
    .connectTimeout(10, TimeUnit.SECONDS)
    .readTimeout(15, TimeUnit.SECONDS)
    .build()

private suspend fun testSource(url: String): String = withContext(Dispatchers.IO) {
    val parser = SourceParser()

    if (parser.isSingleProxyUrl(url)) {
        val proxy = parser.parseTgLink(url)
            ?: return@withContext "Невалидная ссылка (секрет не dd/ee или неверный формат)"
        val result = com.proxyguard.proxy.ProxyDiagnostic.run(proxy, timeoutMs = 10_000)
        val lines = result.steps.mapIndexed { _, step ->
            val icon = if (step.ok) "✓" else "✗"
            "$icon ${step.name}: ${step.detail}"
        }
        val header = if (result.success) "✓✓✓ РАБОТАЕТ! ping=${result.pingMs}ms\n" else "✗ НЕ РАБОТАЕТ\n"
        return@withContext header + lines.joinToString("\n")
    }

    try {
        val req  = Request.Builder().url(url).build()
        val body = httpClient.newCall(req).execute().use { resp ->
            if (!resp.isSuccessful) return@withContext "HTTP ${resp.code}"
            resp.body?.string() ?: return@withContext "Пустой ответ"
        }
        val proxies = parser.parseText(body)
        if (proxies.isEmpty()) return@withContext "Прокси: 0 (нет dd/ee совместимых)"
        val dd = proxies.count { !it.isFakeTls }
        val ee = proxies.count { it.isFakeTls }
        "Итого: ${proxies.size}  (dd: $dd | ee/FakeTLS: $ee)"
    } catch (e: Exception) {
        Log.w("SourcesScreen", "Test failed: ${e.message}")
        "Ошибка: ${e.message?.take(60)}"
    }
}

private fun parseDdCount(result: String?): Int {
    if (result == null) return -1
    Regex("""Итого: (\d+)""").find(result)?.let { return it.groupValues[1].toIntOrNull() ?: 0 }
    if (result.startsWith("✓✓✓")) return 1
    if (result.startsWith("✗"))   return 0
    return 0
}
