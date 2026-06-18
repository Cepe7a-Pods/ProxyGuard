package com.proxyguard.ui

import android.Manifest
import android.content.*
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.*
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.List
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.proxyguard.relay.BridgeSecret
import com.proxyguard.service.ProxyGuardService

class MainActivity : ComponentActivity() {

    private val notifPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED
            ) notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
        setContent {
            MaterialTheme {
                Surface(Modifier.fillMaxSize()) {
                    AppNavigation()
                }
            }
        }
    }
}

@Composable
fun AppNavigation() {
    var screen by remember { mutableStateOf("main") }   // "main" | "sources"

    when (screen) {
        "main"    -> MainScreen(onOpenSources = { screen = "sources" })
        "sources" -> SourcesScreen(onBack = { screen = "main" })
    }
}

@Composable
fun MainScreen(onOpenSources: () -> Unit) {
    val context   = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val secret    = remember { BridgeSecret.getHex(context) }
    val prefs     = remember { ProxyGuardService.prefs(context) }

    var serviceRunning by remember {
        mutableStateOf(prefs.getBoolean(ProxyGuardService.PREF_RUNNING, false))
    }
    var statusText by remember {
        mutableStateOf(prefs.getString(ProxyGuardService.PREF_STATUS_TEXT, "") ?: "")
    }
    var poolSize by remember {
        mutableIntStateOf(prefs.getInt(ProxyGuardService.PREF_POOL_SIZE, 0))
    }
    var isLoading by remember {
        mutableStateOf(prefs.getBoolean(ProxyGuardService.PREF_IS_LOADING, false))
    }
    var copied by remember { mutableStateOf(false) }

    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                val text = intent.getStringExtra(ProxyGuardService.EXTRA_STATUS_TEXT) ?: ""
                statusText     = text
                poolSize       = intent.getIntExtra(ProxyGuardService.EXTRA_POOL_SIZE, 0)
                isLoading      = intent.getBooleanExtra(ProxyGuardService.EXTRA_IS_LOADING, false)
                if (text.isEmpty()) serviceRunning = false
            }
        }
        val filter = IntentFilter(ProxyGuardService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("UnspecifiedRegisterReceiverFlag")
            context.registerReceiver(receiver, filter)
        }
        onDispose { context.unregisterReceiver(receiver) }
    }

    Column(
        modifier                = Modifier.fillMaxSize().padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment     = Alignment.CenterHorizontally,
        verticalArrangement     = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(8.dp))

        // Заголовок + кнопка "Источники"
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Spacer(Modifier.weight(1f))
            Text("🛡 ProxyGuard", style = MaterialTheme.typography.headlineLarge)
            Spacer(Modifier.weight(1f))
            IconButton(onClick = onOpenSources) {
                Icon(Icons.Default.List, contentDescription = "Источники",
                    tint = MaterialTheme.colorScheme.primary)
            }
        }

        Text(
            "MTProto прокси-менеджер для Telegram",
            style     = MaterialTheme.typography.bodyMedium,
            color     = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        HorizontalDivider()

        // Статус-карточка
        AnimatedVisibility(visible = serviceRunning) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors = CardDefaults.cardColors(
                    containerColor = if (isLoading)
                        MaterialTheme.colorScheme.surfaceVariant
                    else
                        MaterialTheme.colorScheme.primaryContainer,
                ),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Row(
                        verticalAlignment      = Alignment.CenterVertically,
                        horizontalArrangement  = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            if (isLoading) "Загрузка" else "Статус",
                            style = MaterialTheme.typography.labelLarge,
                        )
                        if (isLoading) {
                            CircularProgressIndicator(Modifier.size(14.dp), strokeWidth = 2.dp)
                        }
                    }
                    if (statusText.isNotEmpty()) {
                        Text(statusText, style = MaterialTheme.typography.bodyMedium)
                    }
                    if (!isLoading && poolSize > 0) {
                        Text(
                            "Прокси в пуле: $poolSize",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                        )
                    }
                }
            }
        }

        // Инструкция
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Настройка Telegram — один раз",
                    style = MaterialTheme.typography.titleSmall)
                Text("1. Настройки → Данные → Прокси → Добавить", fontSize = 13.sp)
                Text("2. Тип: MTProto  •  Адрес: 127.0.0.1  •  Порт: 1080", fontSize = 13.sp)
                Text("3. Секрет — скопируй ниже и вставь", fontSize = 13.sp)
            }
        }

        // Bridge secret
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer),
        ) {
            Column(
                Modifier.padding(14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("Секрет для Telegram:", style = MaterialTheme.typography.labelLarge)
                Text(
                    text       = secret,
                    fontFamily = FontFamily.Monospace,
                    fontSize   = 12.sp,
                    textAlign  = TextAlign.Center,
                    modifier   = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(6.dp))
                        .padding(10.dp),
                )
                OutlinedButton(
                    onClick  = { clipboard.setText(AnnotatedString(secret)); copied = true },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (copied) "✓ Скопировано" else "Скопировать")
                }
            }
        }

        Spacer(Modifier.weight(1f))

        // Кнопки управления
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Button(
                onClick = {
                    if (serviceRunning) {
                        ProxyGuardService.stop(context)
                        serviceRunning = false; statusText = ""; poolSize = 0; isLoading = false
                    } else {
                        ProxyGuardService.start(context)
                        serviceRunning = true; statusText = "Запуск..."; isLoading = true
                    }
                },
                modifier = Modifier.weight(1f).height(52.dp),
                colors   = if (serviceRunning)
                    ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                else
                    ButtonDefaults.buttonColors(),
            ) {
                Text(if (serviceRunning) "⏹ Стоп" else "▶ Запустить", fontSize = 16.sp)
            }

            // Следующий прокси
            AnimatedVisibility(visible = serviceRunning && poolSize > 1) {
                OutlinedButton(
                    onClick  = { ProxyGuardService.nextProxy(context) },
                    modifier = Modifier.height(52.dp).width(52.dp),
                    contentPadding = PaddingValues(0.dp),
                ) {
                    Text("⏭", fontSize = 18.sp)
                }
            }

            // Обновить всё
            AnimatedVisibility(visible = serviceRunning) {
                OutlinedButton(
                    onClick  = {
                        ProxyGuardService.refresh(context)
                        statusText = "Обновление..."; isLoading = true
                    },
                    modifier = Modifier.height(52.dp).width(52.dp),
                    contentPadding = PaddingValues(0.dp),
                ) {
                    Text("🔄", fontSize = 18.sp)
                }
            }
        }

        AnimatedVisibility(visible = serviceRunning) {
            Text(
                "Relay работает • 127.0.0.1:1080",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(4.dp))
    }
}
