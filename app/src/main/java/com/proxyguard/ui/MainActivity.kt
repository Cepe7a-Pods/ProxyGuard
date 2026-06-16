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
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
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
    ) { }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                notifPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
        setContent {
            MaterialTheme { Surface(Modifier.fillMaxSize()) { MainScreen() } }
        }
    }
}

@Composable
fun MainScreen() {
    val context      = LocalContext.current
    val clipboard    = LocalClipboardManager.current
    val bridgeSecret = remember { BridgeSecret.getHex(context) }

    // ── Начальное состояние из SharedPreferences (переживает пересоздание Activity) ──
    val prefs = remember { ProxyGuardService.prefs(context) }

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

    // ── Broadcast от сервиса (real-time обновления) ──
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                statusText     = intent.getStringExtra(ProxyGuardService.EXTRA_STATUS_TEXT) ?: ""
                poolSize       = intent.getIntExtra(ProxyGuardService.EXTRA_POOL_SIZE, 0)
                isLoading      = intent.getBooleanExtra(ProxyGuardService.EXTRA_IS_LOADING, false)
                serviceRunning = statusText.isNotEmpty()  // сервис остановлен → шлёт пустой статус
                // Актуализируем prefs-флаг running если сервис остановился
                if (statusText.isEmpty()) serviceRunning = false
            }
        }
        val filter = IntentFilter(ProxyGuardService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            context.registerReceiver(receiver, filter)
        }
        onDispose { context.unregisterReceiver(receiver) }
    }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(horizontal = 20.dp, vertical = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Spacer(Modifier.height(8.dp))

        Text("🛡 ProxyGuard", style = MaterialTheme.typography.headlineLarge)
        Text(
            "MTProto прокси-менеджер для Telegram",
            style     = MaterialTheme.typography.bodyMedium,
            color     = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        HorizontalDivider()

        // ── Статус / Загрузка ──
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
                Column(
                    Modifier.padding(14.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text(
                            if (isLoading) "Загрузка" else "Статус",
                            style = MaterialTheme.typography.labelLarge,
                        )
                        if (isLoading) {
                            CircularProgressIndicator(
                                modifier  = Modifier.size(14.dp),
                                strokeWidth = 2.dp,
                            )
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

        // ── Инструкция ──
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Настройка Telegram — один раз", style = MaterialTheme.typography.titleSmall)
                Text("1. Настройки → Данные → Прокси → Добавить", fontSize = 13.sp)
                Text("2. Тип: MTProto  •  Адрес: 127.0.0.1  •  Порт: 1080", fontSize = 13.sp)
                Text("3. Секрет — скопируй ниже и вставь", fontSize = 13.sp)
            }
        }

        // ── Bridge secret ──
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
            ),
        ) {
            Column(
                Modifier.padding(14.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(10.dp),
            ) {
                Text("Секрет для Telegram:", style = MaterialTheme.typography.labelLarge)
                Text(
                    text       = bridgeSecret,
                    fontFamily = FontFamily.Monospace,
                    fontSize   = 12.sp,
                    textAlign  = TextAlign.Center,
                    modifier   = Modifier
                        .fillMaxWidth()
                        .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(6.dp))
                        .padding(10.dp),
                )
                OutlinedButton(
                    onClick = {
                        clipboard.setText(AnnotatedString(bridgeSecret))
                        copied = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (copied) "✓ Скопировано" else "Скопировать")
                }
            }
        }

        Spacer(Modifier.weight(1f))

        // ── Кнопки ──
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            Button(
                onClick = {
                    if (serviceRunning) {
                        ProxyGuardService.stop(context)
                        serviceRunning = false
                        statusText = ""
                        poolSize = 0
                        isLoading = false
                    } else {
                        ProxyGuardService.start(context)
                        serviceRunning = true
                        statusText = "Запуск..."
                        isLoading = true
                    }
                },
                modifier = Modifier
                    .weight(1f)
                    .height(52.dp),
                colors = if (serviceRunning)
                    ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                else
                    ButtonDefaults.buttonColors(),
            ) {
                Text(if (serviceRunning) "⏹ Стоп" else "▶ Запустить", fontSize = 16.sp)
            }

            AnimatedVisibility(visible = serviceRunning) {
                OutlinedButton(
                    onClick = {
                        ProxyGuardService.refresh(context)
                        statusText = "Обновление..."
                        isLoading = true
                    },
                    modifier = Modifier.height(52.dp),
                ) {
                    Text("🔄", fontSize = 16.sp)
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
