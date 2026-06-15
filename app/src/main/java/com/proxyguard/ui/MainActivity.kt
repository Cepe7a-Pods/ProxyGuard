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
    ) { /* opional */ }

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
    val context       = LocalContext.current
    val clipboard     = LocalClipboardManager.current
    val bridgeSecret  = remember { BridgeSecret.getHex(context) }

    var serviceRunning  by remember { mutableStateOf(false) }
    var copied          by remember { mutableStateOf(false) }
    var statusText      by remember { mutableStateOf("") }
    var poolSize        by remember { mutableIntStateOf(0) }

    // Принимаем broadcast от сервиса
    DisposableEffect(Unit) {
        val receiver = object : BroadcastReceiver() {
            override fun onReceive(ctx: Context, intent: Intent) {
                statusText = intent.getStringExtra(ProxyGuardService.EXTRA_STATUS_TEXT) ?: ""
                poolSize   = intent.getIntExtra(ProxyGuardService.EXTRA_POOL_SIZE, 0)
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
            style    = MaterialTheme.typography.bodyMedium,
            color    = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        HorizontalDivider()

        // Статус (показываем только если сервис запущен)
        AnimatedVisibility(visible = serviceRunning && statusText.isNotEmpty()) {
            Card(
                modifier = Modifier.fillMaxWidth(),
                colors   = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                ),
            ) {
                Column(Modifier.padding(14.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    Text("Статус", style = MaterialTheme.typography.labelLarge)
                    Text(statusText, style = MaterialTheme.typography.bodyMedium)
                    if (poolSize > 0) {
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
                Text("Настройка Telegram — один раз", style = MaterialTheme.typography.titleSmall)
                Text("1. Настройки → Данные → Прокси → Добавить", fontSize = 13.sp)
                Text("2. Тип: MTProto  •  Адрес: 127.0.0.1  •  Порт: 1080", fontSize = 13.sp)
                Text("3. Секрет — скопируй ниже и вставь", fontSize = 13.sp)
            }
        }

        // Bridge secret
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
                    text = bridgeSecret,
                    fontFamily = FontFamily.Monospace,
                    fontSize   = 12.sp,
                    textAlign  = TextAlign.Center,
                    modifier   = Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.surface,
                            RoundedCornerShape(6.dp),
                        )
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

        // Кнопки
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(10.dp),
        ) {
            // Кнопка Запуск/Стоп
            Button(
                onClick = {
                    if (serviceRunning) {
                        ProxyGuardService.stop(context)
                    } else {
                        ProxyGuardService.start(context)
                    }
                    serviceRunning = !serviceRunning
                },
                modifier = Modifier.weight(1f).height(52.dp),
                colors = if (serviceRunning) {
                    ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
                } else {
                    ButtonDefaults.buttonColors()
                },
            ) {
                Text(if (serviceRunning) "⏹ Стоп" else "▶ Запустить", fontSize = 16.sp)
            }

            // Кнопка Обновить (только когда запущен)
            AnimatedVisibility(visible = serviceRunning) {
                OutlinedButton(
                    onClick = { ProxyGuardService.refresh(context) },
                    modifier = Modifier.height(52.dp),
                ) {
                    Text("🔄", fontSize = 16.sp)
                }
            }
        }

        if (serviceRunning) {
            Text(
                "Relay работает • 127.0.0.1:1080",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        Spacer(Modifier.height(4.dp))
    }
}
