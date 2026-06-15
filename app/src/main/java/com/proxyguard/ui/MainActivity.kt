package com.proxyguard.ui

import android.Manifest
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.border
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

    private val notificationPermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()
    ) { /* не обязательно — уведомление опционально */ }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)
                != PackageManager.PERMISSION_GRANTED) {
                notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }

        setContent {
            MaterialTheme {
                Surface(
                    modifier = Modifier.fillMaxSize(),
                    color = MaterialTheme.colorScheme.background,
                ) {
                    MainScreen()
                }
            }
        }
    }
}

@Composable
fun MainScreen() {
    val context = LocalContext.current
    val clipboard = LocalClipboardManager.current
    val bridgeSecret = remember { BridgeSecret.getHex(context) }
    var serviceRunning by remember { mutableStateOf(false) }
    var copied by remember { mutableStateOf(false) }

    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(24.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(24.dp),
    ) {
        Spacer(modifier = Modifier.height(16.dp))

        // Заголовок
        Text(
            text = "🛡 ProxyGuard",
            style = MaterialTheme.typography.headlineLarge,
        )
        Text(
            text = "Автоматический MTProto прокси-менеджер",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            textAlign = TextAlign.Center,
        )

        HorizontalDivider()

        // Инструкция
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier.padding(16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text("Настройка Telegram (один раз)", style = MaterialTheme.typography.titleMedium)
                Text("1. Telegram → Настройки → Данные и хранилище → Прокси")
                Text("2. Добавить прокси → тип MTProto")
                Text("3. Адрес: 127.0.0.1   Порт: 1080")
                Text("4. Секрет — скопируй ниже ↓")
            }
        }

        // Bridge Secret
        Card(
            modifier = Modifier.fillMaxWidth(),
            colors = CardDefaults.cardColors(
                containerColor = MaterialTheme.colorScheme.secondaryContainer,
            ),
        ) {
            Column(
                modifier = Modifier.padding(16.dp),
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Text("Твой секрет для Telegram:", style = MaterialTheme.typography.labelLarge)
                Text(
                    text = bridgeSecret,
                    fontFamily = FontFamily.Monospace,
                    fontSize = 13.sp,
                    textAlign = TextAlign.Center,
                    modifier = Modifier
                        .fillMaxWidth()
                        .background(
                            MaterialTheme.colorScheme.surface,
                            RoundedCornerShape(8.dp),
                        )
                        .padding(12.dp),
                )
                Button(
                    onClick = {
                        clipboard.setText(AnnotatedString(bridgeSecret))
                        copied = true
                    },
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text(if (copied) "✓ Скопировано!" else "Скопировать секрет")
                }
            }
        }

        Spacer(modifier = Modifier.weight(1f))

        // Кнопка запуска
        Button(
            onClick = {
                if (serviceRunning) {
                    ProxyGuardService.stop(context)
                    serviceRunning = false
                } else {
                    ProxyGuardService.start(context)
                    serviceRunning = true
                }
            },
            modifier = Modifier
                .fillMaxWidth()
                .height(56.dp),
            colors = if (serviceRunning) {
                ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            } else {
                ButtonDefaults.buttonColors()
            },
        ) {
            Text(
                text = if (serviceRunning) "⏹ Остановить" else "▶ Запустить",
                fontSize = 18.sp,
            )
        }

        if (serviceRunning) {
            Text(
                text = "Relay работает на 127.0.0.1:1080\nСм. уведомление для статуса",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                textAlign = TextAlign.Center,
            )
        }

        Spacer(modifier = Modifier.height(8.dp))
    }
}
