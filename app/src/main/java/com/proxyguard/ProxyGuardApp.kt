package com.proxyguard

import android.app.Application

class ProxyGuardApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // Ничего тут не делаем — сервис стартует из MainActivity по кнопке
        // или автоматически после перезагрузки через BootReceiver
    }
}
