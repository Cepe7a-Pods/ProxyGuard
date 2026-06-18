package com.proxyguard.relay

import java.net.InetSocketAddress
import java.security.cert.X509Certificate
import javax.net.ssl.*

/**
 * ee-prefix прокси используют РЕАЛЬНЫЙ TLS 1.3 как транспорт.
 * MTProto obfuscated stream идёт ВНУТРИ TLS сессии.
 * Никакого FakeTLS — просто SSLSocket + MTProto nonce.
 */
object ProxyTls {

    @Volatile private var factory: SSLSocketFactory? = null

    /** Подключается к прокси через TLS, возвращает готовый SSLSocket */
    fun connect(host: String, port: Int, domain: String, timeoutMs: Int): SSLSocket {
        val f = factory ?: buildFactory().also { factory = it }
        // Создаём TCP соединение вручную чтобы контролировать таймаут
        val raw = java.net.Socket()
        raw.connect(InetSocketAddress(host, port), timeoutMs)
        // Оборачиваем в TLS
        val ssl = f.createSocket(raw, host, port, /* autoClose= */ true) as SSLSocket
        // SNI — используем домен из секрета (обязательно для маршрутизации)
        ssl.sslParameters = ssl.sslParameters.apply {
            serverNames = listOf(SNIHostName(domain))
        }
        return ssl
    }

    /** SSLContext принимает любой сертификат сервера */
    private fun buildFactory(): SSLSocketFactory {
        val ctx = SSLContext.getInstance("TLS")
        ctx.init(null, arrayOf(TrustAll), null)
        return ctx.socketFactory
    }

    private object TrustAll : X509TrustManager {
        override fun checkClientTrusted(c: Array<X509Certificate>, a: String) {}
        override fun checkServerTrusted(c: Array<X509Certificate>, a: String) {}
        override fun getAcceptedIssuers(): Array<X509Certificate> = emptyArray()
    }
}
