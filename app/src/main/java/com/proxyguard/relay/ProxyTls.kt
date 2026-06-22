package com.proxyguard.relay

import com.proxyguard.proxy.MtProtoProxy
import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Единая точка установки транспорта до MTProto-прокси: обычный TCP (dd-секрет)
 * или FakeTLS (ee-секрет, см. FakeTls.kt). Вызывающему коду неважно, какой это
 * прокси — он просто получает Link с .input/.output/.socket.
 */
object ProxyTls {

    class Link(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream
    ) : Closeable {
        override fun close() { runCatching { socket.close() } }
    }

    fun connect(proxy: MtProtoProxy, timeoutMs: Int): Link {
        return if (proxy.isFakeTls) {
            val domain = proxy.tlsDomain ?: proxy.server
            val conn = FakeTls.connect(proxy.server, proxy.port, domain, proxy.secretKey, timeoutMs)
            Link(conn.socket, conn.input, conn.output)
        } else {
            val s = Socket()
            s.tcpNoDelay = true
            s.connect(InetSocketAddress(proxy.server, proxy.port), timeoutMs)
            Link(s, s.getInputStream(), s.getOutputStream())
        }
    }
}
