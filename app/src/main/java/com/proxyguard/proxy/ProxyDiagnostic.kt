package com.proxyguard.proxy

import com.proxyguard.relay.MtProtoObfuscation
import com.proxyguard.relay.ProxyTls
import java.net.InetSocketAddress
import java.net.Socket

/**
 * Пошаговая диагностика одного прокси с подробным логом каждого этапа.
 * Используется в UI (кнопка "Тест" для одиночной ссылки) чтобы видеть
 * ТОЧНО на каком шаге обрыв — без догадок.
 */
object ProxyDiagnostic {

    data class Step(val name: String, val ok: Boolean, val detail: String)
    data class Result(val steps: List<Step>, val success: Boolean, val pingMs: Long?)

    fun run(proxy: MtProtoProxy, timeoutMs: Int = 10_000): Result {
        val steps = mutableListOf<Step>()
        val t0 = System.currentTimeMillis()

        // ── Шаг 1: TCP/TLS соединение ──────────────────────────────────
        val socket = try {
            if (proxy.isFakeTls) {
                val domain = proxy.tlsDomain ?: proxy.server
                steps.add(Step("Домен SNI", true, domain))
                val ssl = ProxyTls.connect(proxy.server, proxy.port, domain, timeoutMs)
                ssl.soTimeout = timeoutMs
                ssl.startHandshake()
                steps.add(Step("TLS handshake", true, "${ssl.session.protocol} ${ssl.session.cipherSuite}"))
                ssl
            } else {
                val s = Socket().apply {
                    tcpNoDelay = true
                    connect(InetSocketAddress(proxy.server, proxy.port), timeoutMs)
                }
                steps.add(Step("TCP connect", true, "${proxy.server}:${proxy.port}"))
                s
            }
        } catch (e: Exception) {
            steps.add(Step(if (proxy.isFakeTls) "TLS handshake" else "TCP connect", false, "${e.javaClass.simpleName}: ${e.message}"))
            return Result(steps, false, null)
        }

        socket.use { sock ->
            // ── Шаг 2: MTProto nonce ────────────────────────────────────
            val (initToSend, cipher) = MtProtoObfuscation.generateForProxy(proxy.secretKey)
            try {
                sock.getOutputStream().write(initToSend)
                sock.getOutputStream().flush()
                steps.add(Step("MTProto nonce отправлен", true, "${initToSend.size} байт, ключ=${proxy.secretKey.toHex().take(12)}..."))
            } catch (e: Exception) {
                steps.add(Step("MTProto nonce", false, "${e.javaClass.simpleName}: ${e.message}"))
                return Result(steps, false, null)
            }

            // ── Шаг 3: req_pq_multi запрос ──────────────────────────────
            val request = try {
                MtProtoPing.buildRequest(cipher).also {
                    sock.getOutputStream().write(it)
                    sock.getOutputStream().flush()
                }
            } catch (e: Exception) {
                steps.add(Step("req_pq_multi отправка", false, "${e.javaClass.simpleName}: ${e.message}"))
                return Result(steps, false, null)
            }
            steps.add(Step("req_pq_multi отправлен", true, "${request.size} байт"))

            // ── Шаг 4: ждём ответ от Telegram через прокси ──────────────
            sock.soTimeout = timeoutMs
            val header = ByteArray(4)
            try {
                readFully(sock.getInputStream(), header)
            } catch (e: Exception) {
                steps.add(Step("Ответ от Telegram", false, "${e.javaClass.simpleName}: ${e.message} — прокси НЕ пересылает трафик"))
                return Result(steps, false, null)
            }

            val decryptedHeader = cipher.decrypt(header)
            val respLen = MtProtoPing.isValidResponse(decryptedHeader)
            if (respLen == null) {
                steps.add(Step(
                    "Расшифровка ответа", false,
                    "raw=${header.toHex()} decrypted=${decryptedHeader.toHex()} — невалидная длина"
                ))
                return Result(steps, false, null)
            }
            steps.add(Step("Заголовок ответа расшифрован", true, "длина=$respLen байт"))

            val body = ByteArray(respLen)
            try {
                readFully(sock.getInputStream(), body)
            } catch (e: Exception) {
                steps.add(Step("Тело ответа", false, "${e.javaClass.simpleName}: ${e.message}"))
                return Result(steps, false, null)
            }
            val decryptedBody = cipher.decrypt(body)
            steps.add(Step("resPQ получен ✓", true, decryptedBody.take(16).toByteArray().toHex()))

            val ping = System.currentTimeMillis() - t0
            return Result(steps, true, ping)
        }
    }

    private fun readFully(input: java.io.InputStream, buf: ByteArray) {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) throw java.io.EOFException("closed at $off/${buf.size}")
            off += n
        }
    }

    private fun ByteArray.toHex() = joinToString("") { "%02x".format(it) }
}
