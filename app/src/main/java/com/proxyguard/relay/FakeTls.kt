package com.proxyguard.relay

import java.io.InputStream
import java.security.SecureRandom
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * FakeTLS (ee-prefix) транспорт для MTProto прокси.
 *
 * Протокол:
 *  1. Client → Server: TLS ClientHello
 *     • random[0:4]  = timestamp
 *     • random[4:32] = HMAC-SHA256(key, clientHello_with_zeros)[0:28]
 *     • SNI = домен из ee-секрета
 *  2. Server → Client: ServerHello + ChangeCipherSpec + первый AppData
 *  3. Client → Server: MTProto nonce в TLS Application Data записи
 *  4. Двунаправленный поток: каждый чанк оборачивается в TLS AppData (0x17 0x03 0x03 [len] [data])
 */
object FakeTls {

    private val rng = SecureRandom()

    // ── ClientHello ───────────────────────────────────────────────────────

    fun buildClientHello(key: ByteArray, domain: String): ByteArray {
        val sessionId = ByteArray(32).also { rng.nextBytes(it) }
        val ts = (System.currentTimeMillis() / 1000).toInt()

        // random: [0:4] timestamp, [4:32] zeros → после HMAC заполним
        val random = ByteArray(32)
        random[0] = (ts shr 24).toByte(); random[1] = (ts shr 16).toByte()
        random[2] = (ts shr  8).toByte(); random[3] = ts.toByte()

        val ciphers = byteArrayOf(
            0x13, 0x01,                         // TLS_AES_128_GCM_SHA256
            0x13, 0x02,                         // TLS_AES_256_GCM_SHA384
            0x13, 0x03,                         // TLS_CHACHA20_POLY1305_SHA256
            0xC0.toByte(), 0x2B,                // ECDHE_ECDSA_AES128_GCM_SHA256
            0xC0.toByte(), 0x2F,                // ECDHE_RSA_AES128_GCM_SHA256
            0xCC.toByte(), 0xA8.toByte(),       // ECDHE_RSA_CHACHA20_POLY1305
            0xCC.toByte(), 0xA9.toByte(),       // ECDHE_ECDSA_CHACHA20_POLY1305
        )

        val exts = buildExtensions(domain)
        val body = byteArrayOf(0x03, 0x03) + random +
            byteArrayOf(0x20) + sessionId +
            i2(ciphers.size) + ciphers +
            byteArrayOf(0x01, 0x00) +           // compression: null
            i2(exts.size) + exts

        val handshake = byteArrayOf(0x01) + i3(body.size) + body
        // TLS 1.0 для записи (так пишет Chrome)
        val record = byteArrayOf(0x16, 0x03, 0x01) + i2(handshake.size) + handshake

        // random[4:32] в record находится на позиции 15:
        //  5 (record hdr) + 4 (handshake hdr) + 2 (version) + 4 (timestamp) = 15
        val mac = Mac.getInstance("HmacSHA256").also {
            it.init(SecretKeySpec(key, "HmacSHA256"))
            it.update(record)
        }
        System.arraycopy(mac.doFinal(), 0, record, 15, 28)
        return record
    }

    private fun buildExtensions(domain: String): ByteArray {
        val d = domain.toByteArray()

        // SNI (server_name) — обязательный
        val sni = i2(0x0000) +
            i2(d.size + 5) + i2(d.size + 3) +
            byteArrayOf(0x00) + i2(d.size) + d

        // supported_groups: x25519, secp256r1, secp384r1
        val groups = i2(0x000A) + i2(8) + i2(6) +
            byteArrayOf(0x00, 0x1D, 0x00, 0x17, 0x00, 0x18)

        // ec_point_formats: uncompressed
        val ecFmt = i2(0x000B) + i2(2) + byteArrayOf(0x01, 0x00)

        // session_ticket: empty
        val ticket = i2(0x0023) + i2(0)

        // supported_versions: TLS 1.3 + TLS 1.2
        val vers = i2(0x002B) + i2(5) + byteArrayOf(0x04, 0x03, 0x04, 0x03, 0x03)

        return sni + groups + ecFmt + ticket + vers
    }

    // ── Серверное рукопожатие ─────────────────────────────────────────────

    /**
     * Читаем TLS-записи от сервера до первого Application Data (или пока не прочитали 10 записей).
     * Возвращает true если получили хотя бы один Handshake record — значит сервер принял нас.
     */
    fun readServerHandshake(input: InputStream): Boolean {
        var gotHandshake = false
        repeat(15) {
            val header = ByteArray(5)
            if (!readFull(input, header)) return false
            val type = header[0].toInt() and 0xFF
            val len  = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
            if (len > 16384) return false                // слишком большая запись — не TLS
            val payload = ByteArray(len)
            if (!readFull(input, payload)) return false
            when (type) {
                0x16 -> gotHandshake = true              // ServerHello, Certificate, ...
                0x14 -> { /* ChangeCipherSpec — пропускаем */ }
                0x17 -> return gotHandshake              // Application Data —握手 завершено
                0x15 -> return false                     // Alert — ошибка
            }
        }
        return gotHandshake
    }

    /**
     * Читает одну TLS Application Data запись.
     * Пропускает Handshake/ChangeCipherSpec. Возвращает null при ошибке/закрытии.
     */
    fun readAppData(input: InputStream): ByteArray? {
        repeat(10) {
            val header = ByteArray(5)
            if (!readFull(input, header)) return null
            val type = header[0].toInt() and 0xFF
            val len  = ((header[3].toInt() and 0xFF) shl 8) or (header[4].toInt() and 0xFF)
            if (len > 65535) return null
            val payload = ByteArray(len)
            if (!readFull(input, payload)) return null
            if (type == 0x17) return payload             // Application Data
            if (type == 0x15) return null                // Alert
            // иначе — Handshake/ChangeCipherSpec, пропускаем
        }
        return null
    }

    // ── Обёртка данных ────────────────────────────────────────────────────

    /** Оборачивает данные в TLS Application Data запись */
    fun wrap(data: ByteArray): ByteArray = byteArrayOf(0x17, 0x03, 0x03) + i2(data.size) + data

    // ── Утилиты ───────────────────────────────────────────────────────────

    private fun i2(v: Int) = byteArrayOf((v shr 8).toByte(), (v and 0xFF).toByte())
    private fun i3(v: Int) = byteArrayOf((v shr 16).toByte(), (v shr 8).toByte(), (v and 0xFF).toByte())

    /** Читает ровно buf.size байт, false если поток закрылся раньше */
    fun readFull(input: InputStream, buf: ByteArray): Boolean {
        var off = 0
        while (off < buf.size) {
            val n = input.read(buf, off, buf.size - off)
            if (n < 0) return false
            off += n
        }
        return true
    }
}
