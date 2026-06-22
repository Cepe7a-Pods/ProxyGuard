package com.proxyguard.relay

import java.io.Closeable
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.Socket
import java.security.MessageDigest
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * Настоящий FakeTLS (ee-prefix секреты) транспорт для MTProto-прокси.
 *
 * ВАЖНО: это НЕ настоящий TLS. javax.net.ssl / SSLSocket здесь не нужны и не используются.
 * FakeTLS устроен так:
 *
 *  1. Клиент шлёт ClientHello-подобный набор байт, где в 32-байтовом поле `random`
 *     зашит HMAC-SHA256(secret, весь_ClientHello_с_обнулённым_random), у которого
 *     последние 4 байта дополнительно XOR'ятся с little-endian unix-таймстампом.
 *     Сервер по этому полю узнаёт владельца secret. Без верного digest он МОЛЧИТ —
 *     именно поэтому ssl.startHandshake() на обычном SSLSocket висел и падал
 *     по SocketTimeoutException: Read timed out (см. прошлый разбор).
 *
 *  2. Сервер (если digest верный) отвечает: ServerHello + ChangeCipherSpec +
 *     ровно один "шумовой" Application Data рекорд (имитация зашифрованного
 *     Certificate/Finished — содержимое не парсится, это просто случайные байты
 *     правдоподобного размера). В поле `random` ServerHello зашит ответный digest,
 *     который мы можем (и должны) проверить.
 *
 *  3. После этого ОБЕ стороны заворачивают обычный obfuscated2 MTProto-поток
 *     (тот же MtProtoObfuscation, что и для dd-секретов, без каких-либо изменений)
 *     в TLS Application Data записи (0x17 0x03 0x03 <len 2 байта BE>). Второго слоя
 *     шифрования тут нет — это чисто маскировка трафика под HTTPS для DPI.
 *
 * Сверено побайтово с github.com/9seconds/mtg (mtglib/internal/tls/fake, файлы client_side.go и server_side.go) —
 * структура ClientHello/ServerHello, оффсеты и формула digest идентичны.
 */
object FakeTls {

    private const val RECORD_HANDSHAKE        = 0x16
    private const val RECORD_CHANGE_CIPHER    = 0x14
    private const val RECORD_APPLICATION_DATA = 0x17
    private val TLS_RECORD_VERSION = byteArrayOf(0x03, 0x03)   // legacy record-layer version "3,3"

    private const val HANDSHAKE_CLIENT = 0x01
    private const val RANDOM_LEN = 32

    // record_type(1) + version(2) + size(2) + handshake_type(1) + uint24_length(3) + client_version(2)
    private const val RANDOM_OFFSET = 5 + 1 + 3 + 2   // = 11

    private const val MAX_RECORD_PAYLOAD = 16384 - 5  // 5 = заголовок записи

    class Connection(
        val socket: Socket,
        val input: InputStream,
        val output: OutputStream
    ) : Closeable {
        override fun close() { runCatching { socket.close() } }
    }

    /** TCP-коннект + фейковый TLS-хендшейк. Возвращает потоки, уже завёрнутые/развёрнутые из Application Data записей. */
    fun connect(host: String, port: Int, sniHost: String, secret: ByteArray, timeoutMs: Int): Connection {
        val socket = Socket()
        try {
            socket.tcpNoDelay = true
            socket.connect(InetSocketAddress(host, port), timeoutMs)
            socket.soTimeout = timeoutMs

            val rawOut = socket.getOutputStream()
            val rawIn = socket.getInputStream()

            val (clientHello, clientRandom) = buildClientHello(secret, sniHost)
            rawOut.write(clientHello)
            rawOut.flush()

            verifyServerHello(rawIn, secret, clientRandom)

            return Connection(socket, FakeTlsInputStream(rawIn), FakeTlsOutputStream(rawOut))
        } catch (e: Exception) {
            runCatching { socket.close() }
            throw e
        }
    }

    // ───────────────────────── ClientHello ─────────────────────────

    private fun buildClientHello(secret: ByteArray, sniHost: String): Pair<ByteArray, ByteArray> {
        val sessionId = Random.nextBytes(32)
        val keyShareKey = Random.nextBytes(32)

        val cipherSuites = bytes(
            0x13, 0x01, 0x13, 0x02, 0x13, 0x03,                 // TLS 1.3: AES128-GCM, AES256-GCM, CHACHA20
            0xc0, 0x2b, 0xc0, 0x2f, 0xc0, 0x2c, 0xc0, 0x30,      // ECDHE AES-GCM (TLS 1.2 fallback)
            0x00, 0x9c                                           // RSA AES128-GCM (legacy fallback)
        )

        val extensions =
            ext(0xff01, byteArrayOf(0x00)) +                                              // renegotiation_info
            ext(0x0000, sniExtensionData(sniHost)) +                                       // server_name
            ext(0x0017, ByteArray(0)) +                                                    // extended_master_secret
            ext(0x000d, lengthPrefixed16(bytes(0x04, 0x03, 0x08, 0x04, 0x04, 0x01, 0x08, 0x05))) + // signature_algorithms
            ext(0x000b, lengthPrefixed8(bytes(0x00))) +                                    // ec_point_formats
            ext(0x0010, alpnExtensionData(listOf("h2", "http/1.1"))) +                     // ALPN
            ext(0x000a, lengthPrefixed16(bytes(0x00, 0x1d, 0x00, 0x17, 0x00, 0x18))) +      // supported_groups
            ext(0x0033, keyShareExtensionData(keyShareKey)) +                              // key_share (x25519)
            ext(0x002d, lengthPrefixed8(bytes(0x01))) +                                    // psk_key_exchange_modes
            ext(0x002b, lengthPrefixed8(bytes(0x03, 0x04, 0x03, 0x03)))                    // supported_versions

        val body =
            byteArrayOf(0x03, 0x03) +                       // client_version (legacy TLS1.2 значение)
            ByteArray(RANDOM_LEN) +                          // random — placeholder, заполним после digest
            byteArrayOf(sessionId.size.toByte()) + sessionId +
            u16(cipherSuites.size) + cipherSuites +
            byteArrayOf(0x01, 0x00) +                        // compression methods: len=1, null
            u16(extensions.size) + extensions

        val handshake = byteArrayOf(HANDSHAKE_CLIENT.toByte()) + u24(body.size) + body
        val record = byteArrayOf(RECORD_HANDSHAKE.toByte()) + TLS_RECORD_VERSION + u16(handshake.size) + handshake

        // digest = HMAC-SHA256(secret, record[0:11) ++ zero(32) ++ record[43:end))
        val mac = hmacSha256(secret)
        mac.update(record, 0, RANDOM_OFFSET)
        mac.update(ByteArray(RANDOM_LEN))
        mac.update(record, RANDOM_OFFSET + RANDOM_LEN, record.size - RANDOM_OFFSET - RANDOM_LEN)
        val digest = mac.doFinal()

        val timestampLe = le32((System.currentTimeMillis() / 1000).toInt())
        val clientRandom = ByteArray(RANDOM_LEN)
        for (i in 0 until RANDOM_LEN - 4) clientRandom[i] = digest[i]
        for (i in 0 until 4) {
            clientRandom[RANDOM_LEN - 4 + i] = (digest[RANDOM_LEN - 4 + i].toInt() xor timestampLe[i].toInt()).toByte()
        }

        System.arraycopy(clientRandom, 0, record, RANDOM_OFFSET, RANDOM_LEN)
        return record to clientRandom
    }

    // ───────────────────────── ServerHello проверка ─────────────────────────

    private fun verifyServerHello(input: InputStream, secret: ByteArray, clientRandom: ByteArray) {
        val packet = java.io.ByteArrayOutputStream()

        // ServerHello
        val shHeader = ByteArray(5).also { input.readFully(it) }
        require(shHeader[0].toInt() and 0xFF == RECORD_HANDSHAKE) {
            "ServerHello: ожидался handshake-рекорд (0x16), получен 0x${"%02x".format(shHeader[0])}"
        }
        val shBody = ByteArray(u16At(shHeader, 3)).also { input.readFully(it) }
        packet.write(shHeader); packet.write(shBody)

        // ChangeCipherSpec
        val ccsHeader = ByteArray(5).also { input.readFully(it) }
        require(ccsHeader[0].toInt() and 0xFF == RECORD_CHANGE_CIPHER) {
            "ожидался ChangeCipherSpec (0x14), получен 0x${"%02x".format(ccsHeader[0])}"
        }
        val ccsBody = ByteArray(u16At(ccsHeader, 3)).also { input.readFully(it) }
        packet.write(ccsHeader); packet.write(ccsBody)

        // Ровно один "шумовой" Application Data рекорд
        val noiseHeader = ByteArray(5).also { input.readFully(it) }
        require(noiseHeader[0].toInt() and 0xFF == RECORD_APPLICATION_DATA) {
            "ожидался шумовой Application Data рекорд (0x17), получен 0x${"%02x".format(noiseHeader[0])}"
        }
        val noiseBody = ByteArray(u16At(noiseHeader, 3)).also { input.readFully(it) }
        packet.write(noiseHeader); packet.write(noiseBody)

        val packetBytes = packet.toByteArray()
        val withZeroRandom = packetBytes.copyOf()
        for (i in 0 until RANDOM_LEN) withZeroRandom[RANDOM_OFFSET + i] = 0

        val mac = hmacSha256(secret)
        mac.update(clientRandom)
        mac.update(withZeroRandom)
        val expected = mac.doFinal()

        val actual = packetBytes.copyOfRange(RANDOM_OFFSET, RANDOM_OFFSET + RANDOM_LEN)
        if (!MessageDigest.isEqual(expected, actual)) {
            throw java.io.IOException("FakeTLS digest mismatch — прокси не подтвердил secret (не FakeTLS сервер или неверный secret)")
        }
    }

    // ───────────────────────── Application Data framing ─────────────────────────

    private class FakeTlsInputStream(private val raw: InputStream) : InputStream() {
        private var buf = ByteArray(0)
        private var pos = 0

        private fun fill(): Boolean {
            if (pos < buf.size) return true
            val header = ByteArray(5)
            raw.readFully(header)
            require(header[0].toInt() and 0xFF == RECORD_APPLICATION_DATA) {
                "Ожидался Application Data рекорд (0x17), получен 0x${"%02x".format(header[0])}"
            }
            val len = u16At(header, 3)
            val payload = ByteArray(len)
            raw.readFully(payload)
            buf = payload
            pos = 0
            return buf.isNotEmpty()
        }

        override fun read(): Int {
            if (!fill()) return -1
            return buf[pos++].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (!fill()) return -1
            val n = minOf(len, buf.size - pos)
            System.arraycopy(buf, pos, b, off, n)
            pos += n
            return n
        }
    }

    private class FakeTlsOutputStream(private val raw: OutputStream) : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()), 0, 1)

        override fun write(b: ByteArray, off: Int, len: Int) {
            var o = off
            var remaining = len
            while (remaining > 0) {
                val chunk = minOf(remaining, MAX_RECORD_PAYLOAD)
                raw.write(byteArrayOf(RECORD_APPLICATION_DATA.toByte()))
                raw.write(TLS_RECORD_VERSION)
                raw.write(u16(chunk))
                raw.write(b, o, chunk)
                o += chunk
                remaining -= chunk
            }
        }

        override fun flush() = raw.flush()
    }

    // ───────────────────────── Байтовые хелперы ─────────────────────────

    private fun bytes(vararg ints: Int): ByteArray = ByteArray(ints.size) { ints[it].toByte() }

    private fun u16(v: Int): ByteArray = byteArrayOf(((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u24(v: Int): ByteArray =
        byteArrayOf(((v shr 16) and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(), (v and 0xFF).toByte())

    private fun u16At(arr: ByteArray, off: Int): Int =
        ((arr[off].toInt() and 0xFF) shl 8) or (arr[off + 1].toInt() and 0xFF)

    private fun le32(v: Int): ByteArray = byteArrayOf(
        (v and 0xFF).toByte(), ((v shr 8) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(), ((v shr 24) and 0xFF).toByte()
    )

    private fun ext(type: Int, data: ByteArray): ByteArray = u16(type) + u16(data.size) + data

    private fun lengthPrefixed16(data: ByteArray): ByteArray = u16(data.size) + data
    private fun lengthPrefixed8(data: ByteArray): ByteArray = byteArrayOf(data.size.toByte()) + data

    private fun sniExtensionData(host: String): ByteArray {
        val nameBytes = host.toByteArray(Charsets.US_ASCII)
        val entry = byteArrayOf(0x00) + u16(nameBytes.size) + nameBytes   // host_name type(0) + len + name
        return u16(entry.size) + entry
    }

    private fun alpnExtensionData(protocols: List<String>): ByteArray {
        val list = protocols.fold(ByteArray(0)) { acc, p ->
            val pb = p.toByteArray(Charsets.US_ASCII)
            acc + byteArrayOf(pb.size.toByte()) + pb
        }
        return u16(list.size) + list
    }

    private fun keyShareExtensionData(key: ByteArray): ByteArray {
        val share = byteArrayOf(0x00, 0x1d) + u16(key.size) + key   // group=x25519(0x001d) + key_len + key
        return u16(share.size) + share
    }

    private fun hmacSha256(secret: ByteArray): Mac =
        Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
}
