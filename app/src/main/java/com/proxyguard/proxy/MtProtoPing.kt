package com.proxyguard.proxy

import com.proxyguard.relay.MtProtoObfuscation
import java.security.SecureRandom
import kotlin.random.Random

/**
 * Реальная проверка MTProto прокси через round-trip к Telegram DC.
 *
 * Отправляет req_pq_multi (простейший unencrypted запрос) и ждёт resPQ.
 * Это единственный надёжный способ отличить настоящий рабочий прокси
 * от "чёрной дыры" (сервер просто молчит, ничего никуда не пересылает).
 *
 * Формат unencrypted MTProto сообщения:
 *   auth_key_id(8, =0) + message_id(8) + length(4) + body
 * Обёрнуто в Padded Intermediate framing:
 *   length_LE(4, = len(payload)+len(padding)) + payload + padding
 */
object MtProtoPing {

    private const val REQ_PQ_MULTI = 0xbe7e8ef1.toInt()
    private val rng = SecureRandom()

    /**
     * Строит зашифрованный req_pq_multi пакет для отправки прокси.
     * @return Pair(зашифрованные байты для отправки, expectedNonce для опциональной сверки)
     */
    fun buildRequest(cipher: MtProtoObfuscation): ByteArray {
        val nonce16 = ByteArray(16).also { rng.nextBytes(it) }

        // body: req_pq_multi#be7e8ef1 nonce:int128
        val body = i32le(REQ_PQ_MULTI) + nonce16

        // unencrypted envelope: auth_key_id(8=0) + message_id(8) + length(4) + body
        val msgId = generateMsgId()
        val payload = ByteArray(8) /* auth_key_id = 0 */ + msgId + i32le(body.size) + body

        // Padded Intermediate framing: length(payload+padding) + payload + padding
        val padding = ByteArray(Random.nextInt(4, 16)).also { rng.nextBytes(it) }
        val totalLen = payload.size + padding.size
        val framed = i32le(totalLen) + payload + padding

        return cipher.encrypt(framed)
    }

    /**
     * Читает и валидирует ответ.
     * @return true если получили правдоподобный resPQ (длина 8..10000 байт)
     */
    fun isValidResponse(decryptedLengthHeader: ByteArray): Int? {
        if (decryptedLengthHeader.size < 4) return null
        val len = leToInt(decryptedLengthHeader)
        return if (len in 8..10_000) len else null
    }

    private fun generateMsgId(): ByteArray {
        // message_id ≈ unixtime * 2^32, делится на 4 (валидно для первого запроса сессии)
        val seconds = System.currentTimeMillis() / 1000
        var msgId = seconds shl 32
        msgId -= msgId % 4
        return longToLE(msgId)
    }

    private fun i32le(v: Int) = byteArrayOf(
        (v and 0xFF).toByte(),
        ((v shr 8) and 0xFF).toByte(),
        ((v shr 16) and 0xFF).toByte(),
        ((v shr 24) and 0xFF).toByte(),
    )

    private fun longToLE(v: Long) = ByteArray(8) { i -> ((v shr (i * 8)) and 0xFF).toByte() }

    private fun leToInt(b: ByteArray) =
        (b[0].toInt() and 0xFF) or
        ((b[1].toInt() and 0xFF) shl 8) or
        ((b[2].toInt() and 0xFF) shl 16) or
        ((b[3].toInt() and 0xFF) shl 24)
}
