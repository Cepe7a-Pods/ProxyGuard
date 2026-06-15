package com.proxyguard.relay

import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.random.Random

/**
 * MTProto proxy обфускация — random-padded режим ("dd" prefix secrets).
 *
 * Протокол:
 *  1. Клиент шлёт 64-байтовый nonce. Байты [8..40] — ключевой материал, [40..56] — IV.
 *  2. Из них + shared secret выводятся два AES-256-CTR ключа (по одному на каждое направление).
 *  3. Байты [56..60] nonce — зашифрованный protocol tag (0xdddddddd = padded intermediate).
 *  4. После nonce весь трафик — AES-CTR поток (счётчик стартует с позиции 64).
 *
 * Для relay нужны ДВА экземпляра:
 *   bridgeCipher  — Telegram ↔ LocalRelay   (bridge secret)
 *   proxyCipher   — LocalRelay ↔ ExternalProxy (proxy secret)
 */
class MtProtoObfuscation(
    private val encryptCipher: Cipher,  // этот узел → удалённая сторона
    private val decryptCipher: Cipher,  // удалённая сторона → этот узел
) {
    fun encrypt(data: ByteArray): ByteArray = encryptCipher.update(data)
    fun decrypt(data: ByteArray): ByteArray = decryptCipher.update(data)

    companion object {

        val PADDED_INTERMEDIATE_TAG = byteArrayOf(
            0xdd.toByte(), 0xdd.toByte(), 0xdd.toByte(), 0xdd.toByte()
        )

        // Запрещённые первые 4 байта nonce — не должны выглядеть как HTTP/TLS
        private val BANNED_PREFIXES = listOf(
            byteArrayOf(0xef.toByte(), 0xef.toByte(), 0xef.toByte(), 0xef.toByte()),
            "GET ".toByteArray(Charsets.US_ASCII),
            "POST".toByteArray(Charsets.US_ASCII),
            "HEAD".toByteArray(Charsets.US_ASCII),
            "OPTI".toByteArray(Charsets.US_ASCII),
        )

        /**
         * SERVER-режим: Telegram подключился, мы получили его 64-байтовый nonce.
         * Возвращает (protocolTag, шифр-контекст).
         *
         * Проверь: protocolTag == PADDED_INTERMEDIATE_TAG.
         * Если нет — неизвестный клиент, закрой соединение.
         */
        fun fromClientInit(init: ByteArray, secret: ByteArray): Pair<ByteArray, MtProtoObfuscation> {
            require(init.size == 64) { "Init must be exactly 64 bytes, got ${init.size}" }

            val keyPart = init.copyOfRange(8, 40)    // 32 байта ключевого материала
            val ivPart  = init.copyOfRange(40, 56)   // 16 байт IV

            // Два ключа — два направления трафика
            val encKey = sha256(secret + keyPart)
            val decKey = sha256(secret + keyPart.reversedArray())

            // Мы СЕРВЕР:
            //   decryptCipher → расшифровываем входящее от Telegram  (encKey, encIv)
            //   encryptCipher → шифруем исходящее к Telegram          (decKey, decIv)
            val decryptCipher = aesCtr(encKey, ivPart)
            val encryptCipher = aesCtr(decKey, ivPart.reversedArray())

            // Прогоняем все 64 байта через decryptCipher:
            //   — синхронизируем счётчик с Telegram (он тоже прошёл 64 байта при отправке nonce)
            //   — decryptedInit[56..60] == protocol tag (проверяем что это наш формат)
            val decryptedInit = decryptCipher.update(init)
            val protocolTag   = decryptedInit.copyOfRange(56, 60)

            // encryptCipher стартует с позиции 0 (нет данных в этом направлении до сих пор)

            return Pair(protocolTag, MtProtoObfuscation(encryptCipher, decryptCipher))
        }

        /**
         * CLIENT-режим: мы подключаемся к внешнему прокси.
         * Генерируем свой nonce, формируем байты для отправки.
         * Возвращает (bytesToSend, шифр-контекст).
         */
        fun generateForProxy(secret: ByteArray): Pair<ByteArray, MtProtoObfuscation> {
            val init = generateValidInit()

            val keyPart = init.copyOfRange(8, 40)
            val ivPart  = init.copyOfRange(40, 56)

            val encKey = sha256(secret + keyPart)
            val decKey = sha256(secret + keyPart.reversedArray())

            // Мы КЛИЕНТ:
            //   encryptCipher → шифруем исходящее к прокси       (encKey)
            //   decryptCipher → расшифровываем входящее от прокси (decKey)
            val encryptCipher = aesCtr(encKey, ivPart)
            val decryptCipher = aesCtr(decKey, ivPart.reversedArray())

            // Формируем пакет для отправки прокси:
            //   байты [0..55]  — plaintext (прокси использует их для деривации ключей)
            //   байты [56..63] — зашифрованные (прокси по ним верифицирует protocol tag)
            //   encryptCipher.update(init) делает advance на 64 байта — это нужно!
            val encryptedInit = encryptCipher.update(init)
            val toSend = init.copyOfRange(0, 56) + encryptedInit.copyOfRange(56, 64)

            // decryptCipher стартует с позиции 0

            return Pair(toSend, MtProtoObfuscation(encryptCipher, decryptCipher))
        }

        private fun generateValidInit(): ByteArray {
            while (true) {
                val init = Random.nextBytes(64)
                // Вписываем protocol tag в байты [56..60]
                PADDED_INTERMEDIATE_TAG.copyInto(init, destinationOffset = 56)
                // Байты [60..64] зарезервированы — обнуляем
                init[60] = 0; init[61] = 0; init[62] = 0; init[63] = 0

                // Первые 4 байта не должны совпадать с HTTP/TLS маркерами
                val prefix = init.copyOfRange(0, 4)
                val banned = BANNED_PREFIXES.any { it.contentEquals(prefix) }
                if (!banned && init[0] != 0xef.toByte()) return init
                // иначе генерируем снова
            }
        }

        private fun aesCtr(key: ByteArray, iv: ByteArray): Cipher =
            Cipher.getInstance("AES/CTR/NoPadding").apply {
                // В CTR-режиме ENCRYPT и DECRYPT идентичны (XOR с keystream).
                // Используем ENCRYPT_MODE для обоих — без разницы.
                init(
                    Cipher.ENCRYPT_MODE,
                    SecretKeySpec(key.copyOfRange(0, 32), "AES"),
                    IvParameterSpec(iv),
                )
            }

        private fun sha256(data: ByteArray): ByteArray =
            MessageDigest.getInstance("SHA-256").digest(data)
    }
}
