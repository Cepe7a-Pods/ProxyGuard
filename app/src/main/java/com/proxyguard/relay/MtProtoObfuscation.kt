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

            val (keyA, ivA, keyB, ivB) = deriveKeys(init, secret)

            // Мы СЕРВЕР:
            //   decryptCipher → расшифровываем входящее от Telegram  (направление A, как клиент шифровал)
            //   encryptCipher → шифруем исходящее к Telegram          (направление B, reversed)
            val decryptCipher = aesCtr(keyA, ivA)
            val encryptCipher = aesCtr(keyB, ivB)

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

            val (keyA, ivA, keyB, ivB) = deriveKeys(init, secret)

            // Мы КЛИЕНТ:
            //   encryptCipher → шифруем исходящее к прокси        (направление A)
            //   decryptCipher → расшифровываем входящее от прокси  (направление B, reversed)
            val encryptCipher = aesCtr(keyA, ivA)
            val decryptCipher = aesCtr(keyB, ivB)

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

        /**
         * Каноничный вывод ключей obfuscated2 / padded-intermediate.
         * Сверено с тремя независимыми реализациями (alexbers/mtprotoproxy,
         * seriyps/mtproto_proxy, Flowseal/tg-ws-proxy) — все три сходятся в этом алгоритме.
         *
         * block48 = init[8..56) = prekey(32 байта) ++ iv(16 байт)
         *
         * Направление A («как есть»):
         *   prekeyA = block48[0..32), ivA = block48[32..48)
         *
         * Направление B (reversed):
         *   ВЕСЬ 48-байтовый block48 реверсируется КАК ЕДИНЫЙ БУФЕР
         *   (НЕ prekey и iv по отдельности!), затем нарезается заново на 32+16:
         *   block48Rev = reverse(block48); prekeyB = block48Rev[0..32), ivB = block48Rev[32..48)
         *
         * Ключ: sha256(prekey ++ secret) — prekey ПЕРВЫМ, secret ВТОРЫМ.
         * (Раньше тут было sha256(secret + prekey) — обратный порядок —
         *  и реверс prekey/iv по отдельности вместо реверса всего блока.
         *  Из-за лавинного эффекта SHA-256 это давало два независимых, полностью
         *  не совпадающих с реальным сервером ключа в обоих направлениях.)
         */
        private fun deriveKeys(init: ByteArray, secret: ByteArray): KeySet {
            val block48 = init.copyOfRange(8, 56)        // prekey(32) ++ iv(16)
            val prekeyA = block48.copyOfRange(0, 32)
            val ivA     = block48.copyOfRange(32, 48)

            val block48Rev = block48.reversedArray()      // реверс ВСЕГО блока целиком
            val prekeyB = block48Rev.copyOfRange(0, 32)
            val ivB     = block48Rev.copyOfRange(32, 48)

            val keyA = sha256(prekeyA + secret)            // prekey ++ secret, не secret ++ prekey
            val keyB = sha256(prekeyB + secret)

            return KeySet(keyA, ivA, keyB, ivB)
        }

        private data class KeySet(
            val keyA: ByteArray, val ivA: ByteArray,
            val keyB: ByteArray, val ivB: ByteArray,
        )

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
