// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import java.io.IOException
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.SecureRandom

/** Establishes a session using the installed device entitlement. */
internal class VcxPassThruSession(
    private val transact: (Int, ByteArray) -> ByteArray,
    private val wallTimeMillis: () -> Long,
    private val uptimeMillis: () -> Long,
) {
    private val random = SecureRandom()

    fun establish(deviceInfo: ByteArray) {
        if (deviceInfo.size < 24) throw IOException("GETINFO did not include session parameters")
        val prefix = deviceInfo.copyOfRange(16, 24)
        try {
            withSessionKey(prefix) { key ->
                requireExistingEntitlement(0x84, key)
            }
            withSessionKey(prefix) { key ->
                val selector = ByteArray(144)
                ByteBuffer.wrap(selector).order(ByteOrder.LITTLE_ENDIAN).putInt(132, 0xdfb986a5.toInt())
                passThru.copyInto(selector, 136)
                transact(0xa1, seal(selector, key))
                requireExistingEntitlement(0xa2, key)
            }
        } finally {
            prefix.fill(0)
        }
    }

    private fun withSessionKey(prefix: ByteArray, session: (ByteArray) -> Unit) {
        val exponent = generateSequence { BigInteger(64, random) }
            .first { it >= two && it < upperBound && it.gcd(groupOrder) == BigInteger.ONE }
        val clientPublic = generator.modPow(exponent, modulus)
        val reply = transact(0xa0, encodePublic(clientPublic))
        if (reply.size != 8) throw IOException("Unexpected VCX key exchange response length")
        val peer = BigInteger(1, reply.reversedArray())
        if (peer < two || peer > upperBound ||
            peer.modPow(cofactor, modulus) == BigInteger.ONE
        ) {
            throw IOException("VCX returned an invalid public key")
        }
        val shared = encodePublic(peer.modPow(exponent, modulus))
        val key = prefix + shared
        try {
            session(key)
        } finally {
            shared.fill(0)
            key.fill(0)
        }
    }

    private fun requireExistingEntitlement(opcode: Int, key: ByteArray) {
        val query = ByteArray(16).also { passThru.copyInto(it) }
        val response = transact(opcode, seal(query, key))
        if (response.size != 32) throw IOException("Unexpected VCX entitlement response length")
        val plain = VcxSessionEnvelope.transform(response, key, decrypt = true)
        try {
            val marker = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN).getInt(16)
            if (marker != VcxSessionEnvelope.marker ||
                !plain.copyOfRange(0, passThru.size).contentEquals(passThru)
            ) throw IOException("VCX did not confirm the existing PASSTHRU entitlement")
        } finally {
            plain.fill(0)
        }
    }

    private fun seal(payload: ByteArray, key: ByteArray): ByteArray {
        val plain = payload.copyOf(payload.size + 16)
        ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN).apply {
            position(payload.size)
            putInt(VcxSessionEnvelope.marker)
            putLong((wallTimeMillis() + 11644473600000L) * 10000L)
            putInt(uptimeMillis().toInt())
        }
        return try {
            VcxSessionEnvelope.transform(plain, key, decrypt = false)
        } finally {
            plain.fill(0)
        }
    }

    companion object {
        private val passThru = "PASSTHRU".toByteArray(Charsets.US_ASCII)
        private val modulus = BigInteger("18446744073709551557")
        private val groupOrder = modulus - BigInteger.ONE
        private val two = BigInteger.valueOf(2)
        private val upperBound = modulus - two
        private val generator = BigInteger.valueOf(5)
        // Reject a public key with no component in the largest prime-order subgroup.
        private val cofactor = groupOrder / BigInteger("5594472617641")

        private fun encodePublic(value: BigInteger): ByteArray =
            value.toByteArray().reversedArray().copyOf(8)
    }
}

/** Firmware-compatible session envelope. Kept internal to the authenticated transport. */
internal object VcxSessionEnvelope {
    const val marker = 0xa567a567.toInt()
    private val delta = 0x9e3779b9.toInt()

    fun transform(data: ByteArray, key: ByteArray, decrypt: Boolean): ByteArray {
        require(data.size in 8..160 && data.size % 4 == 0 && key.size == 16)
        val bytes = ByteBuffer.wrap(data).order(ByteOrder.LITTLE_ENDIAN)
        val words = IntArray(data.size / 4) { bytes.int }
        val keyReader = ByteBuffer.wrap(key).order(ByteOrder.LITTLE_ENDIAN)
        val keys = IntArray(4) { keyReader.int }
        val rounds = 64 + 52 / words.size
        var sum = 0
        fun mix(z: Int, y: Int, index: Int): Int =
            (((z ushr 5) xor (y shl 2)) + ((y ushr 3) xor (z shl 4))) xor
                ((y xor sum) + (z xor keys[(index and 3) xor ((sum ushr 2) and 3)]))
        try {
            if (decrypt) {
                sum = delta * rounds
                var y = words.first()
                repeat(rounds) {
                    for (i in words.lastIndex downTo 1) {
                        words[i] -= mix(words[i - 1], y, i)
                        y = words[i]
                    }
                    words[0] -= mix(words.last(), y, 0)
                    y = words.first()
                    sum -= delta
                }
            } else {
                var z = words.last()
                repeat(rounds) {
                    sum += delta
                    for (i in 0 until words.lastIndex) {
                        words[i] += mix(z, words[i + 1], i)
                        z = words[i]
                    }
                    words[words.lastIndex] += mix(z, words[0], words.lastIndex)
                    z = words.last()
                }
            }
            return ByteBuffer.allocate(data.size).order(ByteOrder.LITTLE_ENDIAN).apply {
                words.forEach { putInt(it) }
            }.array()
        } finally {
            words.fill(0)
            keys.fill(0)
        }
    }
}
