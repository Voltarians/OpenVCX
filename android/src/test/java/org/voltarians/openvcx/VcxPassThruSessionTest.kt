// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import java.io.IOException
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class VcxPassThruSessionTest {
    private val info = ByteArray(64) { (it + 1).toByte() }
    private val name = "PASSTHRU".toByteArray()
    private val modulus = BigInteger("18446744073709551557")

    @Test
    fun establishesWithTwoIndependentKeysAndTheInstalledEntitlement() {
        val calls = mutableListOf<Int>()
        val clientKeys = mutableSetOf<BigInteger>()
        var key = byteArrayOf()
        val session = VcxPassThruSession({ opcode, data ->
            calls.add(opcode)
            if (opcode == 0xa0) {
                val peer = BigInteger(1, data.reversedArray())
                assertTrue(peer > BigInteger.ONE && peer < modulus - BigInteger.ONE)
                assertTrue(clientKeys.add(peer))
                val exponent = BigInteger.valueOf(if (clientKeys.size == 1) 123457L else 234569L)
                key = info.copyOfRange(16, 24) + encode(peer.modPow(exponent, modulus))
                encode(BigInteger.valueOf(5).modPow(exponent, modulus))
            } else {
                val plain = VcxSessionEnvelope.transform(data, key, decrypt = true)
                val payloadLength = plain.size - 16
                val header = ByteBuffer.wrap(plain).order(ByteOrder.LITTLE_ENDIAN)
                assertEquals(VcxSessionEnvelope.marker, header.getInt(payloadLength))
                assertEquals(133444736000000000L, header.getLong(payloadLength + 4))
                assertEquals(123, header.getInt(payloadLength + 12))
                if (opcode == 0xa1) {
                    assertEquals(144, payloadLength)
                    assertEquals(0, header.getInt(128))
                    assertEquals(0xdfb986a5.toInt(), header.getInt(132))
                    assertArrayEquals(name, plain.copyOfRange(136, 144))
                    byteArrayOf()
                } else {
                    assertEquals(16, payloadLength)
                    assertArrayEquals(name, plain.copyOfRange(0, 8))
                    VcxSessionEnvelope.transform(plain, key, decrypt = false)
                }
            }
        }, { 1700000000000L }, { 123L })
        session.establish(info)
        assertEquals(listOf(0xa0, 0x84, 0xa0, 0xa1, 0xa2), calls)
    }

    @Test
    fun rejectsAnInvalidPeerBeforeSelectingAnyEntitlement() {
        val calls = mutableListOf<Int>()
        val session = VcxPassThruSession({ opcode, _ ->
            calls.add(opcode)
            ByteArray(8)
        }, { 1700000000000L }, { 123L })
        val failure = assertThrows(IOException::class.java) { session.establish(info) }
        assertTrue(failure.message!!.contains("invalid public key"))
        assertEquals(listOf(0xa0), calls)
    }

    @Test
    fun stopsIfTheAdapterCannotConfirmTheInstalledEntitlement() {
        val calls = mutableListOf<Int>()
        val session = VcxPassThruSession({ opcode, _ ->
            calls.add(opcode)
            if (opcode == 0xa0) encode(BigInteger.valueOf(5)) else ByteArray(0)
        }, { 1700000000000L }, { 123L })
        assertThrows(IOException::class.java) { session.establish(info) }
        assertFalse(calls.contains(0xa1))
        assertEquals(listOf(0xa0, 0x84), calls)
    }

    private fun encode(value: BigInteger) = value.toByteArray().reversedArray().copyOf(8)
}
