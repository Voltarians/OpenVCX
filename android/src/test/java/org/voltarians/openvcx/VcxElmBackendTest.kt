// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import java.math.BigInteger
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VcxElmBackendTest {
    @Test
    fun elmAuthenticatesThenReadsAcrossTheSameCanSession() {
        val usb = SimulatedUsb()
        Elm327(VcxElmBackend(usb.session)).use { elm ->
            elm.command("ATE0")
            elm.command("ATL0")
            assertEquals("12.6V\r>", elm.command("ATRV"))
            assertEquals("OK\r>", elm.command("ATSP6"))
            assertEquals("41 00 BE 3F A8 13\r>", elm.command("0100"))
            assertEquals("49 02 01 31 32 33 34 35 36 37\r>", elm.command("0902"))
            assertEquals("OK\r>", elm.command("ATSP9"))
            assertEquals("41 00 BE 3F A8 13\r>", elm.command("0100"))
            assertNull(elm.lastError)
        }
        assertEquals(
            listOf(0x86, 0x8c, 0xa0, 0x84, 0xa0, 0xa1, 0xa2,
                0x40, 0x45, 0x47, 0x42, 0x48, 0x43, 0x41, 0x40, 0x45, 0x47, 0x42, 0x48, 0x43, 0x41),
            usb.controls,
        )
        assertEquals(listOf(500_000, 250_000), usb.bitrates)
        assertTrue(usb.closed)
    }

    @Test
    fun elmReportsRejectedHandshakeWithoutOpeningCan() {
        val usb = SimulatedUsb(rejectKey = true)
        Elm327(VcxElmBackend(usb.session)).use { elm ->
            assertTrue(elm.command("0100").contains("CAN ERROR"))
            assertTrue(elm.lastError?.message.orEmpty().contains("invalid public key"))
        }
        assertEquals(listOf(0x8c, 0xa0), usb.controls)
        assertTrue(usb.closed)
    }

    private class SimulatedUsb(private val rejectKey: Boolean = false) {
        val controls = mutableListOf<Int>()
        val bitrates = mutableListOf<Int>()
        var closed = false
            private set
        private var time = 0L
        private val pending = ArrayDeque<ByteArray>()
        private val parser = VcxFrame.Parser()
        private val info = "VCX-NANO".toByteArray().copyOf(32)
        private val modulus = BigInteger("18446744073709551557")
        private val exponent = BigInteger.valueOf(123457)
        private var key = byteArrayOf()

        val session = VcxControlSession(
            write = { bytes, _ -> write(bytes) },
            read = { timeout -> pending.removeFirstOrNull() ?: ByteArray(0).also { time += timeout } },
            closeUsb = { closed = true },
            clock = { time },
        )

        private fun write(bytes: ByteArray) {
            val frame = parser.feed(bytes).single()
            if (frame[1].toInt() == 1) {
                val tx = checkNotNull(VcxCanFrame.decode(frame))
                val service = tx.data[1].toInt() and 255
                val response = when {
                    tx.id == 0x7e0 && tx.data[0] == 0x30.toByte() -> byteArrayOf(0x21, 0x34, 0x35, 0x36, 0x37)
                    (tx.id == 0x7df || tx.id == 0x18db33f1) && service == 1 -> byteArrayOf(6, 0x41, 0, 0xbe.toByte(), 0x3f, 0xa8.toByte(), 0x13)
                    tx.id == 0x7df && service == 9 -> byteArrayOf(0x10, 10, 0x49, 2, 1, 0x31, 0x32, 0x33)
                    else -> error("Unexpected CAN request")
                }
                val responseId = if (tx.extended) 0x18daf110 else 0x7e8
                pending.addLast(VcxFrame.encode(0, 0, 0, VcxCanFrame(responseId, tx.extended, response).encode()))
                return
            }
            val opcode = frame[2].toInt() and 255
            controls.add(opcode)
            val response = when (opcode) {
                0x86 -> byteArrayOf(0, 0, 0x31, 0x38)
                0x8c -> info
                0xa0 -> if (rejectKey) ByteArray(8) else {
                    val peer = BigInteger(1, frame.copyOfRange(4, frame.size).reversedArray())
                    key = info.copyOfRange(16, 24) + encode(peer.modPow(exponent, modulus))
                    encode(BigInteger.valueOf(5).modPow(exponent, modulus))
                }
                0x84, 0xa2 -> frame.copyOfRange(4, frame.size)
                0xa1 -> {
                    val selector = VcxSessionEnvelope.transform(frame.copyOfRange(4, frame.size), key, decrypt = true)
                    check(selector.copyOfRange(136, 144).decodeToString() == "PASSTHRU")
                    byteArrayOf()
                }
                0x45 -> {
                    val params = java.nio.ByteBuffer.wrap(frame, 4, frame.size - 4)
                    check(params.short.toInt() == 3)
                    bitrates.add(params.int)
                    byteArrayOf()
                }
                0x40, 0x47, 0x42, 0x48, 0x43, 0x41 -> byteArrayOf()
                else -> error("Unexpected control opcode")
            }
            pending.addLast(VcxFrame.encode(0, opcode, 0, byteArrayOf(0) + response))
        }

        private fun encode(value: BigInteger) = value.toByteArray().reversedArray().copyOf(8)
    }
}
