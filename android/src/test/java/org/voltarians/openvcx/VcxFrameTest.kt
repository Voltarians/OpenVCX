// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import org.junit.Test
import org.junit.Assert.*

class VcxFrameTest {
    @Test fun getInfoRequest() {
        assertArrayEquals(byteArrayOf(0xbb.toByte(),0x80.toByte(),0,0x8c.toByte(),0,0x0c,0xbb.toByte()),
            VcxFrame.encode(0,0x8c,0))
    }
    @Test fun fragmentedEscapedFrame() {
        val payload = byteArrayOf(0xbb.toByte(),0xdd.toByte(),0xee.toByte())
        val frame = VcxFrame.encode(0,0x8c,0,payload)
        val parser = VcxFrame.Parser()
        val result = frame.flatMap { parser.feed(byteArrayOf(it)) }
        assertEquals(1,result.size)
        assertArrayEquals(byteArrayOf(0x80.toByte(),0,0x8c.toByte(),0)+payload,result.single())
    }
    @Test fun corruptChecksumRejected() {
        val frame = VcxFrame.encode(0,0x8c,0)
        frame[5] = 0x0d
        val parser = VcxFrame.Parser()
        assertTrue(parser.feed(frame).isEmpty())
        assertEquals(1,parser.rejected)
    }
    @Test fun recoveryAfterOverflow() {
        val parser = VcxFrame.Parser()
        assertTrue(parser.feed(byteArrayOf(0xbb.toByte())+ByteArray(4140)+byteArrayOf(0xbb.toByte())).isEmpty())
        assertEquals(1,parser.rejected)
        assertEquals(1,parser.feed(VcxFrame.encode(0,0x8c,0)).size)
    }
}
