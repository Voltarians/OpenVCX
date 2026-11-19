// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import org.junit.Test
import org.junit.Assert.*

class IsoTpTest {
    @Test fun roundTrip() {
        for (size in listOf(1,7,8,20,118,4095)) {
            val source = ByteArray(size) { it.toByte() }
            val sender = IsoTpSender(source)
            val receiver = IsoTpReceiver()
            var result = receiver.accept(sender.start())
            while (result !is IsoTpReceiver.Result.Complete) {
                if (result is IsoTpReceiver.Result.FlowControl) sender.flowControl(result.bytes)
                result = receiver.accept(sender.nextFrame())
            }
            assertTrue(sender.complete)
            assertArrayEquals(source,result.bytes)
        }
    }
    @Test fun blockCredit() {
        val sender = IsoTpSender(ByteArray(30))
        sender.start()
        sender.flowControl(byteArrayOf(0x30,1,5))
        assertEquals(5000,sender.separationMicros)
        sender.nextFrame()
        assertTrue(sender.awaitingFlowControl)
        sender.flowControl(byteArrayOf(0x30,0,0xf3.toByte()))
        assertEquals(300,sender.separationMicros)
        while (!sender.complete) sender.nextFrame()
    }
    @Test fun wrongSequenceResets() {
        val receiver = IsoTpReceiver()
        receiver.accept(byteArrayOf(0x10,9,1,2,3,4,5,6))
        try {
            receiver.accept(byteArrayOf(0x22,7,8,9))
            fail("Expected sequence rejection")
        } catch (_: IllegalArgumentException) {}
        val result = receiver.accept(byteArrayOf(1,42)) as IsoTpReceiver.Result.Complete
        assertArrayEquals(byteArrayOf(42),result.bytes)
    }
}
