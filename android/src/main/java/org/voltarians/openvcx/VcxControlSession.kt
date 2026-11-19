// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import android.os.SystemClock
import java.io.Closeable
import java.io.IOException

/** Exclusive owner of the USB link; no concurrent identity probe or reader. */
class VcxControlSession(private val usb: VcxUsbTransport) : Closeable {
    private val parser = VcxFrame.Parser()
    private var closed = false
    private var faulted = false
    private var identity: VcxIdentity? = null

    @Synchronized fun identify(): VcxIdentity {
        check(!closed && !faulted)
        identity?.let { return it }
        val info = control(0x8c, 0, byteArrayOf(), 5000)
        if (!info.toString(Charsets.US_ASCII).contains("VCX-NANO"))
            throw IOException("Unqualified adapter identity")
        return VcxIdentity("VCX-NANO", info.size).also { identity = it }
    }

    /** No channel-open or entitlement-changing commands exposed in this revision. */
    private fun control(opcode: Int, channel: Int, payload: ByteArray, timeoutMs: Int): ByteArray {
        check(!closed && !faulted)
        require(opcode == 0x8c)
        try {
            usb.write(VcxFrame.encode(0, opcode, channel, payload))
            val deadline = SystemClock.elapsedRealtime() + timeoutMs
            while (SystemClock.elapsedRealtime() < deadline) {
                for (frame in parser.feed(usb.read(100))) {
                    if (frame.size < 5 || frame[1].toInt() != 0 ||
                        (frame[2].toInt() and 255) != opcode ||
                        (frame[3].toInt() and 255) != channel) continue
                    val status = frame[4].toInt() and 255
                    if (status != 0) throw IOException("VCX status 0x" + status.toString(16))
                    return frame.copyOfRange(5, frame.size)
                }
            }
            throw IOException("VCX control timeout")
        } catch (e: Exception) {
            faulted = true // Late replies must not be attributed to later requests.
            throw e
        }
    }

    @Synchronized override fun close() {
        if (!closed) {
            closed = true
            usb.close()
        }
    }
}
