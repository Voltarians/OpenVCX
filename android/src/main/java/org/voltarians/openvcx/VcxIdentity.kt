// SPDX-License-Identifier: LGPL-3.0-only
package org.voltarians.openvcx

import android.os.SystemClock
import java.io.IOException

data class VcxIdentity(val model: String, val infoLength: Int)

class VcxIdentityProbe(private val usb: VcxUsbTransport) {
    /** Identifies the adapter without opening a vehicle bus or modifying entitlement. */
    fun identify(timeoutMs: Int = 5000): VcxIdentity {
        require(timeoutMs in 800..15000)
        val deadline = SystemClock.elapsedRealtime() + timeoutMs
        val parser = VcxFrame.Parser()
        var nextSend = 0L
        while (SystemClock.elapsedRealtime() < deadline) {
            val now = SystemClock.elapsedRealtime()
            if (now >= nextSend) {
                usb.write(VcxFrame.encode(0, 0x8c, 0))
                nextSend = now + 800
            }
            for (frame in parser.feed(usb.read(100))) {
                if (frame.size < 5 || frame[1].toInt() != 0 ||
                    (frame[2].toInt() and 255) != 0x8c || frame[3].toInt() != 0) continue
                if (frame[4].toInt() != 0) throw IOException("GETINFO rejected: " + (frame[4].toInt() and 255))
                val info = frame.copyOfRange(5, frame.size)
                val model = if (info.toString(Charsets.US_ASCII).contains("VCX-NANO")) "VCX-NANO"
                    else throw IOException("Unqualified VCX identity")
                return VcxIdentity(model, info.size)
            }
        }
        throw IOException("VCX GETINFO timed out; rejected frames: " + parser.rejected)
    }
}
